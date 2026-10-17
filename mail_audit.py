#!/usr/bin/env python3
"""
mail_audit.py -- email security auditor (mail-security-auditor).

Zero-dependency, single-file, stdlib-only Python 3. Implements a minimal raw
DNS client (UDP + TCP fallback, RFC 1035) to query TXT/MX/A/AAAA records
directly -- no dnspython, no external binaries (dig/host).

Checks performed (every finding has a severity: HIGH/MEDIUM/LOW/INFO):
  - MX records present (null MX recognised)
  - SPF: present, exactly one record, the 'all' qualifier, real sender
    mechanisms, and the RFC 7208 limits receivers enforce: at most 10 DNS
    lookups (include/a/mx/ptr/exists/redirect, counted across the whole include
    tree), at most 2 void lookups, includes/redirects that have no SPF record,
    include loops, mx terms with more than 10 hosts, ptr usage
  - DMARC: present, exactly one record, p= and sp= strength, adkim/aspf values,
    rua configured, pct, and rua/ruf addresses in other domains authorized via
    <domain>._report._dmarc.<other> (RFC 7489 7.1)
  - DKIM: common selectors (+ --selectors), RSA key size (< 1024 HIGH, < 2048 LOW),
    revoked keys
  - MTA-STS: _mta-sts TXT, the HTTPS policy (version, mode, max_age) and that
    every MX host is covered by an mx: pattern
  - TLS-RPT: _smtp._tls TXT with a valid rua
  - BIMI: default._bimi record, enforcing DMARC, https SVG logo, VMC note
  - --smtp: STARTTLS offered on each MX, TLS version and certificate validity

Usage:
  mail-security-auditor example.com [example2.com ...]
  mail-security-auditor --json example.com
  mail-security-auditor --html report.html example.com
  mail-security-auditor --fail-on high --smtp example.com

Exit codes: 0 = no finding at or above --fail-on (default: medium),
1 = at least one, 2 = usage error.

License: MIT (c) 2026 Errant Solutions
"""
__version__ = "1.2.0"

import argparse
import base64
import html
import http.client
import json
import random
import socket
import ssl
import struct
import sys
import time

DNS_SERVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
TIMEOUT = 4.0

TYPE_A = 1
TYPE_MX = 15
TYPE_TXT = 16
TYPE_AAAA = 28
CLASS_IN = 1

COMMON_DKIM_SELECTORS = [
    "google", "selector1", "selector2", "default", "k1", "dkim", "mail",
    "s1", "s2", "smtp", "mandrill", "mailgun", "sendgrid", "everlytickey1",
    "everlytickey2", "dkim1", "protonmail", "protonmail2", "protonmail3",
]


EDNS_UDP_PAYLOAD_SIZE = 4096


def build_query(qname, qtype, edns=True):
    tid = random.randint(0, 65535)
    arcount = 1 if edns else 0
    header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, arcount)
    parts = qname.strip(".").split(".")
    qbytes = b"".join(bytes([len(p)]) + p.encode() for p in parts) + b"\x00"
    question = qbytes + struct.pack(">HH", qtype, CLASS_IN)
    packet = header + question
    if edns:
        # EDNS0 OPT pseudo-RR (RFC 6891): advertises a larger UDP payload size
        # so TXT/DKIM responses that exceed the classic 512-byte UDP limit
        # come back whole instead of being silently truncated.
        opt = b"\x00" + struct.pack(">HHIH", 41, EDNS_UDP_PAYLOAD_SIZE, 0, 0)
        packet += opt
    return tid, packet


def parse_name(data, offset):
    labels = []
    orig_offset = None
    steps = 0
    while True:
        steps += 1
        if steps > 128:
            break
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            if orig_offset is None:
                orig_offset = offset + 2
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            offset = pointer
            continue
        offset += 1
        labels.append(data[offset:offset + length].decode(errors="replace"))
        offset += length
    end = orig_offset if orig_offset is not None else offset
    return ".".join(labels), end


def parse_response(data, qtype=None):
    """Parse a raw DNS message. Returns (tid, rcode, truncated, results).

    Only answer records of `qtype` are returned: a CNAME in the answer chain
    (alias -> target) must not show up as a bogus MX/TXT value."""
    resp_tid = struct.unpack(">H", data[0:2])[0]
    flags = struct.unpack(">H", data[2:4])[0]
    rcode = flags & 0x000F
    truncated = bool(flags & 0x0200)  # TC bit
    qdcount, ancount = struct.unpack(">HH", data[4:8])
    offset = 12
    for _ in range(qdcount):
        _, offset = parse_name(data, offset)
        offset += 4
    results = []
    for _ in range(ancount):
        _, offset = parse_name(data, offset)
        rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", data[offset:offset + 10])
        offset += 10
        rdata = data[offset:offset + rdlen]
        if qtype is not None and rtype != qtype:
            pass
        elif rtype == TYPE_TXT:
            txt = b""
            p = 0
            while p < len(rdata):
                seg_len = rdata[p]
                txt += rdata[p + 1:p + 1 + seg_len]
                p += 1 + seg_len
            results.append(txt.decode(errors="replace"))
        elif rtype == TYPE_MX:
            pref = struct.unpack(">H", rdata[0:2])[0]
            exch, _ = parse_name(data, offset + 2)
            results.append(f"{pref} {exch}")
        elif rtype == TYPE_A:
            results.append(".".join(str(b) for b in rdata))
        elif rtype == TYPE_AAAA and len(rdata) == 16:
            results.append(socket.inet_ntop(socket.AF_INET6, rdata))
        else:
            results.append(rdata.hex())
        offset += rdlen
    return resp_tid, rcode, truncated, results


def _split_server(server):
    """'1.1.1.1' -> ('1.1.1.1', 53); '127.0.0.1:5353' -> ('127.0.0.1', 5353)."""
    if server.count(":") == 1:
        host, port = server.split(":")
        return host, int(port)
    if server.startswith("[") and "]:" in server:
        host, port = server[1:].split("]:")
        return host, int(port)
    return server.strip("[]"), 53


def _family(host):
    return socket.AF_INET6 if ":" in host else socket.AF_INET


def _query_udp(server, packet):
    host, port = _split_server(server)
    sock = socket.socket(_family(host), socket.SOCK_DGRAM)
    try:
        sock.settimeout(TIMEOUT)
        sock.sendto(packet, (host, port))
        data, _ = sock.recvfrom(65535)
        return data
    finally:
        sock.close()


def _query_tcp(server, packet):
    host, port = _split_server(server)
    sock = socket.socket(_family(host), socket.SOCK_STREAM)
    try:
        sock.settimeout(TIMEOUT)
        sock.connect((host, port))
        sock.sendall(struct.pack(">H", len(packet)) + packet)
        length_prefix = _recv_exact(sock, 2)
        if length_prefix is None:
            return None
        (msg_len,) = struct.unpack(">H", length_prefix)
        return _recv_exact(sock, msg_len)
    finally:
        sock.close()


def _recv_exact(sock, n):
    chunks = []
    remaining = n
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            return None
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


_DEAD_SERVERS = set()


def dns_query(qname, qtype, servers=None):
    servers = servers or DNS_SERVERS
    # A resolver that timed out/refused once is skipped for the rest of the
    # run (unless every resolver is dead) -- otherwise one blocked resolver
    # costs a full TIMEOUT on each of the ~25 queries per domain.
    live = [s for s in servers if s not in _DEAD_SERVERS] or list(servers)
    last_err = None
    for server in live:
        try:
            tid, packet = build_query(qname, qtype, edns=True)
            data = _query_udp(server, packet)
            if data is None:
                continue
            resp_tid, rcode, truncated, results = parse_response(data, qtype)
            if resp_tid != tid:
                continue
            if truncated:
                # UDP response didn't fit even with EDNS0 (or a resolver that
                # ignores EDNS0 truncated it) -- retry reliably over TCP
                # instead of silently returning the clipped TXT/record data.
                try:
                    tcp_data = _query_tcp(server, packet)
                except (socket.timeout, OSError) as e:
                    last_err = e
                    tcp_data = None
                if tcp_data:
                    tcp_tid, tcp_rcode, _, tcp_results = parse_response(tcp_data, qtype)
                    if tcp_tid == tid:
                        rcode, results = tcp_rcode, tcp_results
            if rcode in (0, 3) or results:
                # NOERROR or NXDOMAIN is an authoritative answer -- asking the
                # next resolver would only repeat it.
                return results
        except (socket.timeout, OSError) as e:
            last_err = e
            _DEAD_SERVERS.add(server)
            continue
    if last_err:
        return []
    return []


# --------------------------------------------------------------------------- findings

SEVERITIES = ("HIGH", "MEDIUM", "LOW", "INFO")
RANK = {s: i for i, s in enumerate(SEVERITIES)}


class Section:
    """Collects findings for one check; .result() gives the JSON-able dict."""

    def __init__(self, **data):
        self.data = data
        self.findings = []

    def add(self, severity, message):
        self.findings.append({"severity": severity, "message": message})

    def result(self):
        d = dict(self.data)
        d["findings"] = self.findings
        d["issues"] = [f["message"] for f in self.findings]
        return d


# --------------------------------------------------------------------------- SPF

SPF_LOOKUP_LIMIT = 10      # RFC 7208 4.6.4: DNS-querying terms per evaluation
SPF_VOID_LIMIT = 2         # RFC 7208 4.6.4: lookups returning NXDOMAIN/no data
SPF_MX_A_LIMIT = 10        # RFC 7208 4.6.4: address lookups per mx mechanism


def _spf_terms(record):
    """Split an SPF record into (qualifier, mechanism, value) terms (RFC 7208 s4.6)."""
    terms = []
    for tok in record.split()[1:]:
        if "=" in tok.split(":", 1)[0]:
            continue  # modifier (redirect=, exp=)
        qualifier = "+"
        if tok[:1] in "+-~?":
            qualifier, tok = tok[0], tok[1:]
        name, _, value = tok.partition(":")
        name = name.split("/", 1)[0].lower()
        terms.append((qualifier, name, value))
    return terms


def _spf_modifier(record, name):
    for tok in record.split()[1:]:
        if tok.lower().startswith(name + "="):
            return tok.split("=", 1)[1]
    return None


def _spf_record(domain):
    txts = dns_query(domain, TYPE_TXT)
    return [t for t in txts if t.lower() == "v=spf1" or t.lower().startswith("v=spf1 ")]


class SpfWalk:
    """Evaluate the DNS cost of an SPF record the way a receiver would (RFC 7208 4.6.4):
    every include/a/mx/ptr/exists term and the redirect modifier is one lookup, counted
    across the whole include tree; lookups that come back empty are void lookups."""

    def __init__(self):
        self.lookups = 0
        self.void = 0
        self.errors = []      # permerror causes
        self.notes = []       # (severity, message)
        self.seen = set()

    def target(self, value, current):
        spec = value.split("/", 1)[0] if value else current
        return spec.rstrip(".").lower()

    def walk(self, domain, record, depth=0, chain=()):
        chain = chain + (domain,)
        node = {"domain": domain, "record": record, "lookups": 0, "children": []}
        if depth > 10:
            self.errors.append("SPF include/redirect nesting deeper than 10 levels at %s" % domain)
            return node
        start = self.lookups
        for q, name, value in _spf_terms(record):
            if name not in ("include", "a", "mx", "ptr", "exists"):
                continue
            self.lookups += 1
            tgt = self.target(value, domain)
            if "%{" in tgt:
                self.notes.append(("INFO", "SPF term '%s:%s' uses a macro; its target can't be checked offline" % (name, value)))
                continue
            if name == "ptr":
                self.notes.append(("LOW", "SPF uses the 'ptr' mechanism, which RFC 7208 says SHOULD NOT be used (slow, unreliable)"))
            elif name == "include":
                if tgt in chain:
                    self.errors.append("SPF include loop: %s includes itself via %s" % (tgt, " -> ".join(chain)))
                    continue
                if tgt in self.seen:
                    self.notes.append(("INFO", "%s is included more than once; every occurrence costs DNS lookups" % tgt))
                self.seen.add(tgt)
                recs = _spf_record(tgt)
                if not recs:
                    self.void += 1
                    self.errors.append("include:%s has no SPF record (receivers return permerror)" % tgt)
                    continue
                node["children"].append(self.walk(tgt, recs[0], depth + 1, chain))
            elif name == "a":
                if not (dns_query(tgt, TYPE_A) or dns_query(tgt, TYPE_AAAA)):
                    self.void += 1
            elif name == "mx":
                mx = [r.split(" ", 1)[1] for r in dns_query(tgt, TYPE_MX) if " " in r]
                if not mx:
                    self.void += 1
                elif len(mx) > SPF_MX_A_LIMIT:
                    self.errors.append("mx:%s has %d MX hosts; RFC 7208 allows at most %d address lookups per mx term"
                                       % (tgt, len(mx), SPF_MX_A_LIMIT))
            elif name == "exists":
                if not dns_query(tgt, TYPE_A):
                    self.void += 1
        redirect = _spf_modifier(record, "redirect")
        if redirect and not any(n == "all" for _, n, _ in _spf_terms(record)):
            self.lookups += 1
            tgt = redirect.rstrip(".").lower()
            recs = _spf_record(tgt) if "%{" not in tgt else []
            if tgt in chain:
                self.errors.append("SPF redirect loop: %s via %s" % (tgt, " -> ".join(chain)))
            elif not recs:
                self.void += 1
                self.errors.append("redirect=%s has no SPF record (receivers return permerror)" % tgt)
            else:
                self.seen.add(tgt)
                node["children"].append(self.walk(tgt, recs[0], depth + 1, chain))
        node["lookups"] = self.lookups - start
        return node


def check_spf(domain):
    spf_records = _spf_record(domain)
    if not spf_records:
        s = Section(present=False, records=[])
        s.add("HIGH", "No SPF record found (v=spf1 TXT)")
        return s.result()
    s = Section(present=True, records=spf_records)
    if len(spf_records) > 1:
        s.add("HIGH", "Multiple SPF records found (%d); RFC 7208 permits only one -- causes PermError in strict validators" % len(spf_records))
    record = spf_records[0]
    terms = _spf_terms(record)
    all_terms = [q for q, name, _ in terms if name == "all"]
    has_redirect = _spf_modifier(record, "redirect") is not None
    if all_terms:
        q = all_terms[0]
        if q == "+":
            s.add("HIGH", "SPF uses '+all' (or a bare 'all', which means the same) -- allows ANY host to send as this domain (critical misconfiguration)")
        elif q == "?":
            s.add("MEDIUM", "SPF uses '?all' (neutral) -- provides no real protection")
        elif q == "~":
            s.add("LOW", "SPF uses '~all' (softfail) -- consider '-all' (hardfail) once confident in the record")
    elif not has_redirect:
        s.add("MEDIUM", "SPF has no 'all' mechanism -- undefined/permissive behavior for non-matching senders")
    senders = [name for _, name, _ in terms if name in ("include", "a", "mx", "ip4", "ip6", "exists", "ptr")]
    null_record = terms == [("-", "all", "")]  # "v=spf1 -all": domain deliberately sends no mail
    if not senders and not has_redirect and not null_record:
        s.add("MEDIUM", "SPF record has no include/a/mx/ip4/ip6 mechanisms -- likely won't authorize any real sender")

    w = SpfWalk()
    tree = w.walk(domain.lower(), record)
    s.data.update(lookups=w.lookups, void_lookups=w.void, tree=tree)
    if w.lookups > SPF_LOOKUP_LIMIT:
        s.add("HIGH", "SPF needs %d DNS lookups (include/a/mx/ptr/exists/redirect across the include tree); "
                      "RFC 7208 allows %d, so receivers return permerror and SPF fails for ALL your mail"
              % (w.lookups, SPF_LOOKUP_LIMIT))
    elif w.lookups >= SPF_LOOKUP_LIMIT - 1:
        s.add("LOW", "SPF needs %d of the %d allowed DNS lookups -- one more include breaks it" % (w.lookups, SPF_LOOKUP_LIMIT))
    if w.void > SPF_VOID_LIMIT:
        s.add("HIGH", "SPF has %d void lookups (names that don't exist or have no records); RFC 7208 allows %d, "
                      "so receivers may return permerror" % (w.void, SPF_VOID_LIMIT))
    for e in w.errors:
        s.add("HIGH", e)
    for sev, msg in dict.fromkeys(w.notes):
        s.add(sev, msg)
    return s.result()


# --------------------------------------------------------------------------- DMARC

def _tags(record, sep=";"):
    fields = {}
    for part in record.split(sep):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            fields[k.strip().lower()] = v.strip()
    return fields


def _related(a, b):
    """Rough organizational-domain test without a public suffix list: same domain or one is
    a subdomain of the other."""
    a, b = a.lower().rstrip("."), b.lower().rstrip(".")
    return a == b or a.endswith("." + b) or b.endswith("." + a)


def check_dmarc(domain):
    txts = dns_query("_dmarc." + domain, TYPE_TXT)
    dmarc_records = [t for t in txts if t.lower().startswith("v=dmarc1")]
    if not dmarc_records:
        s = Section(present=False, records=[])
        s.add("HIGH", "No DMARC record found (_dmarc.<domain> TXT v=DMARC1)")
        return s.result()
    record = dmarc_records[0]
    fields = _tags(record)
    policy = fields.get("p", "").lower()
    s = Section(present=True, records=dmarc_records, policy=policy, tags=fields)
    if len(dmarc_records) > 1:
        s.add("HIGH", "Multiple DMARC records found (%d); RFC 7489 says receivers then ignore DMARC entirely" % len(dmarc_records))
    if policy == "none":
        s.add("MEDIUM", "DMARC policy is 'p=none' -- monitoring only, no enforcement against spoofing")
    elif policy == "quarantine":
        s.add("LOW", "DMARC policy is 'p=quarantine' -- consider 'p=reject' once reports show clean alignment")
    elif policy != "reject":
        s.add("HIGH", "DMARC policy '%s' is non-standard or missing" % (policy or "(missing)"))
    sp = fields.get("sp", "").lower()
    if sp and sp not in ("none", "quarantine", "reject"):
        s.add("MEDIUM", "DMARC subdomain policy 'sp=%s' is not none/quarantine/reject" % sp)
    elif sp == "none" and policy in ("quarantine", "reject"):
        s.add("MEDIUM", "DMARC 'sp=none' leaves every subdomain unprotected even though p=%s" % policy)
    for tag in ("adkim", "aspf"):
        v = fields.get(tag, "r").lower()
        if v not in ("r", "s"):
            s.add("MEDIUM", "DMARC '%s=%s' is invalid (must be r or s)" % (tag, v))
    if "rua" not in fields:
        s.add("LOW", "No 'rua' aggregate-report address configured -- no visibility into spoofing attempts")
    pct = fields.get("pct")
    if pct and pct != "100":
        s.add("LOW", "DMARC 'pct=%s' -- policy only applied to %s%% of mail" % (pct, pct))

    # RFC 7489 7.1: a report address in another domain must authorize this domain
    external = []
    for tag in ("rua", "ruf"):
        for uri in fields.get(tag, "").split(","):
            uri = uri.strip()
            if not uri.lower().startswith("mailto:") or "@" not in uri:
                continue
            dest = uri.split("@", 1)[1].split("!", 1)[0].rstrip(".").lower()
            if _related(dest, domain):
                continue
            auth_name = "%s._report._dmarc.%s" % (domain, dest)
            ok = any(t.lower().startswith("v=dmarc1") for t in dns_query(auth_name, TYPE_TXT))
            external.append({"tag": tag, "address": uri[7:], "authorized": ok, "record": auth_name})
            if not ok:
                s.add("MEDIUM", "%s address %s is in another domain that doesn't authorize it (no v=DMARC1 TXT at %s) "
                                "-- receivers won't send these reports" % (tag, uri[7:], auth_name))
    s.data["external_report_destinations"] = external
    return s.result()


# --------------------------------------------------------------------------- DKIM

def _der_read(data, pos):
    """One DER TLV: returns (tag, value_bytes, next_pos)."""
    tag = data[pos]
    length = data[pos + 1]
    pos += 2
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(data[pos:pos + n], "big")
        pos += n
    return tag, data[pos:pos + length], pos + length


RSA_OID = bytes.fromhex("2a864886f70d010101")  # 1.2.840.113549.1.1.1 rsaEncryption


def rsa_key_bits(b64):
    """Modulus size of a DKIM p= RSA key (SubjectPublicKeyInfo or bare RSAPublicKey), or None."""
    try:
        der = base64.b64decode("".join(b64.split()), validate=True)
        tag, seq, end = _der_read(der, 0)
        if tag != 0x30 or end != len(der):
            return None
        tag1, first, after = _der_read(seq, 0)
        if tag1 == 0x30:  # SubjectPublicKeyInfo: AlgorithmIdentifier, BIT STRING(RSAPublicKey)
            otag, oid, _ = _der_read(first, 0)
            if otag != 0x06 or oid != RSA_OID:
                return None
            btag, bits, _ = _der_read(seq, after)
            if btag != 0x03:
                return None
            rtag, rsa, _ = _der_read(bits[1:], 0)
            if rtag != 0x30:
                return None
            mtag, modulus, _ = _der_read(rsa, 0)
        elif tag1 == 0x02:  # RSAPublicKey: INTEGER modulus, INTEGER exponent
            mtag, modulus = tag1, first
        else:
            return None
        if mtag != 0x02:
            return None
        return int.from_bytes(modulus, "big").bit_length() or None
    except Exception:
        return None


def check_dkim(domain, selectors=None):
    selectors = selectors or COMMON_DKIM_SELECTORS
    found = []
    s = Section()
    for sel in selectors:
        name = sel + "._domainkey." + domain
        txts = dns_query(name, TYPE_TXT)
        dkim_txts = [t for t in txts if "v=dkim1" in t.lower() or "p=" in t.lower()]
        if not dkim_txts:
            continue
        tags = _tags(dkim_txts[0])
        entry = {"selector": sel, "record": dkim_txts[0], "key_type": tags.get("k", "rsa").lower()}
        p = tags.get("p", "")
        if not p:
            entry["revoked"] = True
            s.add("INFO", "DKIM selector '%s' has an empty p= (key revoked)" % sel)
        elif entry["key_type"] == "rsa":
            bits = rsa_key_bits(p)
            entry["key_bits"] = bits
            if bits is None:
                s.add("MEDIUM", "DKIM selector '%s': p= is not a valid RSA public key" % sel)
            elif bits < 1024:
                s.add("HIGH", "DKIM selector '%s' uses a %d-bit RSA key -- RFC 8301 requires at least 1024, receivers ignore it" % (sel, bits))
            elif bits < 2048:
                s.add("LOW", "DKIM selector '%s' uses a %d-bit RSA key -- 2048 bits is the current recommendation" % (sel, bits))
        found.append(entry)
    if not found:
        s.add("LOW", "No DKIM record found under %d common selectors -- this only means the common ones weren't "
                     "found; check your mail provider's docs for the actual selector name (--selectors)" % len(selectors))
    s.data["found"] = found
    return s.result()


# --------------------------------------------------------------------------- MX

def check_mx(domain):
    mx = dns_query(domain, TYPE_MX)
    s = Section(records=sorted(mx, key=lambda r: (int(r.split()[0]) if r.split()[0].isdigit() else 0, r)))
    if not mx:
        s.add("LOW", "No MX records found -- domain cannot receive mail (may be intentional)")
    elif any(r.split(" ", 1)[-1] in ("", ".") for r in mx):
        s.add("INFO", "Null MX (RFC 7505): this domain declares it accepts no mail")
    return s.result()


def mx_hosts(mx_result):
    hosts = []
    for r in mx_result["records"]:
        parts = r.split(" ", 1)
        if len(parts) == 2 and parts[1] not in ("", "."):
            hosts.append(parts[1].rstrip(".").lower())
    return hosts


# --------------------------------------------------------------------------- HTTPS fetch via our resolver

HTTPS_PORT = 443
SMTP_PORT = 25


def resolve(host):
    """IPv4 addresses for host through the same resolvers as every other query, then the OS."""
    ips = dns_query(host, TYPE_A)
    if ips:
        return ips
    try:
        return [ai[4][0] for ai in socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)]
    except OSError:
        return []


def https_get(host, path):
    """GET https://host/path with normal certificate + hostname verification, connecting to the
    address our resolver returns. Returns (status, body, error)."""
    ips = resolve(host)
    if not ips:
        return None, "", "%s does not resolve" % host
    ctx = ssl.create_default_context()
    try:
        raw = socket.create_connection((ips[0], HTTPS_PORT), timeout=TIMEOUT * 2)
        with ctx.wrap_socket(raw, server_hostname=host) as tls:
            tls.sendall(("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: mail-security-auditor/%s\r\n"
                         "Connection: close\r\n\r\n" % (path, host, __version__)).encode())
            resp = http.client.HTTPResponse(tls)
            resp.begin()
            body = resp.read(65536).decode("utf-8", "replace")
            return resp.status, body, None
    except ssl.SSLCertVerificationError as e:
        return None, "", "TLS certificate not valid for %s (%s)" % (host, e.verify_message or e)
    except (OSError, ssl.SSLError, http.client.HTTPException) as e:
        return None, "", "%s: %s" % (host, e)


# --------------------------------------------------------------------------- MTA-STS / TLS-RPT / BIMI

def _mx_matches(pattern, host):
    pattern, host = pattern.lower().rstrip("."), host.lower().rstrip(".")
    if pattern.startswith("*."):
        return host.endswith(pattern[1:]) and host.count(".") == pattern.count(".")
    return pattern == host


def check_mta_sts(domain, mx_result):
    txts = [t for t in dns_query("_mta-sts." + domain, TYPE_TXT) if t.lower().startswith("v=stsv1")]
    if not txts:
        s = Section(present=False)
        s.add("LOW", "No MTA-STS (_mta-sts TXT v=STSv1) -- sending servers can be downgraded to unencrypted SMTP")
        return s.result()
    s = Section(present=True, record=txts[0])
    if len(txts) > 1:
        s.add("HIGH", "Multiple _mta-sts TXT records -- senders treat MTA-STS as not present (RFC 8461 3.1)")
    if not _tags(txts[0]).get("id"):
        s.add("HIGH", "_mta-sts TXT record has no id= -- invalid (RFC 8461 3.1)")
    status, body, err = https_get("mta-sts." + domain, "/.well-known/mta-sts.txt")
    if status != 200:
        s.add("HIGH", "MTA-STS policy https://mta-sts.%s/.well-known/mta-sts.txt not retrievable (%s) -- the TXT "
                      "record advertises a policy senders can't fetch" % (domain, err or "HTTP %s" % status))
        return s.result()
    policy = {"mx": []}
    for line in body.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            k, v = k.strip().lower(), v.strip()
            if k == "mx":
                policy["mx"].append(v)
            else:
                policy[k] = v
    s.data["policy"] = policy
    if policy.get("version") != "STSv1":
        s.add("HIGH", "MTA-STS policy has no 'version: STSv1' line")
    mode = policy.get("mode", "").lower()
    if mode == "testing":
        s.add("LOW", "MTA-STS mode is 'testing' -- failures are only reported, not enforced")
    elif mode == "none":
        s.add("MEDIUM", "MTA-STS mode is 'none' -- the policy is switched off")
    elif mode != "enforce":
        s.add("HIGH", "MTA-STS mode '%s' is not enforce/testing/none" % (mode or "(missing)"))
    try:
        max_age = int(policy.get("max_age", ""))
        if max_age < 86400:
            s.add("LOW", "MTA-STS max_age=%d is under a day (RFC 8461 recommends weeks)" % max_age)
    except ValueError:
        s.add("HIGH", "MTA-STS policy has no valid max_age")
    hosts = mx_hosts(mx_result)
    uncovered = [h for h in hosts if not any(_mx_matches(p, h) for p in policy["mx"])]
    if uncovered and mode in ("enforce", "testing"):
        s.add("HIGH" if mode == "enforce" else "MEDIUM",
              "MX host(s) not matched by any 'mx:' line in the MTA-STS policy: %s -- senders %s mail to them"
              % (", ".join(uncovered), "refuse to deliver" if mode == "enforce" else "report failures for"))
    return s.result()


def check_tls_rpt(domain):
    txts = [t for t in dns_query("_smtp._tls." + domain, TYPE_TXT) if t.lower().startswith("v=tlsrptv1")]
    if not txts:
        s = Section(present=False)
        s.add("LOW", "No SMTP TLS reporting (_smtp._tls TXT v=TLSRPTv1) -- you won't hear about TLS delivery failures")
        return s.result()
    s = Section(present=True, record=txts[0])
    rua = _tags(txts[0]).get("rua", "")
    if not rua or not all(u.strip().lower().startswith(("mailto:", "https:")) for u in rua.split(",")):
        s.add("MEDIUM", "TLS-RPT record has no valid rua= (mailto: or https: URIs)")
    return s.result()


def check_bimi(domain, dmarc_result):
    txts = [t for t in dns_query("default._bimi." + domain, TYPE_TXT) if t.lower().startswith("v=bimi1")]
    if not txts:
        s = Section(present=False)
        s.add("INFO", "No BIMI record (default._bimi TXT) -- optional: shows your logo in supporting inboxes")
        return s.result()
    tags = _tags(txts[0])
    s = Section(present=True, record=txts[0], logo=tags.get("l", ""), authority=tags.get("a", ""))
    pol = dmarc_result.get("policy")
    pct = (dmarc_result.get("tags") or {}).get("pct", "100")
    if pol not in ("quarantine", "reject") or pct != "100":
        s.add("MEDIUM", "BIMI requires an enforcing DMARC policy (p=quarantine or reject, pct=100) -- mailbox providers ignore it")
    logo = tags.get("l", "")
    if not logo:
        s.add("MEDIUM", "BIMI record has no l= logo URL")
    elif not logo.lower().startswith("https://"):
        s.add("MEDIUM", "BIMI logo URL must be https: %s" % logo)
    else:
        host, _, path = logo[8:].partition("/")
        status, body, err = https_get(host, "/" + path)
        if status != 200:
            s.add("MEDIUM", "BIMI logo %s not retrievable (%s)" % (logo, err or "HTTP %s" % status))
        elif "<svg" not in body[:4096].lower():
            s.add("MEDIUM", "BIMI logo %s is not an SVG document" % logo)
    if not tags.get("a"):
        s.add("INFO", "BIMI has no a= certificate (VMC/CMC); Gmail and Apple Mail only show logos with one")
    return s.result()


# --------------------------------------------------------------------------- MX STARTTLS

def _smtp_reply(f):
    lines = []
    while True:
        line = f.readline(4096).decode("utf-8", "replace")
        if not line:
            raise OSError("connection closed")
        lines.append(line.rstrip("\r\n"))
        if len(line) < 4 or line[3] != "-":
            return int(line[:3]), lines


def probe_starttls(host):
    """Connect to host:25, EHLO, STARTTLS, handshake with verification. Returns a dict."""
    out = {"host": host, "starttls": False, "tls_version": None, "cert_valid": None, "error": None}
    ips = resolve(host)
    if not ips:
        out["error"] = "does not resolve"
        return out
    try:
        sock = socket.create_connection((ips[0], SMTP_PORT), timeout=TIMEOUT * 3)
    except OSError as e:
        out["error"] = "port %d unreachable (%s)" % (SMTP_PORT, e)
        return out
    try:
        f = sock.makefile("rb")
        code, _ = _smtp_reply(f)
        sock.sendall(b"EHLO mail-security-auditor.invalid\r\n")
        code, lines = _smtp_reply(f)
        if code != 250 or not any(l[4:].strip().upper() == "STARTTLS" for l in lines):
            return out
        out["starttls"] = True
        sock.sendall(b"STARTTLS\r\n")
        code, _ = _smtp_reply(f)
        if code != 220:
            out["error"] = "STARTTLS refused (%d)" % code
            return out
        for verify in (True, False):
            ctx = ssl.create_default_context()
            if not verify:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            try:
                tls = ctx.wrap_socket(sock, server_hostname=host)
                out["tls_version"] = tls.version()
                out["cert_valid"] = verify
                tls.close()
                return out
            except ssl.SSLCertVerificationError as e:
                out["cert_error"] = e.verify_message or str(e)
                # reconnect for the unverified handshake so we can still report the TLS version
                sock.close()
                sock = socket.create_connection((ips[0], SMTP_PORT), timeout=TIMEOUT * 3)
                f = sock.makefile("rb")
                _smtp_reply(f)
                sock.sendall(b"EHLO mail-security-auditor.invalid\r\n")
                _smtp_reply(f)
                sock.sendall(b"STARTTLS\r\n")
                _smtp_reply(f)
        return out
    except (OSError, ssl.SSLError, ValueError) as e:
        out["error"] = str(e)
        return out
    finally:
        try:
            sock.close()
        except OSError:
            pass


def check_smtp(domain, mx_result, mta_sts):
    s = Section(servers=[])
    enforce = ((mta_sts.get("policy") or {}).get("mode") or "").lower() == "enforce"
    for host in mx_hosts(mx_result)[:5]:
        r = probe_starttls(host)
        s.data["servers"].append(r)
        if r["error"] and not r["starttls"]:
            s.add("INFO", "MX %s: could not test STARTTLS (%s)" % (host, r["error"]))
        elif not r["starttls"]:
            s.add("HIGH", "MX %s does not offer STARTTLS -- mail to it travels unencrypted" % host)
        elif r["cert_valid"] is False:
            s.add("HIGH" if enforce else "MEDIUM",
                  "MX %s: TLS certificate doesn't verify (%s)%s" % (host, r.get("cert_error"),
                                                                    " -- MTA-STS enforce senders will refuse it" if enforce else ""))
        elif r["tls_version"] in ("TLSv1", "TLSv1.1"):
            s.add("MEDIUM", "MX %s negotiated legacy %s" % (host, r["tls_version"]))
    return s.result()


# --------------------------------------------------------------------------- audit

SECTIONS = ("mx", "spf", "dmarc", "dkim", "mta_sts", "tls_rpt", "bimi", "smtp")


def audit_domain(domain, selectors=None, smtp=False):
    result = {"domain": domain, "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())}
    result["mx"] = check_mx(domain)
    result["spf"] = check_spf(domain)
    result["dmarc"] = check_dmarc(domain)
    result["dkim"] = check_dkim(domain, selectors)
    receives = bool(mx_hosts(result["mx"]))
    if receives:
        result["mta_sts"] = check_mta_sts(domain, result["mx"])
        result["tls_rpt"] = check_tls_rpt(domain)
    result["bimi"] = check_bimi(domain, result["dmarc"])
    if smtp and receives:
        result["smtp"] = check_smtp(domain, result["mx"], result["mta_sts"])
    findings = [dict(f, check=k) for k in SECTIONS if k in result for f in result[k]["findings"]]
    findings.sort(key=lambda f: RANK[f["severity"]])
    result["findings"] = findings
    result["counts"] = {sv: sum(1 for f in findings if f["severity"] == sv) for sv in SEVERITIES}
    result["all_issues"] = [f["message"] for f in findings if f["severity"] != "INFO"]
    result["issue_count"] = len(result["all_issues"])
    return result


def worst(result):
    return min((RANK[f["severity"]] for f in result["findings"]), default=len(SEVERITIES))


LABELS = {"mx": "MX", "spf": "SPF", "dmarc": "DMARC", "dkim": "DKIM", "mta_sts": "MTA-STS",
          "tls_rpt": "TLS-RPT", "bimi": "BIMI", "smtp": "MX STARTTLS"}


def print_report(result):
    print("\n=== Mail Security Audit: %s ===" % result["domain"])
    mx = result["mx"]
    print("\nMX records: %d" % len(mx["records"]))
    for r in mx["records"]:
        print("  " + r)
    spf = result["spf"]
    print("\nSPF: %s" % ("present" if spf["present"] else "MISSING"))
    for r in spf["records"]:
        print("  " + r)
    if spf["present"]:
        print("  DNS lookups: %d/%d, void lookups: %d/%d" % (spf["lookups"], SPF_LOOKUP_LIMIT,
                                                            spf["void_lookups"], SPF_VOID_LIMIT))
    dmarc = result["dmarc"]
    print("\nDMARC: %s" % ("present" if dmarc["present"] else "MISSING"))
    for r in dmarc["records"]:
        print("  " + r)
    dkim = result["dkim"]
    print("\nDKIM selectors found: %d" % len(dkim["found"]))
    for f in dkim["found"]:
        bits = (" (%d-bit RSA)" % f["key_bits"]) if f.get("key_bits") else ""
        print("  selector=%s%s: %s..." % (f["selector"], bits, f["record"][:70]))
    for key in ("mta_sts", "tls_rpt", "bimi"):
        if key in result:
            print("\n%s: %s" % (LABELS[key], "present" if result[key].get("present") else "not configured"))
    if "smtp" in result:
        print("\nMX STARTTLS:")
        for r in result["smtp"]["servers"]:
            print("  %s: %s" % (r["host"], ("STARTTLS %s, certificate %s" % (r["tls_version"], "valid" if r["cert_valid"] else "INVALID"))
                                if r["tls_version"] else (r["error"] or "no STARTTLS")))
    print("\nFindings:")
    for f in result["findings"]:
        print("  [%-6s] %-8s %s" % (f["severity"], LABELS[f["check"]], f["message"]))
    if not result["findings"]:
        print("  none")
    c = result["counts"]
    print("\nTotal issues: %d (%d high, %d medium, %d low; %d info)" % (result["issue_count"], c["HIGH"], c["MEDIUM"], c["LOW"], c["INFO"]))


def render_html(results):
    rows = []
    for r in results:
        w = worst(r)
        sev = "high" if w == 0 else ("medium" if w == 1 else "low")
        issues_html = "".join("<li><b>%s</b> %s: %s</li>" % (f["severity"], LABELS[f["check"]], html.escape(f["message"]))
                              for f in r["findings"] if f["severity"] != "INFO") or "<li>None found</li>"
        dmarc_status = ("present (" + r["dmarc"].get("policy", "") + ")") if r["dmarc"]["present"] else "missing"
        spf = r["spf"]
        spf_status = ("present, %d/10 lookups" % spf["lookups"]) if spf["present"] else "missing"
        extra = "".join("<tr><td>%s</td><td>%s</td></tr>" % (LABELS[k], "present" if r[k].get("present") else "not configured")
                        for k in ("mta_sts", "tls_rpt", "bimi") if k in r)
        rows.append("""
        <div class="domain-card sev-%s">
          <h2>%s</h2>
          <p class="meta">Checked %s &middot; %d issue(s)</p>
          <table>
            <tr><td>MX</td><td>%d record(s)</td></tr>
            <tr><td>SPF</td><td>%s</td></tr>
            <tr><td>DMARC</td><td>%s</td></tr>
            <tr><td>DKIM</td><td>%d selector(s) matched</td></tr>%s
          </table>
          <ul class="issues">%s</ul>
        </div>""" % (
            sev, html.escape(r["domain"]), html.escape(r["timestamp"]), r["issue_count"],
            len(r["mx"]["records"]), spf_status, html.escape(dmarc_status), len(r["dkim"]["found"]), extra,
            issues_html,
        ))
    return """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Mail Security Audit Report</title>
<style>
body{font-family:-apple-system,Segoe UI,sans-serif;background:#0b0e14;color:#e6e6e6;margin:0;padding:2rem;}
h1{color:#7dd3fc}
.domain-card{background:#141922;border:1px solid #232a36;border-radius:10px;padding:1.2rem 1.5rem;margin-bottom:1.2rem;}
.sev-high{border-left:4px solid #f87171}
.sev-medium{border-left:4px solid #fbbf24}
.sev-low{border-left:4px solid #4ade80}
.meta{color:#9ca3af;font-size:0.85rem}
table{border-collapse:collapse;margin:0.5rem 0}
td{padding:2px 10px 2px 0;font-size:0.9rem}
.issues li{font-size:0.88rem;color:#fca5a5;margin:2px 0}
</style></head>
<body><h1>Mail Security Audit Report</h1>%s
<p style="color:#6b7280;font-size:0.8rem;margin-top:2rem">Generated by mail-security-auditor %s (Errant Solutions) &mdash; stdlib-only Python, no external dependencies.</p>
</body></html>""" % ("".join(rows), __version__)


def main(argv=None):
    global HTTPS_PORT, SMTP_PORT
    ap = argparse.ArgumentParser(
        prog="mail-security-auditor",
        description="Email security auditor: SPF (incl. the 10-lookup limit), DKIM, DMARC, MX, MTA-STS, TLS-RPT, BIMI "
                    "and optional MX STARTTLS checks.",
        epilog="Exit codes: 0 no finding at/above --fail-on, 1 at least one, 2 usage error.")
    ap.add_argument("--version", action="version", version="%(prog)s " + __version__)
    ap.add_argument("domains", nargs="+", help="Domain(s) to audit")
    ap.add_argument("--json", action="store_true", help="Output JSON instead of text")
    ap.add_argument("--html", metavar="FILE", help="Write HTML report to FILE")
    ap.add_argument("--selectors", metavar="SEL", help="Comma-separated extra DKIM selectors to try")
    ap.add_argument("--resolver", metavar="IP[:PORT]", action="append",
                    help="DNS resolver to query instead of 1.1.1.1/8.8.8.8/9.9.9.9 (repeatable, "
                         "e.g. your internal resolver or 127.0.0.1:5353)")
    ap.add_argument("--smtp", action="store_true",
                    help="also connect to each MX on port 25 and check STARTTLS + certificate (needs outbound port 25)")
    ap.add_argument("--fail-on", choices=["high", "medium", "low", "never"], default="medium",
                    help="lowest severity that makes the exit code 1 (default: medium)")
    ap.add_argument("--https-port", type=int, default=443, help=argparse.SUPPRESS)
    ap.add_argument("--smtp-port", type=int, default=25, help=argparse.SUPPRESS)
    args = ap.parse_args(argv)
    HTTPS_PORT, SMTP_PORT = args.https_port, args.smtp_port

    if args.resolver:
        DNS_SERVERS[:] = [r.strip() for item in args.resolver for r in item.split(",") if r.strip()]

    selectors = COMMON_DKIM_SELECTORS
    if args.selectors:
        extra = [s.strip() for s in args.selectors.split(",") if s.strip()]
        selectors = list(dict.fromkeys(selectors + extra))

    results = [audit_domain(domain.strip().rstrip("."), selectors, args.smtp) for domain in args.domains]

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for r in results:
            print_report(r)

    if args.html:
        with open(args.html, "w", encoding="utf-8") as f:
            f.write(render_html(results))
        print("\nHTML report written to %s" % args.html)

    if args.fail_on == "never":
        return 0
    gate = RANK[args.fail_on.upper()]
    return 1 if any(worst(r) <= gate for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
