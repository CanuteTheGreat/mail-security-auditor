#!/usr/bin/env python3
"""
mail_audit.py -- Email authentication (SPF/DKIM/DMARC/MX) hygiene auditor.

Zero-dependency, single-file, stdlib-only Python 3. Implements a minimal raw
DNS client (UDP, RFC 1035) to query TXT/MX records directly -- no dnspython,
no external binaries (dig/host), works anywhere Python 3 runs.

Checks performed:
  - MX records present and resolvable
  - SPF (TXT v=spf1) present, not overly permissive (+all), not missing
    -all/~all, record count (RFC 7208 allows only one SPF TXT record)
  - DMARC (_dmarc.domain TXT v=DMARC1) present, policy strength
    (none/quarantine/reject), rua/ruf reporting configured
  - DKIM: checks common selectors (google, selector1/2, default, k1, dkim,
    mail, s1/s2, mandrill, mailgun, sendgrid) for a DKIM TXT record

Usage:
  python3 mail_audit.py example.com [example2.com ...]
  python3 mail_audit.py --json example.com
  python3 mail_audit.py --html report.html example.com

License: MIT (c) 2026 Errant Solutions
"""
import sys
import socket
import struct
import random
import json
import html
import argparse
import time

DNS_SERVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
TIMEOUT = 4.0

TYPE_A = 1
TYPE_MX = 15
TYPE_TXT = 16
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


def check_spf(domain):
    txts = dns_query(domain, TYPE_TXT)
    spf_records = [t for t in txts if t.lower() == "v=spf1" or t.lower().startswith("v=spf1 ")]
    issues = []
    if not spf_records:
        return {"present": False, "records": [], "issues": ["No SPF record found (v=spf1 TXT)"]}
    if len(spf_records) > 1:
        issues.append("Multiple SPF records found (%d); RFC 7208 permits only one -- causes PermError in strict validators" % len(spf_records))
    record = spf_records[0]
    terms = _spf_terms(record)
    all_terms = [q for q, name, _ in terms if name == "all"]
    has_redirect = any(t.lower().startswith("redirect=") for t in record.split()[1:])
    if all_terms:
        q = all_terms[0]
        if q == "+":
            issues.append("SPF uses '+all' (or a bare 'all', which means the same) -- allows ANY host to send as this domain (critical misconfiguration)")
        elif q == "?":
            issues.append("SPF uses '?all' (neutral) -- provides no real protection")
        elif q == "~":
            issues.append("SPF uses '~all' (softfail) -- consider '-all' (hardfail) once confident in the record")
    elif not has_redirect:
        issues.append("SPF has no 'all' mechanism -- undefined/permissive behavior for non-matching senders")
    senders = [name for _, name, _ in terms if name in ("include", "a", "mx", "ip4", "ip6", "exists", "ptr")]
    null_record = terms == [("-", "all", "")]  # "v=spf1 -all": domain deliberately sends no mail
    if not senders and not has_redirect and not null_record:
        issues.append("SPF record has no include/a/mx/ip4/ip6 mechanisms -- likely won't authorize any real sender")
    return {"present": True, "records": spf_records, "issues": issues}


def check_dmarc(domain):
    txts = dns_query("_dmarc." + domain, TYPE_TXT)
    dmarc_records = [t for t in txts if t.lower().startswith("v=dmarc1")]
    issues = []
    if not dmarc_records:
        return {"present": False, "records": [], "issues": ["No DMARC record found (_dmarc.<domain> TXT v=DMARC1)"]}
    if len(dmarc_records) > 1:
        issues.append("Multiple DMARC records found (%d); RFC 7489 says receivers then ignore DMARC entirely" % len(dmarc_records))
    record = dmarc_records[0]
    fields = {}
    for part in record.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            fields[k.strip().lower()] = v.strip()
    policy = fields.get("p", "").lower()
    if policy == "none":
        issues.append("DMARC policy is 'p=none' -- monitoring only, no enforcement against spoofing")
    elif policy == "quarantine":
        issues.append("DMARC policy is 'p=quarantine' -- consider 'p=reject' once reports show clean alignment")
    elif policy != "reject":
        issues.append("DMARC policy '%s' is non-standard or missing" % (policy or "(missing)"))
    if "rua" not in fields:
        issues.append("No 'rua' aggregate-report address configured -- no visibility into spoofing attempts")
    pct = fields.get("pct")
    if pct and pct != "100":
        issues.append("DMARC 'pct=%s' -- policy only applied to %s%% of mail" % (pct, pct))
    return {"present": True, "records": dmarc_records, "policy": policy, "issues": issues}


def check_dkim(domain, selectors=None):
    selectors = selectors or COMMON_DKIM_SELECTORS
    found = []
    for sel in selectors:
        name = sel + "._domainkey." + domain
        txts = dns_query(name, TYPE_TXT)
        dkim_txts = [t for t in txts if "v=dkim1" in t.lower() or "p=" in t.lower()]
        if dkim_txts:
            found.append({"selector": sel, "record": dkim_txts[0]})
    issues = []
    if not found:
        issues.append(
            "No DKIM record found under %d common selectors -- this only means "
            "the common ones weren't found; check your mail provider's docs for "
            "the actual selector name" % len(selectors)
        )
    return {"found": found, "issues": issues}


def check_mx(domain):
    mx = dns_query(domain, TYPE_MX)
    issues = []
    if not mx:
        issues.append("No MX records found -- domain cannot receive mail (may be intentional)")
    return {"records": sorted(mx), "issues": issues}


def audit_domain(domain, selectors=None):
    result = {"domain": domain, "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())}
    result["mx"] = check_mx(domain)
    result["spf"] = check_spf(domain)
    result["dmarc"] = check_dmarc(domain)
    result["dkim"] = check_dkim(domain, selectors)
    all_issues = (
        result["mx"]["issues"] + result["spf"]["issues"] +
        result["dmarc"]["issues"] + result["dkim"]["issues"]
    )
    result["issue_count"] = len(all_issues)
    result["all_issues"] = all_issues
    return result


def print_report(result):
    d = result["domain"]
    print("\n=== Mail Security Audit: %s ===" % d)
    mx = result["mx"]
    print("\nMX records: %d" % len(mx["records"]))
    for r in mx["records"]:
        print("  " + r)
    for i in mx["issues"]:
        print("  [!] " + i)

    spf = result["spf"]
    print("\nSPF: %s" % ("present" if spf["present"] else "MISSING"))
    for r in spf["records"]:
        print("  " + r)
    for i in spf["issues"]:
        print("  [!] " + i)

    dmarc = result["dmarc"]
    print("\nDMARC: %s" % ("present" if dmarc["present"] else "MISSING"))
    for r in dmarc["records"]:
        print("  " + r)
    for i in dmarc["issues"]:
        print("  [!] " + i)

    dkim = result["dkim"]
    print("\nDKIM selectors found: %d" % len(dkim["found"]))
    for f in dkim["found"]:
        print("  selector=%s: %s..." % (f["selector"], f["record"][:80]))
    for i in dkim["issues"]:
        print("  [!] " + i)

    print("\nTotal issues: %d" % result["issue_count"])


def render_html(results):
    rows = []
    for r in results:
        sev = "high" if r["issue_count"] >= 3 else ("medium" if r["issue_count"] >= 1 else "low")
        issues_html = "".join("<li>%s</li>" % html.escape(i) for i in r["all_issues"]) or "<li>None found</li>"
        dmarc_status = ("present (" + r["dmarc"].get("policy", "") + ")") if r["dmarc"]["present"] else "missing"
        rows.append("""
        <div class="domain-card sev-%s">
          <h2>%s</h2>
          <p class="meta">Checked %s &middot; %d issue(s)</p>
          <table>
            <tr><td>MX</td><td>%d record(s)</td></tr>
            <tr><td>SPF</td><td>%s</td></tr>
            <tr><td>DMARC</td><td>%s</td></tr>
            <tr><td>DKIM</td><td>%d selector(s) matched</td></tr>
          </table>
          <ul class="issues">%s</ul>
        </div>""" % (
            sev, html.escape(r["domain"]), html.escape(r["timestamp"]), r["issue_count"],
            len(r["mx"]["records"]),
            "present" if r["spf"]["present"] else "missing",
            dmarc_status,
            len(r["dkim"]["found"]),
            issues_html,
        ))
    return """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Mail Security Audit Report</title>
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
<p style="color:#6b7280;font-size:0.8rem;margin-top:2rem">Generated by mail_audit.py (Errant Solutions) &mdash; stdlib-only Python, no external dependencies.</p>
</body></html>""" % "".join(rows)


def main():
    ap = argparse.ArgumentParser(description="Email authentication (SPF/DKIM/DMARC/MX) hygiene auditor")
    ap.add_argument("domains", nargs="+", help="Domain(s) to audit")
    ap.add_argument("--json", action="store_true", help="Output JSON instead of text")
    ap.add_argument("--html", metavar="FILE", help="Write HTML report to FILE")
    ap.add_argument("--selectors", metavar="SEL", help="Comma-separated extra DKIM selectors to try")
    ap.add_argument("--resolver", metavar="IP[:PORT]", action="append",
                    help="DNS resolver to query instead of 1.1.1.1/8.8.8.8/9.9.9.9 (repeatable, "
                         "e.g. your internal resolver or 127.0.0.1:5353)")
    args = ap.parse_args()

    if args.resolver:
        DNS_SERVERS[:] = [r.strip() for item in args.resolver for r in item.split(",") if r.strip()]

    selectors = COMMON_DKIM_SELECTORS
    if args.selectors:
        extra = [s.strip() for s in args.selectors.split(",") if s.strip()]
        selectors = list(dict.fromkeys(selectors + extra))

    results = [audit_domain(domain.strip().rstrip("."), selectors) for domain in args.domains]

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for r in results:
            print_report(r)

    if args.html:
        with open(args.html, "w", encoding="utf-8") as f:
            f.write(render_html(results))
        print("\nHTML report written to %s" % args.html)

    max_issues = max((r["issue_count"] for r in results), default=0)
    sys.exit(1 if max_issues >= 3 else 0)


if __name__ == "__main__":
    main()
