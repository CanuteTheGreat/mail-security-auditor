"""Detection accuracy for SPF, DMARC and DKIM, judged against independent references.

* SPF differential (false negatives AND false positives): a seeded random corpus of 120 SPF
  include trees (includes, redirects, a/mx terms, missing targets, loops, void names,
  over-the-limit trees) is served by a real dnsmasq and evaluated twice: by this tool and by
  pyspf, the reference RFC 7208 implementation (used by Postfix's policyd-spf), with dnspython
  pointed at the same dnsmasq. For every domain, "the tool reports a HIGH SPF finding" must
  equal "pyspf returns permerror", and the tool's lookup count must equal pyspf's.
* DMARC: a curated corpus of real published records (known good, must come back with nothing
  at MEDIUM or above) and RFC 7489 violations (known bad, exact expected finding set).
* DKIM key size: keys of 512..4096 bits (incl. odd sizes and the bare RSAPublicKey form) made by
  openssl; the tool's key_bits must equal what `openssl pkey -text` reports, and the severity
  must follow RFC 8301 (< 1024 HIGH, < 2048 LOW).
"""
import base64
import json
import os
import random
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest

import dns.resolver
import spf

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(os.path.dirname(HERE), "mail_audit.py")
PORT = None        # picked free in setUpModule (free_dns_port)
RESOLVER = None
CLIENT_IP = "203.0.113.250"   # matches no ip4/a/mx in the corpus: pyspf evaluates every term
SEED = 20261016


def run(*args):
    return subprocess.run([sys.executable, TOOL, "--resolver", RESOLVER] + list(args),
                          capture_output=True, text=True, timeout=600)


def audit_many(domains, *extra):
    out = []
    for i in range(0, len(domains), 40):
        p = run("--json", "--fail-on", "never", *(list(extra) + domains[i:i + 40]))
        assert p.returncode == 0, p.stderr
        out += json.loads(p.stdout)
    return {r["domain"]: r for r in out}


def spf_corpus():
    """(records, roots): dnsmasq lines and the root domains to evaluate."""
    rnd = random.Random(SEED)
    recs = []
    # leaf pools: SPF records with 0..2 lookups of their own
    leaves = []
    for i in range(30):
        name = "l%d.leaf.test" % i
        kind = i % 5
        if kind == 0:
            body = "ip4:192.0.2.%d -all" % (i + 1)
        elif kind == 1:
            body = "a:h%d.leaf.test -all" % i
            recs.append("host-record=h%d.leaf.test,198.51.100.%d" % (i, i + 1))
        elif kind == 2:
            body = "mx:m%d.leaf.test ~all" % i
            recs.append("mx-host=m%d.leaf.test,mail%d.leaf.test,10" % (i, i))
            recs.append("host-record=mail%d.leaf.test,198.51.100.%d" % (i, 100 + i))
        elif kind == 3:
            # (exists: would match any client once its name resolves, ending evaluation early)
            body = "a:h%d.leaf.test/24 ip6:2001:db8::/32 -all" % i
            recs.append("host-record=h%d.leaf.test,198.51.100.%d" % (i, i + 1))
        else:
            body = "a:h%d.leaf.test a:void%d.leaf.test -all" % (i, i)  # one void lookup
            recs.append("host-record=h%d.leaf.test,198.51.100.%d" % (i, i + 1))
        recs.append('txt-record=%s,"v=spf1 %s"' % (name, body))
        leaves.append(name)
    # middle layer: includes of 1..4 leaves
    mids = []
    for i in range(20):
        name = "m%d.mid.test" % i
        inc = rnd.sample(leaves, rnd.randint(1, 4))
        recs.append('txt-record=%s,"v=spf1 %s -all"' % (name, " ".join("include:" + x for x in inc)))
        mids.append(name)
    recs.append('txt-record=noSPF.mid.test,"some-verification=1"')
    roots = []
    for i in range(120):
        name = "r%d.root.test" % i
        terms = []
        for _ in range(rnd.randint(1, 5)):
            r = rnd.random()
            if r < 0.40:
                terms.append("include:" + rnd.choice(mids))
            elif r < 0.65:
                terms.append("include:" + rnd.choice(leaves))
            elif r < 0.72:
                terms.append("include:missing%d.root.test" % rnd.randint(0, 9))   # NXDOMAIN include
            elif r < 0.76:
                terms.append("include:noSPF.mid.test")                              # TXT but no SPF
            elif r < 0.84:
                terms.append("a:gone%d.root.test" % rnd.randint(0, 99))             # void
            elif r < 0.90:
                terms.append("mx:" + rnd.choice(["m%d.leaf.test" % j for j in (2, 7, 12)]))
            elif r < 0.95:
                terms.append("ip4:192.0.2.%d" % rnd.randint(1, 254))
            else:
                terms.append("include:r%d.root.test" % rnd.randint(0, 119))         # may loop
        if rnd.random() < 0.2:
            body = " ".join(terms) + " redirect=" + rnd.choice(mids)
        else:
            body = " ".join(terms) + " " + rnd.choice(["-all", "~all"])
        recs.append('txt-record=%s,"v=spf1 %s"' % (name, body))
        roots.append(name)
    return recs, roots


# real published DMARC records (2026-10 snapshots; rua addresses in their own organisation or
# authorized via _report._dmarc) -> nothing at MEDIUM or above
GOOD_DMARC = {
    "google.dm.test": "v=DMARC1; p=reject; rua=mailto:mailauth-reports@google.dm.test",
    "paypal.dm.test": "v=DMARC1; p=reject; rua=mailto:d@rua.agari.test; ruf=mailto:d@ruf.agari.test",
    "github.dm.test": "v=DMARC1; p=reject; pct=100; rua=mailto:dmarc@github.dm.test",
    "gov.dm.test": "v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s; rua=mailto:reports@dmarc.cyber.dhs.test",
    "quar.dm.test": "v=DMARC1;p=quarantine;rua=mailto:x@quar.dm.test",  # LOW only
    "spaces.dm.test": "v=DMARC1 ;  p = reject ; rua = mailto:x@spaces.dm.test",
}
GOOD_AUTH = ["paypal.dm.test._report._dmarc.rua.agari.test", "paypal.dm.test._report._dmarc.ruf.agari.test",
             "gov.dm.test._report._dmarc.dmarc.cyber.dhs.test"]

# RFC 7489 violations -> the exact (severity, finding-start) set the tool must report
BAD_DMARC = {
    "none.dm.test": ("v=DMARC1; p=none; rua=mailto:x@none.dm.test",
                     {("MEDIUM", "DMARC policy is 'p=none'")}),
    "nop.dm.test": ("v=DMARC1; rua=mailto:x@nop.dm.test",
                    {("HIGH", "DMARC policy '(missing)'")}),
    "typo.dm.test": ("v=DMARC1; p=rejected; rua=mailto:x@typo.dm.test",
                     {("HIGH", "DMARC policy 'rejected'")}),
    "sp.dm.test": ("v=DMARC1; p=reject; sp=none; rua=mailto:x@sp.dm.test",
                   {("MEDIUM", "DMARC 'sp=none'")}),
    "spbad.dm.test": ("v=DMARC1; p=reject; sp=strict; rua=mailto:x@spbad.dm.test",
                      {("MEDIUM", "DMARC subdomain policy 'sp=strict'")}),
    "align.dm.test": ("v=DMARC1; p=reject; adkim=strict; aspf=r; rua=mailto:x@align.dm.test",
                      {("MEDIUM", "DMARC 'adkim=strict' is invalid")}),
    "ext.dm.test": ("v=DMARC1; p=reject; rua=mailto:a@thirdparty.test",
                    {("MEDIUM", "rua address a@thirdparty.test is in another domain")}),
    "norua.dm.test": ("v=DMARC1; p=reject", {("LOW", "No 'rua' aggregate-report address")}),
    "pct.dm.test": ("v=DMARC1; p=reject; pct=0; rua=mailto:x@pct.dm.test", {("LOW", "DMARC 'pct=0'")}),
}

DKIM_SIZES = [512, 768, 1023, 1024, 1536, 2047, 2048, 3072, 4096]


def openssl_key(bits, bare=False):
    key = os.path.join(TMP, "dk%d.pem" % bits)
    subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:%d" % bits,
                    "-out", key], check=True, capture_output=True)
    text = subprocess.run(["openssl", "pkey", "-in", key, "-text_pub", "-noout"],
                          check=True, capture_output=True, text=True).stdout
    ref_bits = int(re.search(r"Public-Key: \((\d+) bit\)", text).group(1))
    if bare:
        der = subprocess.run(["openssl", "rsa", "-in", key, "-RSAPublicKey_out", "-outform", "DER"],
                             check=True, capture_output=True).stdout
    else:
        der = subprocess.run(["openssl", "pkey", "-in", key, "-pubout", "-outform", "DER"],
                             check=True, capture_output=True).stdout
    return base64.b64encode(der).decode(), ref_bits


def chunks(s, n=250):
    return ",".join('"%s"' % s[i:i + n] for i in range(0, len(s), n))


def free_dns_port():
    """A port on 127.0.0.1 free right now for both UDP and TCP (dnsmasq binds both).

    Never a fixed port: mutation testing runs this module in several processes at once (mutmut
    --max-children). With a fixed port the second dnsmasq could not bind and that process's tests
    queried the FIRST process's dnsmasq - another corpus (other DKIM keys) that could be torn down
    mid-test - so mutants were killed or kept at random instead of by what the tool does."""
    for _ in range(50):
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        t = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            u.bind(("127.0.0.1", 0))
            port = u.getsockname()[1]
            t.bind(("127.0.0.1", port))
            return port
        except OSError:
            continue
        finally:
            u.close()
            t.close()
    raise RuntimeError("no free UDP+TCP port on 127.0.0.1")


def dnsmasq_lost_bind(proc, logpath):
    """True when our dnsmasq exited because a parallel run took its port first (try another)."""
    if proc.poll() is None:
        return False
    with open(logpath) as f:
        log = f.read()
    if "Address already in use" in log or "address in use" in log.lower():
        return True
    raise RuntimeError("dnsmasq exited with %s:\n%s" % (proc.returncode, log))


def setUpModule():
    global TMP, DNSMASQ, ROOTS, DKIM_REF, PORT, RESOLVER
    TMP = tempfile.mkdtemp()
    recs, ROOTS = spf_corpus()
    for dom, rec in GOOD_DMARC.items():
        recs.append('txt-record=_dmarc.%s,"%s"' % (dom, rec))
    recs += ['txt-record=%s,"v=DMARC1"' % n for n in GOOD_AUTH]
    for dom, (rec, _) in BAD_DMARC.items():
        recs.append('txt-record=_dmarc.%s,"%s"' % (dom, rec))
    DKIM_REF = {}
    for bits in DKIM_SIZES:
        for bare in (False, True):
            dom = "k%d%s.dk.test" % (bits, "b" if bare else "")
            p, ref = openssl_key(bits, bare)
            DKIM_REF[dom] = ref
            recs.append("txt-record=selector1._domainkey.%s,%s" % (dom, chunks("v=DKIM1; k=rsa; p=" + p)))
    conf = os.path.join(TMP, "dnsmasq.conf")
    logpath = os.path.join(TMP, "dnsmasq.log")
    for _ in range(10):
        PORT = free_dns_port()
        RESOLVER = "127.0.0.1:%d" % PORT
        with open(conf, "w") as f:
            f.write("\n".join(["port=%d" % PORT, "listen-address=127.0.0.1", "bind-interfaces", "no-resolv",
                               "no-hosts", "local=/test/"] + recs) + "\n")
        log = open(logpath, "w")
        DNSMASQ = subprocess.Popen([shutil.which("dnsmasq") or "/usr/sbin/dnsmasq", "-k", "--conf-file=" + conf],
                                   stdout=log, stderr=subprocess.STDOUT)
        res = dns.resolver.Resolver(configure=False)
        res.nameservers, res.port, res.lifetime = ["127.0.0.1"], PORT, 10
        dns.resolver.default_resolver = res
        for _ in range(100):
            if dnsmasq_lost_bind(DNSMASQ, logpath):
                break
            try:
                res.resolve("l0.leaf.test", "TXT")
            except Exception:
                time.sleep(0.1)
                continue
            # answered: only OUR dnsmasq can hold the port if it is still alive (bind-interfaces
            # makes a dnsmasq that lost the race exit at once)
            time.sleep(0.2)
            if not dnsmasq_lost_bind(DNSMASQ, logpath):
                return
            break
        else:
            with open(logpath) as f:
                raise RuntimeError("dnsmasq did not come up:\n" + f.read())
    raise RuntimeError("dnsmasq could not bind a port in 10 attempts")


def tearDownModule():
    DNSMASQ.terminate()
    DNSMASQ.wait(5)
    shutil.rmtree(TMP, ignore_errors=True)


def pyspf(domain):
    """(result, lookups) from the reference implementation."""
    q = spf.query(i=CLIENT_IP, s="postmaster@" + domain, h="mx.client.example", strict=True, timeout=10)
    result = q.check()[0]
    return result, q.lookups


class TestSpfAgainstPyspf(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = audit_many(ROOTS, "--selectors", "none")

    def test_corpus_has_both_outcomes(self):
        results = [pyspf(d)[0] for d in ROOTS]
        self.assertGreater(results.count("permerror"), 15, results)
        self.assertGreater(len([r for r in results if r in ("fail", "softfail")]), 30, results)

    def test_permerror_verdicts_match(self):
        wrong = []
        for d in ROOTS:
            ref, lookups = pyspf(d)
            spf_f = self.tool[d]["spf"]["findings"]
            high = [f["message"] for f in spf_f if f["severity"] == "HIGH"]
            if bool(high) != (ref == "permerror"):
                wrong.append((d, ref, lookups, self.tool[d]["spf"]["lookups"], high))
        self.assertEqual(wrong, [], "tool HIGH finding vs pyspf permerror disagree")

    def test_lookup_counts_match_when_evaluation_completes(self):
        wrong = []
        for d in ROOTS:
            ref, lookups = pyspf(d)
            if ref == "permerror":
                continue  # pyspf stops at the first error; the tool keeps counting the whole tree
            if self.tool[d]["spf"]["lookups"] != lookups:
                wrong.append((d, self.tool[d]["spf"]["lookups"], lookups))
        self.assertEqual(wrong, [])

    def test_over_limit_trees_are_reported_with_the_count(self):
        for d in ROOTS:
            n = self.tool[d]["spf"]["lookups"]
            msgs = " | ".join(self.tool[d]["spf"]["issues"])
            if n > 10:
                self.assertIn("SPF needs %d DNS lookups" % n, msgs)
                self.assertEqual(pyspf(d)[0], "permerror", d)


class TestDmarcCorpus(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = audit_many(sorted(GOOD_DMARC) + sorted(BAD_DMARC), "--selectors", "none")

    def test_known_good_records_are_clean(self):
        for d in GOOD_DMARC:
            bad = [(f["severity"], f["message"]) for f in self.tool[d]["dmarc"]["findings"]
                   if f["severity"] in ("HIGH", "MEDIUM")]
            self.assertEqual(bad, [], d)
        self.assertEqual(self.tool["spaces.dm.test"]["dmarc"]["policy"], "reject")

    def test_known_bad_records_exact_findings(self):
        for d, (_, expected) in BAD_DMARC.items():
            got = self.tool[d]["dmarc"]["findings"]
            self.assertEqual(len(got), len(expected), (d, got))
            for sev, start in expected:
                self.assertTrue(any(f["severity"] == sev and f["message"].startswith(start) for f in got), (d, got))


class TestDkimKeySizeAgainstOpenssl(unittest.TestCase):
    def test_key_bits_and_severity(self):
        tool = audit_many(sorted(DKIM_REF))
        for d, ref in DKIM_REF.items():
            found = tool[d]["dkim"]["found"]
            self.assertEqual([f["key_bits"] for f in found], [ref], d)
            sev = [f["severity"] for f in tool[d]["dkim"]["findings"]]
            self.assertEqual(sev, ["HIGH"] if ref < 1024 else ["LOW"] if ref < 2048 else [], (d, ref))


if __name__ == "__main__":
    unittest.main()
