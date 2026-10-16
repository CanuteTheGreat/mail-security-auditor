"""End-to-end tests for mail_audit.py against a real DNS server.

A real dnsmasq instance (installed by ci/setup.sh) serves a test zone on
127.0.0.1:5353 with deliberately good and broken SPF/DKIM/DMARC/MX records,
and the tool is run as a subprocess with --resolver pointing at it -- the
same raw UDP/TCP DNS code path it uses against public resolvers.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(os.path.dirname(HERE), "mail_audit.py")
PORT = 5353
RESOLVER = f"127.0.0.1:{PORT}"
DKIM_KEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA" + "x" * 300 + "IDAQAB"
# ~750 bytes of TXT; the server caps UDP answers at 512 bytes (edns-packet-max) so
# this only arrives whole through the TC-bit -> TCP retry path.
BIG_SEGMENTS = ["v=DKIM1; k=rsa; p=" + "A" * 230] + ["B" * 250] * 2

RECORDS = [
    # fully healthy domain
    'mx-host=good.test,mx1.good.test,10',
    'txt-record=good.test,"v=spf1 ip4:192.0.2.0/24 include:_spf.good.test -all"',
    'txt-record=good.test,"google-site-verification=abc"',
    'txt-record=_dmarc.good.test,"v=DMARC1; p=reject; rua=mailto:dmarc@good.test"',
    f'txt-record=selector1._domainkey.good.test,"v=DKIM1; k=rsa; p={DKIM_KEY}"',
    # SPF variants (assertions only look at the SPF section)
    'txt-record=bareall.test,"v=spf1 include:_spf.example.test all"',
    'txt-record=plusall.test,"v=spf1 mx +all"',
    'txt-record=softfail.test,"v=spf1 mx ~all"',
    'txt-record=neutral.test,"v=spf1 mx ?all"',
    'txt-record=noall.test,"v=spf1 mx"',
    'txt-record=nomech.test,"v=spf1 ~all"',
    'txt-record=nullspf.test,"v=spf1 -all"',
    'txt-record=redirect.test,"v=spf1 redirect=_spf.good.test"',
    'txt-record=twospf.test,"v=spf1 mx -all"',
    'txt-record=twospf.test,"v=spf1 a -all"',
    # DMARC variants
    'txt-record=_dmarc.dnone.test,"v=DMARC1; p=none; rua=mailto:x@dnone.test"',
    'txt-record=_dmarc.dquar.test,"v=DMARC1; p=quarantine; rua=mailto:x@dquar.test"',
    'txt-record=_dmarc.dnorua.test,"v=DMARC1; p=reject"',
    'txt-record=_dmarc.dpct.test,"v=DMARC1; p=reject; rua=mailto:x@dpct.test; pct=50"',
    'txt-record=_dmarc.dbogus.test,"v=DMARC1; p=sometimes; rua=mailto:x@dbogus.test"',
    'txt-record=_dmarc.dtwo.test,"v=DMARC1; p=reject; rua=mailto:x@dtwo.test"',
    'txt-record=_dmarc.dtwo.test,"v=DMARC1; p=none; rua=mailto:x@dtwo.test"',
    # DKIM under a custom selector only
    f'txt-record=custom2024._domainkey.sel.test,"v=DKIM1; k=rsa; p={DKIM_KEY}"',
    # DKIM record too big for a UDP answer
    'txt-record=selector1._domainkey.big.test,' + ",".join(f'"{s}"' for s in BIG_SEGMENTS),
    # CNAME'd domain: MX answer arrives as CNAME + MX
    'cname=alias.test,good.test',
]


def setUpModule():
    global DNSMASQ, TMP
    TMP = tempfile.mkdtemp()
    conf = os.path.join(TMP, "dnsmasq.conf")
    with open(conf, "w") as f:
        f.write("\n".join([f"port={PORT}", "listen-address=127.0.0.1", "bind-interfaces", "no-resolv",
                           "no-hosts", "local=/test/", "edns-packet-max=512"] + RECORDS) + "\n")
    binary = shutil.which("dnsmasq") or "/usr/sbin/dnsmasq"
    log = open(os.path.join(TMP, "dnsmasq.log"), "w")  # a pipe would fill up and stall dnsmasq
    DNSMASQ = subprocess.Popen([binary, "-k", f"--conf-file={conf}"], stdout=log, stderr=subprocess.STDOUT)
    for _ in range(50):
        if DNSMASQ.poll() is not None:
            break
        p = run("--resolver", RESOLVER, "--json", "good.test")
        if p.returncode == 0 and json.loads(p.stdout)[0]["spf"]["present"]:
            return
        time.sleep(0.1)
    with open(os.path.join(TMP, "dnsmasq.log")) as f:
        raise RuntimeError("dnsmasq did not come up:\n" + f.read())


def tearDownModule():
    DNSMASQ.terminate()
    DNSMASQ.wait(5)
    shutil.rmtree(TMP, ignore_errors=True)


def run(*args):
    return subprocess.run([sys.executable, TOOL] + list(args), capture_output=True, text=True, timeout=120)


def audit(domain, *extra):
    p = run("--resolver", RESOLVER, "--json", *extra, domain)
    assert p.returncode in (0, 1), p.stderr
    res = json.loads(p.stdout)
    return p.returncode, res[0]


class TestHealthyDomain(unittest.TestCase):
    def test_good_domain_has_no_issues(self):
        code, r = audit("good.test")
        self.assertEqual(r["all_issues"], [])
        self.assertEqual(code, 0)
        self.assertEqual(r["mx"]["records"], ["10 mx1.good.test"])
        self.assertEqual(r["spf"]["records"], ["v=spf1 ip4:192.0.2.0/24 include:_spf.good.test -all"])
        self.assertEqual(r["dmarc"]["policy"], "reject")
        self.assertEqual([f["selector"] for f in r["dkim"]["found"]], ["selector1"])

    def test_cname_chain_does_not_leak_into_mx_list(self):
        _, r = audit("alias.test")
        self.assertEqual(r["mx"]["records"], ["10 mx1.good.test"])


class TestSpf(unittest.TestCase):
    def spf_issues(self, domain):
        return " | ".join(audit(domain)[1]["spf"]["issues"])

    def test_bare_all_means_pass_all(self):
        self.assertIn("'+all'", self.spf_issues("bareall.test"))

    def test_plus_all(self):
        self.assertIn("'+all'", self.spf_issues("plusall.test"))

    def test_softfail(self):
        self.assertIn("'~all' (softfail)", self.spf_issues("softfail.test"))

    def test_neutral(self):
        self.assertIn("'?all' (neutral)", self.spf_issues("neutral.test"))

    def test_no_all(self):
        self.assertIn("no 'all' mechanism", self.spf_issues("noall.test"))

    def test_no_sender_mechanisms(self):
        self.assertIn("no include/a/mx/ip4/ip6", self.spf_issues("nomech.test"))

    def test_null_record_is_clean(self):
        self.assertEqual(self.spf_issues("nullspf.test"), "")

    def test_redirect_counts_as_complete(self):
        self.assertEqual(self.spf_issues("redirect.test"), "")

    def test_multiple_spf_records(self):
        self.assertIn("Multiple SPF records found (2)", self.spf_issues("twospf.test"))

    def test_missing_spf(self):
        _, r = audit("nothing.test")
        self.assertFalse(r["spf"]["present"])


class TestDmarc(unittest.TestCase):
    def dmarc(self, domain):
        r = audit(domain)[1]["dmarc"]
        return r, " | ".join(r["issues"])

    def test_policies(self):
        for domain, expected in [("dnone.test", "p=none"), ("dquar.test", "p=quarantine"),
                                 ("dbogus.test", "non-standard")]:
            with self.subTest(domain=domain):
                self.assertIn(expected, self.dmarc(domain)[1])

    def test_missing_rua(self):
        self.assertIn("No 'rua'", self.dmarc("dnorua.test")[1])

    def test_pct(self):
        self.assertIn("pct=50", self.dmarc("dpct.test")[1])

    def test_multiple_records(self):
        self.assertIn("Multiple DMARC records", self.dmarc("dtwo.test")[1])

    def test_missing(self):
        r, issues = self.dmarc("nothing.test")
        self.assertFalse(r["present"])
        self.assertIn("No DMARC record", issues)


class TestDkimAndMx(unittest.TestCase):
    def test_custom_selector_only_found_with_selectors_option(self):
        _, r = audit("sel.test")
        self.assertEqual(r["dkim"]["found"], [])
        _, r = audit("sel.test", "--selectors", "custom2024,other")
        self.assertEqual([f["selector"] for f in r["dkim"]["found"]], ["custom2024"])
        self.assertEqual(r["dkim"]["issues"], [])

    def test_oversized_txt_comes_back_whole_over_tcp(self):
        _, r = audit("big.test")
        self.assertEqual(r["dkim"]["found"][0]["record"], "".join(BIG_SEGMENTS))

    def test_missing_everything_fails_exit_code(self):
        code, r = audit("nothing.test")
        self.assertEqual(code, 1)
        self.assertEqual(r["issue_count"], 4)
        self.assertIn("No MX records", " ".join(r["mx"]["issues"]))


class TestCli(unittest.TestCase):
    def test_text_report_multiple_domains(self):
        p = run("--resolver", RESOLVER, "good.test", "dnone.test")
        self.assertIn("=== Mail Security Audit: good.test ===", p.stdout)
        self.assertIn("=== Mail Security Audit: dnone.test ===", p.stdout)
        self.assertIn("DMARC: present", p.stdout)
        self.assertIn("Total issues: 0", p.stdout)
        self.assertEqual(p.returncode, 1)  # dnone.test: no SPF/MX/DKIM + p=none -> 3+ issues

    def test_html_report(self):
        out = os.path.join(TMP, "r.html")
        p = run("--resolver", RESOLVER, "--html", out, "good.test", "nothing.test")
        self.assertIn("HTML report written to", p.stdout)
        with open(out) as f:
            page = f.read()
        self.assertIn("<h2>good.test</h2>", page)
        self.assertIn("sev-high", page)
        self.assertIn("No DMARC record found", page)

    def test_resolver_fallback(self):
        # 192.0.2.1 (TEST-NET-1) never answers: the tool must fall through to
        # the next resolver and stop waiting on the dead one after the first timeout.
        start = time.time()
        p = run("--resolver", "192.0.2.1", "--resolver", RESOLVER, "--json", "good.test")
        self.assertLess(time.time() - start, 20)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertTrue(json.loads(p.stdout)[0]["spf"]["present"])

    def test_default_public_resolvers(self):
        # The default path: real public resolvers, real domain.
        p = run("--json", "gmail.com")
        r = json.loads(p.stdout)[0]
        self.assertTrue(r["spf"]["present"], r)
        self.assertTrue(r["dmarc"]["present"], r)
        self.assertTrue(r["mx"]["records"], r)

    def test_help(self):
        p = run("--help")
        self.assertEqual(p.returncode, 0)
        for opt in ("--json", "--html", "--selectors", "--resolver"):
            self.assertIn(opt, p.stdout)


if __name__ == "__main__":
    unittest.main()
