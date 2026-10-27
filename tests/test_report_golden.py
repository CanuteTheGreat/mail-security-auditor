"""Exact-output tests for the text and HTML reports (print_report, render_html).

These pin the report wording and structure for hand-built audit results that cover every
branch of the renderers (present / missing / not configured, key sizes, STARTTLS outcomes,
every severity, HTML escaping) so a changed label, separator, count or CSS class shows up.
"""
import contextlib
import io
import os
import json
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import mail_audit as m  # noqa: E402

R1 = {
 "domain": "full.test", "timestamp": "2026-10-27 01:02:03 UTC",
 "mx": {"records": ["10 mx1.full.test", "20 mx2.full.test"], "findings": []},
 "spf": {"present": True, "records": ["v=spf1 mx -all"], "lookups": 3, "void_lookups": 1, "findings": []},
 "dmarc": {"present": True, "policy": "reject", "records": ["v=DMARC1; p=reject"], "findings": []},
 "dkim": {"found": [{"selector": "s1", "key_bits": 2048, "record": "v=DKIM1; k=rsa; p=" + "A" * 100},
                    {"selector": "s2", "record": "v=DKIM1; k=ed25519; p=xyz"}], "findings": []},
 "mta_sts": {"present": True, "findings": []},
 "tls_rpt": {"present": False, "findings": []},
 "bimi": {"present": True, "findings": []},
 "smtp": {"servers": [
     {"host": "mx1.full.test", "tls_version": "TLSv1.3", "cert_valid": True, "error": None},
     {"host": "mx2.full.test", "tls_version": "TLSv1.2", "cert_valid": False, "error": None},
     {"host": "mx3.full.test", "tls_version": None, "cert_valid": False, "error": "connection refused"},
     {"host": "mx4.full.test", "tls_version": None, "cert_valid": False, "error": None}], "findings": []},
 "findings": [
   {"severity": "HIGH", "check": "spf", "message": "SPF is +all"},
   {"severity": "MEDIUM", "check": "mta_sts", "message": "MTA-STS in testing mode"},
   {"severity": "LOW", "check": "dkim", "message": "DKIM key is 1024 bits"},
   {"severity": "INFO", "check": "smtp", "message": "TLS 1.2 only <b>&"},
 ],
 "counts": {"HIGH": 1, "MEDIUM": 1, "LOW": 1, "INFO": 1},
 "all_issues": ["a", "b", "c"], "issue_count": 3,
}
R2 = {
 "domain": "bare.test", "timestamp": "2026-10-27 04:05:06 UTC",
 "mx": {"records": [], "findings": []},
 "spf": {"present": False, "records": [], "lookups": 0, "void_lookups": 0, "findings": []},
 "dmarc": {"present": False, "records": [], "findings": []},
 "dkim": {"found": [], "findings": []},
 "bimi": {"present": False, "findings": []},
 "findings": [], "counts": {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
 "all_issues": [], "issue_count": 0,
}
R3 = dict(R2, domain="med.test", findings=[{"severity": "MEDIUM", "check": "dmarc", "message": "DMARC <missing>"}],
          counts={"HIGH": 0, "MEDIUM": 1, "LOW": 0, "INFO": 0}, all_issues=["x"], issue_count=1)
R4 = dict(R2, domain="low.test", findings=[{"severity": "LOW", "check": "bimi", "message": "BIMI & co"}],
          counts={"HIGH": 0, "MEDIUM": 0, "LOW": 1, "INFO": 0}, all_issues=["y"], issue_count=1)
R5 = dict(R2, domain="info.test", findings=[{"severity": "INFO", "check": "mx", "message": "just info"}],
          counts={"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 1}, all_issues=[], issue_count=0)

HELP = "usage: mail-security-auditor [-h] [--version] [--json] [--html FILE] [--selectors SEL] [--resolver IP[:PORT]] [--smtp] [--fail-on {high,medium,low,never}] domains [domains ...] Email security auditor: SPF (incl. the 10-lookup limit), DKIM, DMARC, MX, MTA- STS, TLS-RPT, BIMI and optional MX STARTTLS checks. positional arguments: domains Domain(s) to audit options: -h, --help show this help message and exit --version show program's version number and exit --json Output JSON instead of text --html FILE Write HTML report to FILE --selectors SEL Comma-separated extra DKIM selectors to try --resolver IP[:PORT] DNS resolver to query instead of 1.1.1.1/8.8.8.8/9.9.9.9 (repeatable, e.g. your internal resolver or 127.0.0.1:5353) --smtp also connect to each MX on port 25 and check STARTTLS + certificate (needs outbound port 25) --fail-on {high,medium,low,never} lowest severity that makes the exit code 1 (default: medium) Exit codes: 0 no finding at/above --fail-on, 1 at least one, 2 usage error."

TEXT = {
    'R1': '\n=== Mail Security Audit: full.test ===\n\nMX records: 2\n  10 mx1.full.test\n  20 mx2.full.test\n\nSPF: present\n  v=spf1 mx -all\n  DNS lookups: 3/10, void lookups: 1/2\n\nDMARC: present\n  v=DMARC1; p=reject\n\nDKIM selectors found: 2\n  selector=s1 (2048-bit RSA): v=DKIM1; k=rsa; p=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA...\n  selector=s2: v=DKIM1; k=ed25519; p=xyz...\n\nMTA-STS: present\n\nTLS-RPT: not configured\n\nBIMI: present\n\nMX STARTTLS:\n  mx1.full.test: STARTTLS TLSv1.3, certificate valid\n  mx2.full.test: STARTTLS TLSv1.2, certificate INVALID\n  mx3.full.test: connection refused\n  mx4.full.test: no STARTTLS\n\nFindings:\n  [HIGH  ] SPF      SPF is +all\n  [MEDIUM] MTA-STS  MTA-STS in testing mode\n  [LOW   ] DKIM     DKIM key is 1024 bits\n  [INFO  ] MX STARTTLS TLS 1.2 only <b>&\n\nTotal issues: 3 (1 high, 1 medium, 1 low; 1 info)\n',
    'R2': '\n=== Mail Security Audit: bare.test ===\n\nMX records: 0\n\nSPF: MISSING\n\nDMARC: MISSING\n\nDKIM selectors found: 0\n\nBIMI: not configured\n\nFindings:\n  none\n\nTotal issues: 0 (0 high, 0 medium, 0 low; 0 info)\n',
    'R3': '\n=== Mail Security Audit: med.test ===\n\nMX records: 0\n\nSPF: MISSING\n\nDMARC: MISSING\n\nDKIM selectors found: 0\n\nBIMI: not configured\n\nFindings:\n  [MEDIUM] DMARC    DMARC <missing>\n\nTotal issues: 1 (0 high, 1 medium, 0 low; 0 info)\n',
    'R4': '\n=== Mail Security Audit: low.test ===\n\nMX records: 0\n\nSPF: MISSING\n\nDMARC: MISSING\n\nDKIM selectors found: 0\n\nBIMI: not configured\n\nFindings:\n  [LOW   ] BIMI     BIMI & co\n\nTotal issues: 1 (0 high, 0 medium, 1 low; 0 info)\n',
    'R5': '\n=== Mail Security Audit: info.test ===\n\nMX records: 0\n\nSPF: MISSING\n\nDMARC: MISSING\n\nDKIM selectors found: 0\n\nBIMI: not configured\n\nFindings:\n  [INFO  ] MX       just info\n\nTotal issues: 0 (0 high, 0 medium, 0 low; 1 info)\n',
}

HTML_ONE = '<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8"><title>Mail Security Audit Report</title>\n<style>\nbody{font-family:-apple-system,Segoe UI,sans-serif;background:#0b0e14;color:#e6e6e6;margin:0;padding:2rem;}\nh1{color:#7dd3fc}\n.domain-card{background:#141922;border:1px solid #232a36;border-radius:10px;padding:1.2rem 1.5rem;margin-bottom:1.2rem;}\n.sev-high{border-left:4px solid #f87171}\n.sev-medium{border-left:4px solid #fbbf24}\n.sev-low{border-left:4px solid #4ade80}\n.meta{color:#9ca3af;font-size:0.85rem}\ntable{border-collapse:collapse;margin:0.5rem 0}\ntd{padding:2px 10px 2px 0;font-size:0.9rem}\n.issues li{font-size:0.88rem;color:#fca5a5;margin:2px 0}\n.issues li.ok{color:#86efac}\n</style></head>\n<body><h1>Mail Security Audit Report</h1>\n        <div class="domain-card sev-low">\n          <h2>bare.test</h2>\n          <p class="meta">Checked 2026-10-27 04:05:06 UTC &middot; 0 issue(s)</p>\n          <table>\n            <tr><td>MX</td><td>0 record(s)</td></tr>\n            <tr><td>SPF</td><td>missing</td></tr>\n            <tr><td>DMARC</td><td>missing</td></tr>\n            <tr><td>DKIM</td><td>0 selector(s) matched</td></tr><tr><td>BIMI</td><td>not configured</td></tr>\n          </table>\n          <ul class="issues"><li class="ok">None found</li></ul>\n        </div>\n<p style="color:#6b7280;font-size:0.8rem;margin-top:2rem">Generated by mail-security-auditor 1.2.1 (Errant Solutions) &mdash; stdlib-only Python, no external dependencies.</p>\n</body></html>'

HTML_ALL = '<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8"><title>Mail Security Audit Report</title>\n<style>\nbody{font-family:-apple-system,Segoe UI,sans-serif;background:#0b0e14;color:#e6e6e6;margin:0;padding:2rem;}\nh1{color:#7dd3fc}\n.domain-card{background:#141922;border:1px solid #232a36;border-radius:10px;padding:1.2rem 1.5rem;margin-bottom:1.2rem;}\n.sev-high{border-left:4px solid #f87171}\n.sev-medium{border-left:4px solid #fbbf24}\n.sev-low{border-left:4px solid #4ade80}\n.meta{color:#9ca3af;font-size:0.85rem}\ntable{border-collapse:collapse;margin:0.5rem 0}\ntd{padding:2px 10px 2px 0;font-size:0.9rem}\n.issues li{font-size:0.88rem;color:#fca5a5;margin:2px 0}\n.issues li.ok{color:#86efac}\n</style></head>\n<body><h1>Mail Security Audit Report</h1>\n        <div class="domain-card sev-high">\n          <h2>full.test</h2>\n          <p class="meta">Checked 2026-10-27 01:02:03 UTC &middot; 3 issue(s)</p>\n          <table>\n            <tr><td>MX</td><td>2 record(s)</td></tr>\n            <tr><td>SPF</td><td>present, 3/10 lookups</td></tr>\n            <tr><td>DMARC</td><td>present (reject)</td></tr>\n            <tr><td>DKIM</td><td>2 selector(s) matched</td></tr><tr><td>MTA-STS</td><td>present</td></tr><tr><td>TLS-RPT</td><td>not configured</td></tr><tr><td>BIMI</td><td>present</td></tr>\n          </table>\n          <ul class="issues"><li><b>HIGH</b> SPF: SPF is +all</li><li><b>MEDIUM</b> MTA-STS: MTA-STS in testing mode</li><li><b>LOW</b> DKIM: DKIM key is 1024 bits</li></ul>\n        </div>\n        <div class="domain-card sev-low">\n          <h2>bare.test</h2>\n          <p class="meta">Checked 2026-10-27 04:05:06 UTC &middot; 0 issue(s)</p>\n          <table>\n            <tr><td>MX</td><td>0 record(s)</td></tr>\n            <tr><td>SPF</td><td>missing</td></tr>\n            <tr><td>DMARC</td><td>missing</td></tr>\n            <tr><td>DKIM</td><td>0 selector(s) matched</td></tr><tr><td>BIMI</td><td>not configured</td></tr>\n          </table>\n          <ul class="issues"><li class="ok">None found</li></ul>\n        </div>\n        <div class="domain-card sev-medium">\n          <h2>med.test</h2>\n          <p class="meta">Checked 2026-10-27 04:05:06 UTC &middot; 1 issue(s)</p>\n          <table>\n            <tr><td>MX</td><td>0 record(s)</td></tr>\n            <tr><td>SPF</td><td>missing</td></tr>\n            <tr><td>DMARC</td><td>missing</td></tr>\n            <tr><td>DKIM</td><td>0 selector(s) matched</td></tr><tr><td>BIMI</td><td>not configured</td></tr>\n          </table>\n          <ul class="issues"><li><b>MEDIUM</b> DMARC: DMARC &lt;missing&gt;</li></ul>\n        </div>\n        <div class="domain-card sev-low">\n          <h2>low.test</h2>\n          <p class="meta">Checked 2026-10-27 04:05:06 UTC &middot; 1 issue(s)</p>\n          <table>\n            <tr><td>MX</td><td>0 record(s)</td></tr>\n            <tr><td>SPF</td><td>missing</td></tr>\n            <tr><td>DMARC</td><td>missing</td></tr>\n            <tr><td>DKIM</td><td>0 selector(s) matched</td></tr><tr><td>BIMI</td><td>not configured</td></tr>\n          </table>\n          <ul class="issues"><li><b>LOW</b> BIMI: BIMI &amp; co</li></ul>\n        </div>\n        <div class="domain-card sev-low">\n          <h2>info.test</h2>\n          <p class="meta">Checked 2026-10-27 04:05:06 UTC &middot; 0 issue(s)</p>\n          <table>\n            <tr><td>MX</td><td>0 record(s)</td></tr>\n            <tr><td>SPF</td><td>missing</td></tr>\n            <tr><td>DMARC</td><td>missing</td></tr>\n            <tr><td>DKIM</td><td>0 selector(s) matched</td></tr><tr><td>BIMI</td><td>not configured</td></tr>\n          </table>\n          <ul class="issues"><li class="ok">None found</li></ul>\n        </div>\n<p style="color:#6b7280;font-size:0.8rem;margin-top:2rem">Generated by mail-security-auditor 1.2.1 (Errant Solutions) &mdash; stdlib-only Python, no external dependencies.</p>\n</body></html>'


def printed(result):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        m.print_report(result)
    return buf.getvalue()


class TestPrintReport(unittest.TestCase):
    def test_every_section_and_severity_exactly(self):
        self.assertEqual(printed(R1), TEXT["R1"])

    def test_missing_records_and_no_findings(self):
        self.assertEqual(printed(R2), TEXT["R2"])

    def test_medium_low_and_info_only_results(self):
        self.assertEqual(printed(R3), TEXT["R3"])
        self.assertEqual(printed(R4), TEXT["R4"])
        self.assertEqual(printed(R5), TEXT["R5"])


class TestRenderHtml(unittest.TestCase):
    def test_one_clean_domain_exactly(self):
        self.assertEqual(m.render_html([R2]).replace(m.__version__, "VERSION"),
                         HTML_ONE.replace(m.__version__, "VERSION"))

    def test_five_domains_severity_classes_escaping_and_extras(self):
        page = m.render_html([R1, R2, R3, R4, R5])
        self.assertEqual(page.replace(m.__version__, "VERSION"), HTML_ALL.replace(m.__version__, "VERSION"))
        # the card colour follows the worst finding; INFO never counts as an issue line
        for cls, dom in (("high", "full.test"), ("medium", "med.test"), ("low", "low.test"),
                         ("low", "info.test"), ("low", "bare.test")):
            self.assertIn('<div class="domain-card sev-%s">\n          <h2>%s</h2>' % (cls, dom), page)
        self.assertEqual(page.count("None found"), 2)  # bare.test and info.test
        self.assertIn("&lt;missing&gt;", page)
        self.assertIn("BIMI &amp; co", page)

    def test_worst_ranks_severities(self):
        self.assertEqual([m.worst(r) for r in (R1, R3, R4, R5, R2)], [0, 1, 2, 3, 4])


class TestMain(unittest.TestCase):
    """main(): argument handling, output modes and exit codes, with the audit itself stubbed out."""

    def run_main(self, argv, result=None, results=None):
        calls = []

        def fake_audit(domain, selectors=None, smtp=False):
            calls.append((domain, list(selectors), smtp))
            return dict(results[domain] if results else result, domain=domain)

        out = io.StringIO()
        saved = (list(m.DNS_SERVERS), m.HTTPS_PORT, m.SMTP_PORT)
        try:
            with mock.patch.object(m, "audit_domain", fake_audit), contextlib.redirect_stdout(out):
                rc = m.main(argv)
            state = (list(m.DNS_SERVERS), m.HTTPS_PORT, m.SMTP_PORT)
        finally:
            m.DNS_SERVERS[:] = saved[0]
            m.HTTPS_PORT, m.SMTP_PORT = saved[1], saved[2]
        return rc, out.getvalue(), calls, state

    def test_exit_code_follows_worst_finding_and_fail_on(self):
        worst_result = {"high": R1, "medium": R3, "low": R4, "info": R5, "none": R2}
        want = {  # fail-on level -> exit code per worst severity
            "high": {"high": 1, "medium": 0, "low": 0, "info": 0, "none": 0},
            "medium": {"high": 1, "medium": 1, "low": 0, "info": 0, "none": 0},
            "low": {"high": 1, "medium": 1, "low": 1, "info": 0, "none": 0},
            "never": {"high": 0, "medium": 0, "low": 0, "info": 0, "none": 0},
        }
        for level, row in want.items():
            for sev, code in row.items():
                rc = self.run_main(["--fail-on", level, "x.test"], worst_result[sev])[0]
                self.assertEqual(rc, code, (level, sev))
        # default is medium; any one failing domain in a batch fails the run
        self.assertEqual(self.run_main(["x.test"], R3)[0], 1)
        self.assertEqual(self.run_main(["x.test"], R4)[0], 0)
        both = {"a.test": R2, "b.test": R3}
        self.assertEqual(self.run_main(["a.test", "b.test"], results=both)[0], 1)
        self.assertEqual(self.run_main(["a.test"], results=both)[0], 0)

    def test_domains_are_stripped_and_trailing_dots_removed_and_each_reported(self):
        rc, out, calls, _ = self.run_main([" a.test. ", "b.test"], R2)
        self.assertEqual([c[0] for c in calls], ["a.test", "b.test"])
        self.assertEqual(out.count("=== Mail Security Audit:"), 2)
        self.assertIn("=== Mail Security Audit: a.test ===", out)

    def test_selectors_extend_the_common_list_without_duplicates_or_blanks(self):
        _, _, calls, _ = self.run_main(["--selectors", "zz1, ,zz2,selector1,zz1", "a.test"], R2)
        sel = calls[0][1]
        self.assertEqual(sel[:len(m.COMMON_DKIM_SELECTORS)], m.COMMON_DKIM_SELECTORS)
        self.assertEqual(sel[len(m.COMMON_DKIM_SELECTORS):], ["zz1", "zz2"])
        self.assertEqual(self.run_main(["a.test"], R2)[2][0][1], m.COMMON_DKIM_SELECTORS)

    def test_smtp_flag_resolvers_and_ports(self):
        _, _, calls, state = self.run_main(["a.test"], R2)
        self.assertEqual(calls[0][2], False)
        self.assertEqual((state[1], state[2]), (443, 25))
        _, _, calls, state = self.run_main(["--smtp", "--resolver", "10.0.0.1, 10.0.0.2:5353",
                                            "--resolver", "", "--resolver", "10.0.0.3",
                                            "--https-port", "8443", "--smtp-port", "2525", "a.test"], R2)
        self.assertEqual(calls[0][2], True)
        self.assertEqual(state[0], ["10.0.0.1", "10.0.0.2:5353", "10.0.0.3"])
        self.assertEqual((state[1], state[2]), (8443, 2525))

    def test_json_output_is_the_results_list_indented(self):
        rc, out, _, _ = self.run_main(["--json", "a.test", "b.test"], R3)
        self.assertEqual(out, json.dumps([dict(R3, domain="a.test"), dict(R3, domain="b.test")], indent=2) + "\n")
        self.assertEqual(rc, 1)

    def test_html_report_is_written_and_announced(self):
        path = os.path.join(tempfile.mkdtemp(), "r.html")
        rc, out, _, _ = self.run_main(["--html", path, "a.test"], R2)
        with open(path, encoding="utf-8") as f:
            self.assertEqual(f.read(), m.render_html([dict(R2, domain="a.test")]))
        self.assertTrue(out.endswith("\nHTML report written to %s\n" % path), out)
        self.assertIn("=== Mail Security Audit: a.test ===", out)
        os.remove(path)

    def test_help_text(self):
        out = io.StringIO()
        with mock.patch.dict(os.environ, {"COLUMNS": "80"}), contextlib.redirect_stdout(out), \
                self.assertRaises(SystemExit) as cm:
            m.main(["--help"])
        self.assertEqual(cm.exception.code, 0)
        body = " ".join(out.getvalue().replace("optional arguments:", "options:").split())
        self.assertEqual(body, HELP)

    def test_version_and_usage_errors(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit) as cm:
            m.main(["--version"])
        self.assertEqual((cm.exception.code, out.getvalue()), (0, "mail-security-auditor %s\n" % m.__version__))
        for bad in ([], ["--fail-on", "bogus", "a.test"], ["--https-port", "x", "a.test"]):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as cm:
                m.main(bad)
            self.assertEqual(cm.exception.code, 2, bad)


if __name__ == "__main__":
    unittest.main()
