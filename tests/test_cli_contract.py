"""Shared CLI contract (docs/CLI-CONTRACT.md): exit codes, --json schema, --quiet, stderr for errors.

Runs the tool as a subprocess against a tiny in-process stub DNS server on 127.0.0.1 (no real DNS,
no dnsmasq needed); .test names never resolve through the OS (tests/nodns).
"""
import contextlib
import io
import json
import os
import socket
import struct
import sys
import tempfile
import threading
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, ROOT)
import contract_support as cs  # noqa: E402
import mail_audit as tool  # noqa: E402

TOOL = os.path.join(ROOT, "mail_audit.py")
SCHEMA = cs.load_schema(ROOT, "mail-security-auditor")
NODNS = os.path.join(HERE, "nodns")

TXT, MX = 16, 15
ZONE = {
    ("clean.test", MX): [b"\x00\x00\x00"],  # null MX: receives no mail, so no MTA-STS/TLS-RPT/SMTP checks
    ("clean.test", TXT): ["v=spf1 -all"],
    ("_dmarc.clean.test", TXT): ["v=DMARC1; p=reject; rua=mailto:d@clean.test"],
    ("bad.test", MX): [b"\x00\x00\x00"],
    ("bad.test", TXT): ["v=spf1 +all"],
}


def _name(labels):
    return b"".join(bytes([len(x)]) + x for x in labels) + b"\x00"


def _answer(packet):
    tid = packet[:2]
    labels, off = [], 12
    while packet[off]:
        labels.append(packet[off + 1:off + 1 + packet[off]])
        off += 1 + packet[off]
    qtype = struct.unpack(">H", packet[off + 1:off + 3])[0]
    question = packet[12:off + 5]
    qname = ".".join(x.decode() for x in labels).lower()
    rdatas = []
    for item in ZONE.get((qname, qtype), []):
        if qtype == TXT:
            item = bytes([len(item)]) + item.encode()
        rdatas.append(item)
    body = b"".join(b"\xc0\x0c" + struct.pack(">HHIH", qtype, 1, 60, len(r)) + r for r in rdatas)
    return tid + struct.pack(">HHHHH", 0x8180, 1, len(rdatas), 0, 0) + question + body


class StubDns(object):
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.addr = "127.0.0.1:%d" % self.sock.getsockname()[1]
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self):
        while True:
            try:
                packet, peer = self.sock.recvfrom(4096)
            except OSError:
                return
            self.sock.sendto(_answer(packet), peer)

    def close(self):
        self.sock.close()


DNS = None


def setUpModule():
    global DNS
    DNS = StubDns()


def tearDownModule():
    DNS.close()


def cli(*args, **kw):
    env = {"PYTHONPATH": NODNS}
    return cs.run_cli(TOOL, args, env=env, **kw)


def cli_dns(*args):
    return cli("--resolver", DNS.addr, *args)


# a closed UDP port on localhost: the query fails at once (connection refused), nothing leaves the host
DEAD_RESOLVER = "127.0.0.1:9"


class TestExitCodes(unittest.TestCase):
    def test_clean_is_0(self):
        self.assertEqual(cli_dns("clean.test")[0], 0)

    def test_findings_is_1(self):
        self.assertEqual(cli_dns("bad.test")[0], 1)

    def test_fail_on_never_is_0_even_with_findings(self):
        self.assertEqual(cli_dns("--fail-on", "never", "bad.test")[0], 0)

    def test_bad_args_is_2_with_message_on_stderr(self):
        for args in ((), ("--no-such-flag", "clean.test"), ("--fail-on", "bogus", "clean.test")):
            rc, out, err = cli(*args)
            self.assertEqual(rc, 2, args)
            self.assertEqual(out, "")
            self.assertIn("usage:", err)

    def test_unreachable_resolver_is_3_with_stderr_message_and_empty_stdout(self):
        rc, out, err = cli("--resolver", DEAD_RESOLVER, "clean.test")
        self.assertEqual(rc, 3)
        self.assertEqual(out, "")
        self.assertIn("no DNS resolver reachable", err)
        self.assertIn(DEAD_RESOLVER, err)

    def test_unreachable_resolver_with_json_keeps_stdout_empty(self):
        rc, out, err = cli("--json", "--resolver", DEAD_RESOLVER, "clean.test")
        self.assertEqual((rc, out), (3, ""))

    def test_one_dead_resolver_among_working_ones_is_not_an_error(self):
        self.assertEqual(cli("--resolver", DEAD_RESOLVER, "--resolver", DNS.addr, "clean.test")[0], 0)

    def test_unwritable_html_path_is_3(self):
        bad = os.path.join(tempfile.gettempdir(), "no-such-dir-mail-audit", "r.html")
        rc, out, err = cli_dns("--html", bad, "clean.test")
        self.assertEqual((rc, out), (3, ""))
        self.assertIn("mail-security-auditor: error:", err)

    def test_unexpected_error_is_3_on_stderr_not_a_traceback_exit_1(self):
        buf = io.StringIO()
        with mock.patch.object(tool, "_main", side_effect=RuntimeError("boom")), contextlib.redirect_stderr(buf):
            self.assertEqual(tool.main(["clean.test"]), 3)
        self.assertIn("mail-security-auditor: error: RuntimeError: boom", buf.getvalue())

    def test_usage_error_in_main_is_still_systemexit_2(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as cm:
            tool.main(["--no-such-flag"])
        self.assertEqual(cm.exception.code, 2)


class TestJson(unittest.TestCase):
    def check(self, args, code):
        rc, out, err = cli_dns("--json", *args)
        self.assertEqual(rc, code, err)
        doc = json.loads(out)  # exactly one JSON document, nothing else on stdout
        self.assertEqual(cs.validate(doc, SCHEMA), [])
        self.assertEqual(doc["exit_code"], rc)
        self.assertEqual(doc["schema_version"], 1)
        self.assertEqual(doc["tool"], "mail-security-auditor")
        self.assertEqual(doc["version"], tool.__version__)
        return doc

    def test_clean(self):
        doc = self.check(("clean.test",), 0)
        self.assertEqual([r["domain"] for r in doc["results"]], ["clean.test"])
        self.assertTrue(doc["results"][0]["spf"]["present"])

    def test_findings(self):
        doc = self.check(("bad.test",), 1)
        self.assertTrue(any(f["severity"] == "HIGH" for f in doc["results"][0]["findings"]))

    def test_results_is_one_entry_per_domain_in_order(self):
        doc = self.check(("bad.test", "clean.test"), 1)
        self.assertEqual([r["domain"] for r in doc["results"]], ["bad.test", "clean.test"])

    def test_exit_code_key_follows_fail_on(self):
        self.assertEqual(self.check(("--fail-on", "never", "bad.test"), 0)["exit_code"], 0)

    def test_html_with_json_keeps_stdout_a_single_document(self):
        path = os.path.join(tempfile.mkdtemp(), "r.html")
        rc, out, err = cli_dns("--json", "--html", path, "clean.test")
        json.loads(out)
        self.assertIn("HTML report written to %s" % path, err)
        self.assertTrue(os.path.isfile(path))

    def test_usage_error_leaves_stdout_empty(self):
        rc, out, err = cli("--json")
        self.assertEqual((rc, out), (2, ""))
        self.assertIn("usage:", err)

    def test_schema_rejects_a_document_without_the_contract_keys(self):
        self.assertNotEqual(cs.validate({"results": []}, SCHEMA), [])
        self.assertNotEqual(cs.validate({"schema_version": 1, "tool": "x", "version": "1", "exit_code": 9,
                                         "results": []}, SCHEMA), [])
        self.assertNotEqual(cs.validate([], SCHEMA), [])  # the pre-2.0 top-level list


class TestQuiet(unittest.TestCase):
    def test_quiet_prints_nothing_but_keeps_exit_code(self):
        for domain, code in (("clean.test", 0), ("bad.test", 1)):
            for extra in ((), ("--json",)):
                for flag in ("--quiet", "-q"):
                    rc, out, err = cli_dns(flag, *(extra + (domain,)))
                    self.assertEqual((rc, out), (code, ""), (flag, extra, domain))

    def test_quiet_still_reports_errors_on_stderr(self):
        rc, out, err = cli("-q", "--resolver", DEAD_RESOLVER, "clean.test")
        self.assertEqual((rc, out), (3, ""))
        self.assertIn("no DNS resolver reachable", err)

    def test_quiet_still_writes_the_html_file_without_announcing_it(self):
        path = os.path.join(tempfile.mkdtemp(), "r.html")
        rc, out, err = cli_dns("--quiet", "--html", path, "bad.test")
        self.assertEqual((rc, out, err), (1, "", ""))
        with open(path, encoding="utf-8") as f:
            self.assertIn("bad.test", f.read())

    def test_without_quiet_the_report_is_printed(self):
        rc, out, err = cli_dns("clean.test")
        self.assertIn("=== Mail Security Audit: clean.test ===", out)
        self.assertEqual(err, "")

    def test_text_mode_announces_the_html_file_on_stdout(self):
        path = os.path.join(tempfile.mkdtemp(), "r.html")
        rc, out, err = cli_dns("--html", path, "clean.test")
        self.assertTrue(out.endswith("\nHTML report written to %s\n" % path), out)


if __name__ == "__main__":
    unittest.main()
