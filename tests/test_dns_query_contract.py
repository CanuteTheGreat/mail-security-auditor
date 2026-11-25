"""dns_query resolver-failover and exit-3 paths, plus main()'s error line and --html encoding.

Pins the behaviour added by the shared CLI contract (docs/CLI-CONTRACT.md): the unreachable-resolver
detection, which resolver answers win, UDP->TCP fallback and the stderr error format. All network
calls (build_query / _query_udp / _query_tcp / parse_response) are stubbed: no sockets, no DNS.
"""
import contextlib
import io
import os
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import mail_audit as tool  # noqa: E402


class DnsQueryBase(unittest.TestCase):
    def setUp(self):
        self._saved = (set(tool._DEAD_SERVERS), dict(tool._DNS_STATS))
        tool._DEAD_SERVERS.clear()
        tool._DNS_STATS.update(ok=0, err=0)
        self.addCleanup(self._restore)

    def _restore(self):
        tool._DEAD_SERVERS.clear()
        tool._DEAD_SERVERS.update(self._saved[0])
        tool._DNS_STATS.clear()
        tool._DNS_STATS.update(self._saved[1])

    def run_query(self, udp, parse, tcp=None, servers=("a:1", "b:2")):
        """udp: {server: bytes|None|Exception}; parse: {bytes: (tid, rcode, truncated, results)}."""
        calls = {"udp": [], "tcp": [], "parse": [], "build": []}

        def build(qname, qtype, edns=False):
            calls["build"].append((qname, qtype, edns))
            return 7, b"PKT"

        def q_udp(server, packet):
            calls["udp"].append(server)
            r = udp[server]
            if isinstance(r, Exception):
                raise r
            return r

        def q_tcp(server, packet):
            calls["tcp"].append(server)
            r = (tcp or {}).get(server)
            if isinstance(r, Exception):
                raise r
            return r

        def parse_response(data, qtype):
            calls["parse"].append((data, qtype))
            return parse[data]

        with mock.patch.object(tool, "build_query", build), mock.patch.object(tool, "_query_udp", q_udp), \
                mock.patch.object(tool, "_query_tcp", q_tcp), mock.patch.object(tool, "parse_response", parse_response):
            return tool.dns_query("x.test", 16, servers=list(servers)), calls


class TestDnsQueryFailover(DnsQueryBase):
    def test_all_resolvers_dead_raises_with_the_exact_message(self):
        tool._DEAD_SERVERS.update({"a:1", "b:2"})
        with self.assertRaises(tool.ResolverUnreachable) as cm:
            self.run_query({}, {})
        self.assertEqual(str(cm.exception), "no DNS resolver reachable (a:1, b:2)")

    def test_dead_resolvers_after_an_answer_are_retried_not_fatal(self):
        tool._DEAD_SERVERS.update({"a:1", "b:2"})
        tool._DNS_STATS["ok"] = 1
        res, calls = self.run_query({"a:1": b"A"}, {b"A": (7, 0, False, ["ok"])})
        self.assertEqual(res, ["ok"])
        self.assertEqual(calls["udp"], ["a:1"])

    def test_queries_are_built_with_edns(self):
        _, calls = self.run_query({"a:1": b"A"}, {b"A": (7, 0, False, ["ok"])})
        self.assertEqual(calls["build"], [("x.test", 16, True)])

    def test_no_reply_moves_on_to_the_next_resolver(self):
        res, calls = self.run_query({"a:1": None, "b:2": b"B"}, {b"B": (7, 0, False, ["from-b"])})
        self.assertEqual(res, ["from-b"])
        self.assertEqual(calls["udp"], ["a:1", "b:2"])

    def test_wrong_transaction_id_moves_on_to_the_next_resolver(self):
        res, calls = self.run_query({"a:1": b"A", "b:2": b"B"},
                                    {b"A": (99, 0, False, ["spoofed"]), b"B": (7, 0, False, ["from-b"])})
        self.assertEqual(res, ["from-b"])
        self.assertEqual(calls["udp"], ["a:1", "b:2"])

    def test_wrong_transaction_id_is_not_counted_as_an_answer(self):
        self.run_query({"a:1": b"A", "b:2": None}, {b"A": (99, 0, False, [])})
        self.assertEqual(tool._DNS_STATS["ok"], 0)

    def test_answers_are_counted_one_each(self):
        tool._DNS_STATS["ok"] = 5
        self.run_query({"a:1": b"A"}, {b"A": (7, 0, False, ["ok"])})
        self.assertEqual(tool._DNS_STATS["ok"], 6)

    def test_network_error_is_counted_and_marks_the_resolver_dead(self):
        res, _ = self.run_query({"a:1": OSError("refused"), "b:2": b"B"}, {b"B": (7, 0, False, ["from-b"])})
        self.assertEqual(res, ["from-b"])
        self.assertEqual(tool._DNS_STATS, {"ok": 1, "err": 1})
        self.assertEqual(tool._DEAD_SERVERS, {"a:1"})

    def test_noerror_without_records_is_final(self):
        res, calls = self.run_query({"a:1": b"A", "b:2": b"B"},
                                    {b"A": (7, 0, False, []), b"B": (7, 0, False, ["late"])})
        self.assertEqual(res, [])
        self.assertEqual(calls["udp"], ["a:1"])

    def test_nxdomain_is_final(self):
        res, calls = self.run_query({"a:1": b"A", "b:2": b"B"},
                                    {b"A": (7, 3, False, []), b"B": (7, 0, False, ["late"])})
        self.assertEqual(res, [])
        self.assertEqual(calls["udp"], ["a:1"])

    def test_servfail_without_records_asks_the_next_resolver(self):
        res, calls = self.run_query({"a:1": b"A", "b:2": b"B"},
                                    {b"A": (7, 2, False, []), b"B": (7, 0, False, ["from-b"])})
        self.assertEqual(res, ["from-b"])
        self.assertEqual(calls["udp"], ["a:1", "b:2"])

    def test_servfail_with_records_is_returned(self):
        res, calls = self.run_query({"a:1": b"A", "b:2": b"B"},
                                    {b"A": (7, 2, False, ["kept"]), b"B": (7, 0, False, ["other"])})
        self.assertEqual(res, ["kept"])
        self.assertEqual(calls["udp"], ["a:1"])


class TestDnsQueryTcpFallback(DnsQueryBase):
    def test_truncated_reply_is_retried_over_tcp_and_parsed_for_the_same_type(self):
        res, calls = self.run_query({"a:1": b"A"}, {b"A": (7, 0, True, ["clipped"]), b"T": (7, 0, False, ["full"])},
                                    tcp={"a:1": b"T"})
        self.assertEqual(res, ["full"])
        self.assertEqual(calls["tcp"], ["a:1"])
        self.assertEqual(calls["parse"], [(b"A", 16), (b"T", 16)])

    def test_tcp_failure_keeps_the_udp_answer(self):
        res, _ = self.run_query({"a:1": b"A"}, {b"A": (7, 0, True, ["clipped"])}, tcp={"a:1": OSError("reset")})
        self.assertEqual(res, ["clipped"])

    def test_tcp_reply_with_wrong_transaction_id_is_ignored(self):
        res, _ = self.run_query({"a:1": b"A"}, {b"A": (7, 0, True, ["clipped"]), b"T": (99, 0, False, ["spoofed"])},
                                tcp={"a:1": b"T"})
        self.assertEqual(res, ["clipped"])


class TestMainErrorLine(unittest.TestCase):
    def test_unexpected_error_line_is_exact(self):
        buf = io.StringIO()
        with mock.patch.object(tool, "_main", side_effect=RuntimeError("boom")), contextlib.redirect_stderr(buf):
            self.assertEqual(tool.main(["clean.test"]), 3)
        self.assertEqual(buf.getvalue(), "mail-security-auditor: error: RuntimeError: boom\n")

    def test_html_report_is_written_as_utf8(self):
        path = os.path.join(tempfile.mkdtemp(), "r.html")
        self.addCleanup(lambda: (os.path.exists(path) and os.remove(path), os.rmdir(os.path.dirname(path))))
        m = mock.mock_open()
        with mock.patch.object(tool, "audit_domain", return_value={"domain": "x.test"}), \
                mock.patch.object(tool, "worst", return_value=3), \
                mock.patch.object(tool, "render_html", return_value="<html>\u00e9</html>"), \
                mock.patch("builtins.open", m):
            self.assertEqual(tool.main(["--quiet", "--html", path, "x.test"]), 0)
        m.assert_called_once_with(path, "w", encoding="utf-8")
        m().write.assert_called_once_with("<html>\u00e9</html>")


if __name__ == "__main__":
    unittest.main()
