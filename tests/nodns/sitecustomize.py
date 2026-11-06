"""Test-only: names under the reserved .test TLD (RFC 6761) never resolve through the OS.

The tool falls back to the OS resolver (getaddrinfo) when our dnsmasq has no A record. On a
host whose resolv.conf has a search domain with a wildcard record (the colo runners:
`search redweek.internal redweek.com`), `mta-sts.stsnoid.test` became
`mta-sts.stsnoid.test.redweek.com`, resolved to a real address, and the HTTPS fetch timed out
instead of "does not resolve" -- every nightly python-matrix job failed for that reason.
Loaded by the test subprocesses through PYTHONPATH (tests/test_mail_audit.py run()).
"""
import socket

_real = socket.getaddrinfo


def _getaddrinfo(host, *args, **kwargs):
    if isinstance(host, str) and host.rstrip(".").lower().endswith(".test"):
        raise socket.gaierror(socket.EAI_NONAME, "Name or service not known (.test is reserved)")
    return _real(host, *args, **kwargs)


socket.getaddrinfo = _getaddrinfo
