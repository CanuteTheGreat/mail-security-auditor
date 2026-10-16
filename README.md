# mail-security-auditor

A single-file, zero-dependency Python 3 tool that audits a domain's email
authentication hygiene: **SPF**, **DKIM**, **DMARC**, and **MX** records.

No `dnspython`, no shelling out to `dig`/`host` — it implements a minimal raw
UDP DNS client (RFC 1035) in stdlib Python, so it runs anywhere Python 3 runs,
including locked-down CI runners and minimal containers.

## Why this matters

Misconfigured or missing SPF/DKIM/DMARC is one of the most common — and most
overlooked — ways attackers spoof your domain for phishing. Most domains
either have no DMARC record at all, or ship one with `p=none` that provides
zero enforcement. This tool surfaces exactly what's wrong in under a second,
per domain, with no signup, no SaaS, no data leaving your machine (queries go
straight to public resolvers 1.1.1.1 / 8.8.8.8 / 9.9.9.9).

## Usage

```bash
# Text report
python3 mail_audit.py example.com

# Multiple domains at once
python3 mail_audit.py example.com example.org example.net

# JSON output (for piping into other tooling / CI gating)
python3 mail_audit.py --json example.com

# HTML report (for sharing with non-technical stakeholders)
python3 mail_audit.py --html report.html example.com

# Try extra DKIM selectors beyond the built-in common list
python3 mail_audit.py --selectors myselector,anotherone example.com

# Use your own resolver(s) instead of the public ones (repeatable, IP[:PORT])
python3 mail_audit.py --resolver 10.0.0.53 example.com
```

Exit code is `1` if any audited domain has 3+ issues (useful for CI gating),
`0` otherwise.

## What it checks

- **MX** — records present and resolvable (no MX = can't receive mail, may be intentional)
- **SPF** — present, single record (RFC 7208 only allows one), not `+all`
  or a bare `all` (both wide open), has a real `-all`/`~all` closing mechanism
  (or a `redirect=`), has at least one real authorization mechanism
  (`include:`/`a`/`mx`/`ip4:`/`ip6:`/`exists:`) — `v=spf1 -all` ("this domain
  sends no mail") is accepted as-is
- **DMARC** — present, exactly one record, policy strength (`none` vs
  `quarantine` vs `reject`), `rua` aggregate-report address configured, `pct=100`
- **DKIM** — checks ~19 common selectors (Google Workspace, Microsoft 365,
  Mailgun, SendGrid, Mandrill, ProtonMail, generic `default`/`selector1`/`s1`,
  etc.) — a miss here only means the common selectors weren't found, not that
  DKIM is absent; check your provider's docs for the real selector name if so

## Requirements

Python 3.7+, stdlib only. No pip install needed. Outbound UDP/53 (TCP/53 for
oversized answers) to a public resolver (falls back through 1.1.1.1 → 8.8.8.8
→ 9.9.9.9; a resolver that doesn't answer is skipped for the rest of the run),
or to whatever you pass with `--resolver`.

## Tests

`tests/` runs every check against a real DNS server (dnsmasq) serving good
and broken records, plus one live query through the default public
resolvers, on Python 3.7 and current Python in Forgejo CI:
`sh ci/run-tests.sh 3.13` reproduces it locally (needs docker).

## License

MIT — see `LICENSE`. Free to use. If it's useful to you and you want to
support future tools like it, pay-what-you-want:
https://buy.stripe.com/8x2dR9amdarB1j16xG1VK03

Built by [Errant Solutions](https://errant.solutions).
