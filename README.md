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

## Install

```sh
pipx install git+https://git.canutethegreat.com/CanuteTheGreat/mail-security-auditor.git        # latest release branch; puts `mail-security-auditor` on PATH
pipx install git+https://git.canutethegreat.com/CanuteTheGreat/mail-security-auditor.git@v1.2.0  # a pinned release
brew install canutethegreat/errant-tools/mail-security-auditor   # after: brew tap canutethegreat/errant-tools https://git.canutethegreat.com/CanuteTheGreat/homebrew-errant-tools
scoop install errant-tools/mail-security-auditor                 # after: scoop bucket add errant-tools https://git.canutethegreat.com/CanuteTheGreat/scoop-errant-tools
```

Or download the single file (stdlib-only Python 3.7+) and run it directly:
`curl -fsSLO https://errant.solutions/downloads/mail_audit.py && python3 mail_audit.py --help`.
Every [release](https://git.canutethegreat.com/CanuteTheGreat/mail-security-auditor/releases) has a changelog, the wheel, the sdist and a `SHA256SUMS` file.
Not on PyPI yet, so plain `pipx install mail-security-auditor` doesn't work until it's published there.

## Usage

```bash
mail-security-auditor example.com                       # text report
mail-security-auditor example.com example.org           # several domains
mail-security-auditor --json example.com                # JSON (every finding has a severity)
mail-security-auditor --html report.html example.com    # HTML report for non-technical readers
mail-security-auditor --selectors myselector example.com
mail-security-auditor --resolver 10.0.0.53 example.com  # your own resolver(s), IP[:PORT], repeatable
mail-security-auditor --smtp example.com                # also test STARTTLS on every MX (needs outbound port 25)
mail-security-auditor --fail-on high example.com        # CI gate on HIGH only
```

Exit codes (same convention as every Errant Solutions tool):

| Code | Meaning |
|---|---|
| 0 | no finding at or above `--fail-on` (default `medium`; `high`, `low`, `never` also accepted) |
| 1 | at least one finding at or above `--fail-on` |
| 2 | usage error |

## What it checks

Every finding is HIGH, MEDIUM, LOW or INFO.

- **SPF** — present, exactly one record (RFC 7208), the `all` qualifier (`+all`/bare
  `all` HIGH, `?all` MEDIUM, `~all` LOW), real sender mechanisms (`v=spf1 -all` is
  accepted as "sends no mail"), and the limits receivers enforce, which are the most
  common cause of SPF permerror in practice:
  - **at most 10 DNS lookups** — every `include`/`a`/`mx`/`ptr`/`exists` term and
    `redirect=`, counted across the whole include tree (HIGH above 10, LOW at 9-10);
    the JSON has the count and the full tree
  - at most 2 void lookups (names that don't exist or have no records)
  - includes/redirects whose target has no SPF record, include loops, `mx` terms with
    more than 10 hosts, `ptr` usage, macros (reported, not expanded)
- **DMARC** — present, exactly one record, `p=` (`none` MEDIUM, `quarantine` LOW),
  `sp=none` under an enforcing `p=`, valid `adkim`/`aspf`, `rua` configured, `pct`, and
  **report addresses in another domain must be authorized** by a
  `<domain>._report._dmarc.<other-domain>` TXT record (RFC 7489 7.1), otherwise
  receivers silently drop the reports
- **DKIM** — ~19 common selectors (+ `--selectors`), RSA key size (< 1024 bits HIGH,
  < 2048 LOW), revoked keys. A miss only means the common selectors weren't found.
- **MX** — present (no MX = can't receive mail, may be intentional), null MX
- **MTA-STS** — `_mta-sts` TXT (one record, with `id=`), the policy fetched from
  `https://mta-sts.<domain>/.well-known/mta-sts.txt` with certificate verification
  (version, `mode` enforce/testing/none, `max_age`) and that every MX host matches an
  `mx:` line (an uncovered MX under `enforce` is HIGH: senders refuse to deliver to it)
- **TLS-RPT** — `_smtp._tls` TXT with a valid `rua=`
- **BIMI** — `default._bimi` record, an enforcing DMARC policy, an https SVG logo that
  actually loads, and a note when there's no VMC/CMC (`a=`)
- **MX STARTTLS** (`--smtp`) — each MX (up to 5) offers STARTTLS, its certificate
  verifies for the MX name, and the negotiated TLS version

HTTPS and SMTP connections go to the addresses the same resolvers return.

## Requirements

Python 3.7+, stdlib only. Outbound UDP/53 (TCP/53 for
oversized answers) to a public resolver (falls back through 1.1.1.1 → 8.8.8.8
→ 9.9.9.9; a resolver that doesn't answer is skipped for the rest of the run),
or to whatever you pass with `--resolver`.

## Tests

`tests/` runs every check against a real DNS server (dnsmasq) serving good
and broken records, plus one live query through the default public
resolvers, an HTTPS server for MTA-STS/BIMI and an SMTP listener with STARTTLS,\non Python 3.7 and current Python in Forgejo CI (then a pip install + `--version` check):
`sh ci/run-tests.sh 3.13` reproduces it locally (needs docker).

## License

MIT — see `LICENSE`. Free to use. If it's useful to you and you want to
support future tools like it, pay-what-you-want:
https://buy.stripe.com/8x2dR9amdarB1j16xG1VK03

Built by [Errant Solutions](https://errant.solutions).
