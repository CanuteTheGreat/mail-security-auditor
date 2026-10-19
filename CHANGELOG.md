# Changelog

All notable changes. Versions are git tags; each tag has a Forgejo release with checksums.

## 1.2.1 - 2026-10-19

- HTML report: a clean domain's "None found" line is shown in green, no longer in red like a finding.

## 1.2.0 - 2026-10-16

- **SPF 10-DNS-lookup limit** (RFC 7208 4.6.4): every include/a/mx/ptr/exists/redirect is counted across the
  whole include tree; over 10 is HIGH (receivers return permerror), 9-10 is LOW. Also void lookups (> 2),
  includes/redirects without an SPF record, include loops, mx terms with > 10 hosts, ptr and macros. The
  JSON carries the lookup count and the include tree.
- **MTA-STS**: TXT record, the HTTPS policy (version, mode, max_age, certificate verified) and MX coverage.
- **TLS-RPT** and **BIMI** (enforcing DMARC, https SVG logo that loads, VMC note).
- DMARC: `sp=`, `adkim`/`aspf` values, and rua/ruf addresses in other domains must be authorized via
  `<domain>._report._dmarc.<other>` (RFC 7489 7.1).
- DKIM RSA key size (< 1024 HIGH, < 2048 LOW) and revoked keys.
- `--smtp`: STARTTLS, certificate validity and TLS version on each MX.
- **Exit code now gates on severity** (`--fail-on`, default `medium`) instead of "3 or more issues":
  `p=none` with no rua used to exit 0. Every finding has a severity in the JSON and text report.
- Installable as a package: `pipx install git+https://git.canutethegreat.com/CanuteTheGreat/mail-security-auditor.git`
  puts a `mail-security-auditor` command on PATH (pyproject.toml, MIT license metadata).
- `--version` flag.
- Exit codes follow the shared convention: 0 = clean, 1 = findings at/above the gate, 2 = error or bad usage.
- Every tag now publishes a Forgejo release with this changelog, the wheel, the sdist and SHA256SUMS.
- CI installs the package with pip in a clean venv and checks `--version`/`--help` on every push.

## 1.1.0 - 2026-10-16

- Fix SPF/MX parsing bugs, add --resolver, skip dead resolvers, add CI tests

## 1.0.0 - 2026-09-30

- First public release.
