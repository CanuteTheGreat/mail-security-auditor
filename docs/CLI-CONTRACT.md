# CLI contract (Errant Solutions free tools, contract version 1)

All Errant Solutions command-line tools follow the same contract, so they can be dropped
into CI pipelines and cron jobs the same way.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Clean: nothing at or above the failure threshold (or, for a verifier, the check passed). |
| 1 | Findings: at least one finding at or above the failure threshold (or the check failed). |
| 2 | Usage or input error: bad or missing arguments, a file that does not exist or cannot be read or parsed. |
| 3 | Runtime or network error: a target could not be reached, a DNS/API call failed, a required system tool is missing. |

A tool that documented a different code for one of these cases before the contract existed keeps
that code, so scripts do not break. Such differences are listed in the tool's own README under
"Exit codes" (marked "legacy").

## Output

- `--json` writes exactly one JSON document to stdout and nothing else. The top level is an
  object with these keys, always present: `schema_version` (integer, currently `1`), `tool`
  (the command name), `version` (the tool's own version) and `exit_code` (the code the process
  will exit with). Everything else is tool-specific and only ever gains new keys within one
  `schema_version`; a removed or renamed key bumps `schema_version`.
- `--quiet` / `-q` writes nothing to stdout (no report, no JSON); only the exit code and any
  errors on stderr remain. Files requested explicitly (for example `--html FILE`) are still
  written.
- Errors and warnings go to stderr, never to stdout, also with `--json`.
- The JSON Schema for each tool's `--json` output is `schema/<tool>.schema.json` in the
  repository, and is checked by the test suite on every push.

## mail-security-auditor

| Code | Meaning here |
|------|--------------|
| 0 | No finding at or above `--fail-on` (default `medium`). |
| 1 | At least one finding at or above `--fail-on`. |
| 2 | Bad usage. |
| 3 | Unexpected runtime error, or every DNS query failed on the network (no resolver reachable). No legacy codes. |

`--json` top-level keys: `schema_version`, `tool`, `version`, `exit_code`, `results` (one object per
domain: `domain`, `timestamp`, `mx`, `spf`, `dmarc`, `dkim`, `findings`, `counts`, ...). Before 2.0.0
the top level was the list that is now `results`.

```
$ mail-security-auditor --json example.com
{"schema_version": 1, "tool": "mail-security-auditor", "version": "2.0.0", "exit_code": 0, "results": [...]}
$ mail-security-auditor --quiet --fail-on low example.com; echo $?
1
```
