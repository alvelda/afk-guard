# afk-guard

Free, local-only guard rails for people who run AI agents. Apache-2.0. Python 3.9+. No network calls. Codex TOML on Python 3.9 and 3.10 uses the `tomli` package; Python 3.11 and newer use the standard-library parser.

Status: **0.1.1 (Apache-2.0). Repository: https://github.com/alvelda/afk-guard**

Context lines mask the full span of a matched secret. The canary registry is written only in a directory you name.

It does five things:
1. `scan` — find leaked secrets in files/directories (regex rules plus entropy). Values are **redacted** in all output: a fixed `[REDACTED]` label, the rule name, a coarse length bucket (not the exact length), and a short location fingerprint. The fingerprint is a hash of the rule, the normalized path, and the line number. It is not a hash of the secret. No characters from the secret are shown, including a short prefix. The same secret in two places does not share an id. Two findings with the same rule, path, and line do share an id (collision accepted; no cross-file value dedupe). `--show-context` masks the union of overlapping matched spans on the line, so a longer overlap cannot leave a secret suffix.
2. `canary` — plant fake, tempting credentials and watch whether anything touches them. Local log, optional webhook to *your own* listener. No signups, no vendor contact. The registry check applies only to the directory you name.
3. `mcp-check` — check OpenClaw / MCP client configs (Cursor, Codex, OpenClaw, generic `mcpServers` JSON/TOML) against a bundled advisory list taken from the AFK Cyber Desk feed. `--pin-state` records a pin and a content hash and reports drift when that covered set changes. See "MCP pin file".
4. `inject-check` — screen a text file or stdin for instruction patterns (ignore-previous, marker file writes, tool-call requests, and similar). Offline and deterministic. A low result is not proof the text is safe, and the check does not block anything.
5. `dashboard` — a local HTML report: one file (inline CSS and SVG, no network) from scan, canary, mcp-check, or inject-check JSON. Pure `--example` is badged EXAMPLE DATA. Live input is not. Findings show `[REDACTED]`, a length bucket, and a location fingerprint of rule, path, and line. No secret prefix is displayed.

## Install / run
```
python3 -m afk_guard --help          # from this directory
pip install .                        # optional; gives the `afk-guard` command
python3 -m unittest discover -s tests
```

## Examples
```
afk-guard scan ~/projects --counts-only          # counts only, no per-finding lines
afk-guard scan ~/projects --format json          # redacted findings
afk-guard scan --procs                           # also scan /proc/*/cmdline (Linux; never environ)
afk-guard canary plant ./sandbox --kinds aws,github,env
afk-guard canary listen --port 8099              # loopback-only listener, writes JSONL
afk-guard canary check ./sandbox --log agent.log --listener-log afk-canary-hits.jsonl
afk-guard mcp-check                               # discovers common config locations under $HOME
afk-guard mcp-check ./repo --hygiene              # plaintext secrets, unpinned npx, http remotes
afk-guard mcp-check ./repo --no-discover --pin-state .afk/mcp-pins.json
afk-guard mcp-check ./repo --no-discover --pin-state .afk/mcp-pins.json --update-pins
afk-guard inventory-preview ./inventory.json   # PREVIEW: offline inventory JSON, no accounts contacted
afk-guard inject-check ./untrusted/page.txt          # versioned JSON; exit 1 when severity is high
afk-guard inject-check -                            # read stdin, size-capped
afk-guard dashboard --example -o afk-guard-dashboard.html   # offline HTML, EXAMPLE DATA
afk-guard dashboard --scan scan.json --inject inject.json -o report.html
```
Exit codes: `scan` returns 1 when a real finding is present. `mcp-check` returns 1 when an advisory hit, an extension hit, a pin/content drift finding, or a pin safety finding is present (`--exit-zero` forces 0). A config that could not be parsed is a high-severity `config-unparseable` safety finding, including when no pin file is requested, so that run exits 1 rather than 0. There is no separate warning exit code. `inject-check` returns 1 when severity is high (medium and low return 0). `dashboard` returns 1 when a live report has a failing check, and 2 when the JSON is rejected, `--example` is mixed with a live input, or the HTML cannot be written. Pure `--example` returns 0. JSON for `mcp-check` uses schema `afk-guard/mcp-check/v1` with `schema`, `tool`, `version`, `generated_at`, and `findings`. Severity `info` means a pin baseline was recorded or refreshed and does not fail the process. The pin file schema is `afk-guard/mcp-pins/v1`. Hygiene findings carry severity for CI but do not by themselves change the process exit.

`dashboard --input` accepts `afk-guard/dashboard-html/v1`, `afk-guard/scan/v1` (or scan JSON with `findings` plus `files_scanned`, `total_real`, or `counts`), `afk-guard/inject-check/v1` (or `tool: inject-check`), `afk-guard/mcp-check/v1`, schema-less mcp-check JSON that has `hits`, `extension_hits`, or `advisory_db`, and `afk-guard/canary/v1` (or `alerts` / `planted`). Other shapes exit 2 and write no file. `afk-guard/mcp-check/v1` is displayed when a document has it. Pin and drift rows show only if that document includes them. Core `len=` buckets and this page's integer-length buckets are not the same scale.

`-o` writes a new file in the destination directory and replaces that directory entry. A symlink at the output path is not followed, so the symlink target is not truncated. An existing regular file is replaced.

## What it will NOT do (read this)
- **A clean result does not mean you are safe.** It means these rules found nothing in the files it looked at. `inject-check` is the same kind of limit: it only matches a fixed list of instruction patterns.
- `inject-check` reads at most 1 MB. It does not print the source text. It does not call the network.
- It cannot see secrets in places it does not read (password managers, browser stores, memory, environment of other processes, remote systems). `~/.ssh`, `~/.secrets` and browser profiles are only scanned if you point it there.
- Entropy findings are guesses. Expect false positives (hashes, test data, minified code). Add `afk-guard:ignore` on a line to skip it. Placeholders and plain hex hashes are skipped.
- It does not delete files or rewrite MCP configs, source trees, or secret stores. Rotate real secrets yourself. `canary plant` writes decoy files and a registry only in the directory you name. `mcp-check --pin-state` writes the pin file (mode `0600`); it rewrites that file only with `--update-pins`.
- Files over 1 MB, binary files, and common dependency/build dirs are skipped.
- Canary "accessed" uses file access time (atime). Many systems mount with `noatime`; treat it as low confidence. Stronger signals: value seen in a log you give it, or a callback hit.
- The canary registry is written only in a directory you own that is mode exactly `0700` and not a symlink. Group or other permission, or the sticky bit on that directory, is refused. The tool does not chmod it. A sticky ancestor such as `/tmp` above that private directory is not inspected and is not a reason to refuse. The registry file is mode `0600`. A symlink or a registry that is not mode `0600` is refused, not repaired. Unix directory descriptors are required; other platforms refuse. This assumes your local user account is not already compromised. It does not claim protection against root, or against someone replacing a parent mount such as `/tmp`.
- Canaries are fake and carry the marker `AFKGUARD`. The payment canary uses an `sk_test_` prefix on purpose so it does not look like a live key to other scanners. Planting them in a repo you scan with other tools will trigger those tools: plant in a sandbox directory.

## Advisory data (mcp-check)
`afk_guard/data/advisories.json` is taken from the AFK Cyber Desk feed (`agentfieldkit.com/agents/cyber/feed.json`, 47 items at build time; 24 had a matchable package and are bundled). For each entry we keep the feed id, title, date, CVE id and source URL, and mark confidence:
- Titles, dates, CVE ids and source URLs are copied from the feed by id.
- **Package names and fixed versions were transcribed by hand from the feed titles and are not independently verified.** Two package ids are guesses and flagged `name_unverified`: `@samanhappy/mcphub` and `awslabs.aws-serverless-mcp-server`.
- Three OpenClaw entries have no version data and are low confidence.
Verdicts: `affected`, `possibly-affected`, `check-version`, `present`, `not-affected`. Where no fixed version is known the verdict is `check-version`, never "safe". Always follow the source URL before acting.

## MCP pin file

`--pin-state` stores `afk-guard/mcp-pins/v1`: one record per config group + server name. The same server name in two groups is two pins plus a `duplicate-server-name` finding (not last-wins). A missing pin file records a baseline only when every config parsed and every launch is covered. That baseline is severity `info`. Drift, a bad pin file, or a refused launch exits 1 and does not rewrite the pin file. `--update-pins` replaces the pin file with the current covered set.

`pin` is a recognized version (`1.2.3`, `v1.2.3`, a short prerelease such as `1.2.3-beta.1`, or the tags `latest` / `next`) or empty when the launcher has no version. A version tail that does not match that syntax is not stored and is not echoed. Empty is "no version pin", not a claim that an unrecognized tail was verified.

`content_hash` is `sha256:` plus the SHA-256 of canonical JSON (sorted keys, no extra whitespace) of this projection:

- server name and command
- boolean flags, **path arguments**, and the syntax-valid package spec
- env **key names**, sorted (env **values** are not hashed and not stored)
- package ecosystem, name, and syntax-valid version
- URL scheme, host, port, and path

`integrity: full` means that projection only. **It includes path arguments. It is not a secret-free claim over path strings:** a credential placed in a path is still hashed. It does not cover env values. Credential-shaped arguments (`--token` and similar), token-shaped arg values, URL userinfo, URL query or fragment, unrecognized version tails, and unclassified args are `integrity: unsupported`. They are not hashed. No verified baseline is written. Changing only the secret must not look like a clean, fully covered pin. A group-or-other-readable pin file is repaired to mode `0600` on read when that repair can be done on the open file; a pin file that cannot be read is left unchanged.

## Tests
`python3 -m unittest discover -s tests` in this repository runs 112 tests. Test secrets are assembled at runtime, so the repo contains no complete token literal. Instruction-pattern fixtures under `test-fixtures/injection/` are fake drill text. Dashboard fixtures are fake too: no live tokens, and the HTML does not load a network.

Paid features are available separately.

## License
Apache-2.0, see `LICENSE`. Commercial terms for paid features will be published separately.
