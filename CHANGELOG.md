# Changelog

## 0.1.1 — 2026-11-09

- Python 3.9 and 3.10 read Codex TOML through the conditional `tomli` dependency (`python_version < '3.11'`). Python 3.11 and newer still use `tomllib`.
- A missing TOML parser, a broken parser install, and a parser crash are separate notes. A broken install is labelled with the exception class. Those notes do not include the exception text or the config body.
- Behaviour change from 0.1.0: `mcp-check` now exits 1 when a config is unparseable or unreadable (JSON, TOML, or a file that cannot be opened), unless `--exit-zero`. In 0.1.0 that case exited 0 unless `--pin-state` was set. The finding is `config-unparseable`, counted as safety, not as pin-drift.
