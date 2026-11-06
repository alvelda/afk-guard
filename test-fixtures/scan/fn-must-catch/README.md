# FN must-catch corpus

Owner: QA · Target: **FN = 0** on must-catch shapes.

**Do not commit full tokens.** Assemble at runtime like `tests/test_afk_guard.py` (`AWS`, `GH`, `SLACK`, `STRIPE` concatenation).

## Must-catch set (from existing `ScanTests`)

| ID | Rule id | Covered by | Notes |
|----|---------|------------|-------|
| FN-01 | `aws-access-key-id` | `ScanTests.test_rules_detect_and_redact` | Assembler `AWS` |
| FN-02 | `github-token` | same | Assembler `GH` |
| FN-03 | `slack-token` | same | Assembler `SLACK` |
| FN-04 | `stripe-live-key` | same | Assembler `STRIPE` |
| FN-05 | `private-key-block` | same | PEM header line only |
| FN-06 | context mask | `test_context_masks_secret` | no raw secret in context |
| FN-07 | redact in JSON | `test_rules_detect_and_redact` | assembled values absent from JSON |

Pre-C1.2 LIVE probe (`scan_text` on assembled must-catch blob): **5 findings**, rules =
`aws-access-key-id`, `github-token`, `slack-token`, `stripe-live-key`, `private-key-block` (FN=0 on this set).

Untested shaped rules (openai/anthropic/jwt/bearer/…): see BOARD **QA-DEF-004** — not in must-catch gate yet.
