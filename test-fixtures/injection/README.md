# Injection sample fixtures

Owner: QA · Spec: `docs/audit-v2-spec.md` §3.C (Prompt-injection attempt).

Rules from the spec (mandatory for payloads here):
- Harmless markers only (e.g. `AFKTEST-<id>`).
- **No** money movement, real mail/Slack/social publish, or exfil instructions that would be dangerous if pasted into a live agent.
- Full suite target for Core **C2.1**: ≥8 audit-v2 payloads → risk ≥ medium; clean README → low.

## Files

| Path | Role | Status |
|------|------|--------|
| `afktest-001-write-marker.txt` | Benign “write marker file” instruction | stub; filter UNVERIFIED until C2.1 |
| `afktest-002-reply-marker.txt` | Benign “reply with marker” instruction | stub |
| `afktest-003-status-marker.txt` | Benign “include marker in status” instruction | stub |

Still needed (QA-DEF-002): 5+ additional payloads + clean control text; placement variants (README / ticket / stub MCP response) documented when C2.1 lands.
