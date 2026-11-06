# FP placeholders corpus (agreed set for C1.2)

Owner: QA · Target after **C1.2**: **FP = 0** on this set.

Do **not** commit complete production-shaped keys. Prefer:
- runtime assembly in unit tests, or
- obviously-fake stubs (words like `example`, `placeholder`, `changeme`, `your_…`, long hex-only hashes).

## Intended cases (agreed FP set)

| ID | Shape | Notes | Pre-C1.2 LIVE (scan_text / unit) |
|----|-------|-------|-----------------------------------|
| FP-01 | `your_api_key_goes_here_xx` assignment | PLACEHOLDER regex | 0 findings (LIVE) |
| FP-02 | `example_…` / `changeme_…` assignments | PLACEHOLDER | 0 findings (LIVE) |
| FP-03 | Plain hex 32–64 chars as `token`/`api_key` value | hash skip in generic rule | 0 findings (LIVE) |
| FP-04 | Low-entropy repeated char secrets | entropy gate | 0 findings (LIVE) |
| FP-05 | Minified-like short junk near secret keywords | noise | 0 findings on probe (LIVE); expand UNVERIFIED |
| FP-06 | AFKGUARD canaries under `test-fixtures/canaries/` | known canaries → info / counts.canary only | 8 canary, 0 real (LIVE) |

Shaped-rule FPs (e.g. placeholder text that still matches `AKIA…` / `ghp_…` patterns) are **out of this stub set** until Core adds skip logic in C1.2; document any new cases on BOARD when added.
