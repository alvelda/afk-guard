"""PREVIEW STUB of the paid tier: offline analysis of an agent-access inventory.

This module opens NO network connections and connects to NO accounts. It reads a JSON
file that a human (or a future connector) produced and answers four questions:
  1. inventory      - what third-party agents/apps hold access, per vendor
  2. capabilities   - which can SEND, PAY or PUBLISH (heuristic scope map, see CAP_HINTS)
  3. stopped?       - did "disconnected" agents really stop (activity after disconnect)
  4. revoke list    - ordered, per vendor, with the method that docs say exists
Scope-to-capability hints are heuristics, not vendor-verified. See docs/account-api-verification.md.
"""
import json

# (substring in a scope/permission string) -> capability. Heuristic, deliberately broad.
CAP_HINTS = {
    "send": ["gmail.send", "gmail.compose", "gmail.modify", "mail.google.com", "chat:write", "chat.write",
             "calendar.events", "email.send", "messages_write", "im:write", "mpim:write"],
    "pay": ["charges_write", "payment_intents_write", "paymentintent_write", "refunds_write", "payouts_write",
            "transfers_write", "customer_write", "checkout_sessions_write", "sk_", "unrestricted", "billing_write"],
    "publish": ["contents:write", "contents_write", "repo", "public_repo", "workflow", "packages:write", "pull_requests:write",
                "tweet.write", "files:write", "drive.file", "sites", "blogger", "youtube", "pages_write", "deployments"],
}
# What the vendor docs I verified say about removing access (see account-api-verification.md)
REVOKE_HOW = {
    "google": "Workspace admin: Directory API tokens.delete (VERIFIED). Consumer: Google Account > linked apps (UI) (VERIFIED UI).",
    "github": "Org owner: uninstall app in org settings or app owner API; PAT: org admin revoke via GitHub App API (VERIFIED); user OAuth app: Settings > Applications (UI).",
    "slack": "Enterprise: admin.apps.uninstall (VERIFIED). Other plans: workspace admin UI (UNVERIFIED path) or the app owner (apps.uninstall).",
    "stripe": "Dashboard: expire/rotate the key (VERIFIED). Connect: platform oauth/deauthorize (VERIFIED). No list/revoke by API found (UNVERIFIED).",
}


def load(path):
    with open(path, encoding="utf-8") as f:
        d = json.load(f)
    if not isinstance(d, dict) or not isinstance(d.get("grants"), list):
        raise ValueError("inventory file must be an object with a 'grants' list")
    return d


def capabilities(grant):
    text = " ".join(str(x).lower() for x in grant.get("scopes", []) or [])
    return sorted(c for c, hints in CAP_HINTS.items() if any(h.lower() in text for h in hints))


def stopped_check(grant):
    """Return None for connected grants, else a verdict about a claimed disconnect."""
    if grant.get("status") != "disconnected_claimed":
        return None
    d, last = grant.get("disconnected_at"), grant.get("last_activity_at")
    if last and d and last > d:           # ISO-8601 strings in one timezone compare lexically
        return "NOT STOPPED: activity after disconnect"
    if grant.get("still_listed"):
        return "GRANT STILL LISTED: disconnect did not remove the grant"
    return "no activity seen since disconnect (absence of logs is not proof)"


def analyze(inv):
    rows = []
    for g in inv["grants"]:
        caps = capabilities(g)
        rows.append({"vendor": g.get("vendor", "?"), "agent": g.get("agent", "?"), "caps": caps,
                     "status": g.get("status", "connected"), "stopped": stopped_check(g),
                     "risk": len(caps) + (3 if stopped_check(g) and stopped_check(g).startswith(("NOT", "GRANT")) else 0)})
    rows.sort(key=lambda r: -r["risk"])
    revoke = {}
    for r in rows:
        if r["risk"] > 0 or r["status"] == "disconnected_claimed":
            revoke.setdefault(r["vendor"], []).append(r["agent"])
    return {"example_data": bool(inv.get("example_data")), "grants": rows,
            "revoke_list": {v: {"agents": a, "how": REVOKE_HOW.get(v, "unknown vendor")} for v, a in revoke.items()}}


def render(res):
    out = []
    if res["example_data"]:
        out.append("EXAMPLE DATA - not a real account")
    out.append("PREVIEW: offline analysis only, no account was contacted")
    for r in res["grants"]:
        out.append(f"{r['vendor']:7} {r['agent']:28} caps={','.join(r['caps']) or '-':18} {r['status']}" + (f"  [{r['stopped']}]" if r["stopped"] else ""))
    out.append("-- revoke list --")
    for v, d in res["revoke_list"].items():
        out.append(f"{v}: {', '.join(d['agents'])}\n   how: {d['how']}")
    return "\n".join(out)
