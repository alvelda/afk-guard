"""afk-guard command line."""
import argparse
import json
import os
import sys

from . import __version__, scan as scanmod, canary as canarymod, mcpcheck
from . import injection_filter


def _sev_counts(findings):
    c = {}
    for f in findings:
        k = "canary" if f.canary else f.severity
        c[k] = c.get(k, 0) + 1
    return c


def cmd_scan(a):
    findings, files = [], 0
    if a.paths:
        for fs, n in scanmod.scan_paths(a.paths, a.show_context, a.exclude or ()):
            findings.extend(fs)
            files = n
    if a.procs:
        findings.extend(scanmod.scan_processes(a.show_context))
    counts = _sev_counts(findings)
    real = [f for f in findings if not f.canary]
    if a.format == "json":
        out = {"files_scanned": files, "counts": counts, "total_real": len(real)}
        if not a.counts_only:
            out["findings"] = [f.to_dict() for f in findings]
        print(json.dumps(out, indent=1))
    else:
        if not a.counts_only:
            for f in findings:
                tag = "CANARY" if f.canary else f.severity.upper()
                print(f"{tag:7} {f.path}:{f.line}  {f.rule}  {f.preview}  id={f.fingerprint}")
                if f.context:
                    print(f"        {f.context}")
        print(f"-- {files} files scanned, {len(real)} findings, counts: {json.dumps(counts, sort_keys=True)}")
    return 0 if a.exit_zero or not real else 1


def cmd_canary(a):
    if a.action == "plant":
        kinds = a.kinds.split(",") if a.kinds else canarymod.KINDS
        for k in kinds:
            if k not in canarymod.KINDS:
                print(f"unknown kind {k}; choose from {', '.join(canarymod.KINDS)}", file=sys.stderr)
                return 2
        try:
            planted = canarymod.plant(a.dir, kinds, a.callback_url)
        except canarymod.CanaryRegistryError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        for p in planted:
            print(f"planted {p['kind']:12} {os.path.join(a.dir, p['file'])}  id={p['id']}")
        print("Canary values are fake and contact no vendor. Registry:", os.path.join(a.dir, canarymod.REGISTRY_NAME))
        return 0
    if a.action == "check":
        try:
            alerts = canarymod.check(a.dir, a.log or (), a.listener_log)
        except canarymod.CanaryRegistryError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print(json.dumps(alerts, indent=1) if a.format == "json" else
              ("\n".join(f"ALERT {x['type']} {x.get('file', x.get('log', ''))} id={x.get('id', '')}" for x in alerts) or "no canary alerts"))
        return 1 if alerts else 0
    if a.action == "listen":
        print(f"listening on {a.host}:{a.port}, logging to {a.log_file} (Ctrl-C to stop)")
        try:
            canarymod.listen(a.port, a.log_file, a.host)
        except KeyboardInterrupt:
            pass
        return 0


def cmd_mcp(a):
    if a.update_pins and not a.pin_state:
        print("error: --update-pins requires --pin-state", file=sys.stderr)
        return 2
    adv = mcpcheck.load_advisories()
    home = a.home or os.path.expanduser("~")
    configs = mcpcheck.discover(home, a.paths) if not a.no_discover else mcpcheck.discover("/nonexistent", a.paths)
    servers, notes = [], []
    for c in configs:
        s, n = mcpcheck.parse_config(c)
        servers += s
        notes += n
    hits = mcpcheck.check_servers(servers, adv) + mcpcheck.openclaw_hits(configs, adv, a.openclaw_version)
    ext = mcpcheck.check_extension_dirs(home, adv)
    hyg = mcpcheck.hygiene(servers, configs) if a.hygiene else []
    generated_at = mcpcheck.utc_now()
    pins = mcpcheck.pin_records(servers)
    if a.pin_state:
        pin_findings = mcpcheck.reconcile_pin_state(
            a.pin_state, pins, version=__version__, generated_at=generated_at,
            update=a.update_pins, parse_failed=mcpcheck.notes_indicate_parse_failure(notes),
        )
    else:
        pin_findings = mcpcheck.safety_findings(pins) + mcpcheck.parse_skip_findings(notes)
    report = mcpcheck.build_report(
        __version__, generated_at, configs, servers, adv, hits, ext, hyg, notes, pins, pin_findings)
    if a.format == "json":
        print(json.dumps(report, indent=1))
    else:
        print(f"advisory db: {len(adv['advisories'])} entries, built {adv['generated_at']} from the AFK Cyber Desk feed")
        print(f"configs checked: {len(configs)}; servers found: {len(servers)}")
        for h in hits:
            print(f"{h.verdict.upper():18} {h.file} [{h.server}] {h.package} {h.version or '(unpinned)'} -> {h.advisory_id} "
                  f"{','.join(h.cve)}\n{'':19}{h.reason}\n{'':19}source: {h.source} {h.source_url}  confidence: {h.confidence}")
        for e in ext:
            print(f"EXTENSION          {e['path']} -> {e['advisory_id']} source: {e['source_url']}")
        for x in hyg:
            print(f"HYGIENE            {json.dumps(x)}")
        for fnd in pin_findings:
            where = fnd.get("file") or ""
            if fnd.get("server"):
                where = f"{where} [{fnd['server']}]".strip()
            print(f"{fnd['check'].upper():18} {where} {fnd['message']}".rstrip())
        for n in notes:
            print("note:", n)
        drift_n = sum(1 for fnd in pin_findings if fnd.get("check") in mcpcheck.DRIFT_CHECKS
                      and fnd.get("severity") in mcpcheck.GATE_SEVERITIES)
        safety_n = sum(1 for fnd in pin_findings if fnd.get("check") in mcpcheck.SAFETY_CHECKS
                       and fnd.get("severity") in mcpcheck.GATE_SEVERITIES)
        print(
            f"-- {len(hits)} advisory hits, {len(ext)} extension hits, {len(hyg)} hygiene items, "
            f"{drift_n} pin-drift, {safety_n} safety"
        )
        print("A clean result does not mean your setup is safe. See README for limits.")
    return mcpcheck.exit_code(hits, ext, pin_findings, a.exit_zero)


def cmd_inject(a):
    try:
        text, source, truncated = injection_filter.read_source(a.file)
    except OSError as exc:
        print(f"inject-check: {exc}", file=sys.stderr)
        return 2
    result = injection_filter.analyze(text, path=source)
    doc = injection_filter.to_document(
        result,
        source=source,
        truncated=truncated,
        version=__version__,
        generated_at=injection_filter.now_iso(),
    )
    if a.format == "json":
        print(json.dumps(doc, indent=1))
    else:
        print(injection_filter.render_text(doc))
    if a.exit_zero:
        return 0
    return 1 if doc["severity"] == "high" else 0


def cmd_inventory(a):
    from . import preview_inventory as pi
    res = pi.analyze(pi.load(a.file))
    print(json.dumps(res, indent=2) if a.format == "json" else pi.render(res))
    return 0


def cmd_dashboard(a):
    from . import dashboard as dash
    try:
        model = dash.assemble(
            manifest=a.input, scan=a.scan, canary=a.canary, mcp=a.mcp,
            inject=a.inject, drift=a.drift, example=a.example,
        )
    except (OSError, ValueError) as exc:
        print(f"dashboard: {exc}", file=sys.stderr)
        return 2
    document = dash.render(model)
    try:
        dash.write(a.out, document)
    except OSError as exc:
        print(f"dashboard: {exc}", file=sys.stderr)
        return 2
    print(f"wrote {a.out} ({len(document)} bytes, {dash.SCHEMA})")
    if len(document) > dash.SIZE_WARN:
        print(f"warning: HTML is {len(document)} bytes (over {dash.SIZE_WARN})", file=sys.stderr)
    if model.get("example"):
        return 0
    return 1 if model.get("exit_code") else 0


def _add_dashboard(sub, name):
    d = sub.add_parser(name, help="write a self-contained local HTML evidence report (offline, no network)")
    d.add_argument("-o", "--out", "--html", dest="out", default="afk-guard-dashboard.html",
                   help="output HTML path (replaces a symlink node; does not follow it)")
    d.add_argument("-i", "--input", help="scan, inject-check, mcp-check, canary, or dashboard manifest JSON")
    d.add_argument("--scan", help="scan --format json file")
    d.add_argument("--canary", help="canary check JSON, or {alerts, planted}")
    d.add_argument("--mcp", help="mcp-check JSON")
    d.add_argument("--inject", help="inject-check JSON (afk-guard/inject-check/v1)")
    d.add_argument("--drift", help="MCP drift JSON if that module is present")
    d.add_argument("--example", action="store_true", help="render the built-in EXAMPLE fixture (not with live inputs)")
    d.set_defaults(fn=cmd_dashboard)


def main(argv=None):
    p = argparse.ArgumentParser(prog="afk-guard", description="Local-only secret scan, canary tokens, MCP advisory check, instruction-pattern screen, and offline HTML report.")
    p.add_argument("--version", action="version", version=f"afk-guard {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="scan files/dirs (and optionally process command lines) for leaked secrets")
    s.add_argument("paths", nargs="*")
    s.add_argument("--procs", action="store_true", help="also scan /proc/*/cmdline (Linux)")
    s.add_argument("--exclude", action="append", help="directory to skip (repeatable)")
    s.add_argument("--format", choices=["text", "json"], default="text")
    s.add_argument("--counts-only", action="store_true", help="print counts only, no per-finding lines")
    s.add_argument("--show-context", action="store_true", help="show the surrounding line with detected secrets masked")
    s.add_argument("--exit-zero", action="store_true")
    s.set_defaults(fn=cmd_scan)

    c = sub.add_parser("canary", help="plant / check / listen for local canary tokens")
    cs = c.add_subparsers(dest="action", required=True)
    cp = cs.add_parser("plant"); cp.add_argument("dir"); cp.add_argument("--kinds"); cp.add_argument("--callback-url", help="your own local listener, e.g. http://127.0.0.1:8099")
    cc = cs.add_parser("check"); cc.add_argument("dir"); cc.add_argument("--log", action="append", help="log file to search for canary values (repeatable)")
    cc.add_argument("--listener-log"); cc.add_argument("--format", choices=["text", "json"], default="text")
    cl = cs.add_parser("listen"); cl.add_argument("--port", type=int, default=8099); cl.add_argument("--host", default="127.0.0.1"); cl.add_argument("--log-file", default="afk-canary-hits.jsonl")
    c.set_defaults(fn=cmd_canary)

    m = sub.add_parser("mcp-check", help="check OpenClaw / MCP client configs against the bundled advisory list")
    m.add_argument("paths", nargs="*", help="extra config files or project dirs to search")
    m.add_argument("--home"); m.add_argument("--no-discover", action="store_true")
    m.add_argument("--openclaw-version"); m.add_argument("--hygiene", action="store_true")
    m.add_argument("--pin-state", metavar="PATH",
                   help="local versioned JSON of MCP server pins and content hashes (afk-guard/mcp-pins/v1)")
    m.add_argument("--update-pins", action="store_true",
                   help="rewrite --pin-state to the current covered servers (accepts drift)")
    m.add_argument("--format", choices=["text", "json"], default="text"); m.add_argument("--exit-zero", action="store_true")
    m.set_defaults(fn=cmd_mcp)

    ij = sub.add_parser("inject-check", help="screen a file or stdin for instruction patterns (offline, heuristic)")
    ij.add_argument("file", help="text file to screen, or - for stdin (read is size-capped)")
    ij.add_argument("--format", choices=["text", "json"], default="json")
    ij.add_argument("--exit-zero", action="store_true")
    ij.set_defaults(fn=cmd_inject)

    iv = sub.add_parser("inventory-preview", help="PREVIEW: offline analysis of an agent-access inventory JSON (no accounts contacted)")
    iv.add_argument("file"); iv.add_argument("--format", choices=["text", "json"], default="text")
    iv.set_defaults(fn=cmd_inventory)

    _add_dashboard(sub, "dashboard")
    _add_dashboard(sub, "report-html")

    a = p.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
