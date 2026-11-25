"""judged sbom [--format cyclonedx|spdx] [--project DIR] [--out DIR]   software bill of materials from lockfiles
   judged diff [--old F --new F]               what changed since the previous saved report (exit 1 if something got worse)
   judged config template | check               a complete config with every option / validate yours (a missing option is an error)
   judged audit [-c FILE] [--framework ce|gdpr|iso27001] [--json | --soa]   evidence per control; --soa: what applies, what proves it, what is open
   judged renew [-c FILE] [--dry-run]   renew certificates that are due, then verify the served one changed
   judged report [--path]               print the newest report.md (pipe to less); --path prints where it is
   judged licences [-c FILE]            bought licences per year of expiry with cost totals
   judged obligations [-c FILE]         recurring and event-driven obligations for the regions in the config
   judged check [-c FILE] [--dry-run]   one pass: collect, print, notify what is newly due
   judged run   [-c FILE] [--every H] same, forever (the one daemon); config path default:
                                       $XDG_CONFIG_HOME/judged/judged.conf"""
import argparse
import json
import os
import sys
import time
from datetime import date, datetime, timezone
from pathlib import Path

import glob
from .secrets import M_SECRETS
from . import report, checks, conf, controls, core, host, mail, net, notify, licences, obligations, renew, rules, secrets, web, deps, sandbox, containers, malware, waivers, areas, sbom, integrity, links, statement


def xdg(var: str, fallback: str) -> Path:
    return Path(os.environ.get(var) or Path.home() / fallback)


def load(path: Path) -> dict:
    return conf.load_strict(path)           # every option must be written down; see `judged config template`


def collect(cfg: dict) -> list:
    items = []
    for e in cfg.get("item", []):
        try:
            if e["kind"] == "tls":
                items += checks.tls(e.get("name", e["host"]), e["host"], e.get("port", 443))
            elif e["kind"] == "gpg":
                items += checks.gpg(e.get("homedir"))
            elif e["kind"] == "date":
                items += checks.date(e["name"], e["expires"])
            elif e["kind"] == "domain":
                items += checks.domain(e["host"])
            elif e["kind"] == "licence":
                meta = {k: v for k, v in e.items() if k not in ("kind", "name", "expires")}
                items += checks.date(e["name"], e["expires"], "licence", meta)
        except Exception as ex:  # one broken item must not hide the others
            print(f"warn: {e.get('name', e['kind'])}: {ex}", file=sys.stderr)
    return items + obligations.items(cfg) + areas.items(cfg, datetime.now(timezone.utc).date())


def notify_urls(cfg: dict) -> list[str]:
    n = cfg.get("notify", {})
    urls = list(n.get("urls", []))
    if n.get("urls_file"):  # secrets live outside the repo
        p = Path(n["urls_file"]).expanduser()
        urls += [l.strip() for l in p.read_text().splitlines() if l.strip() and not l.startswith("#")]
    if os.environ.get("JUDGED_NOTIFY"):
        urls += os.environ["JUDGED_NOTIFY"].split()
    return urls


def once(cfg_path: Path, dry: bool) -> int:
    cfg = load(cfg_path)
    lead = cfg.get("notify", {}).get("lead_days", [30, 14, 7, 1])
    now = datetime.now(timezone.utc)
    state_file = xdg("XDG_STATE_HOME", ".local/state") / "judged" / "state.json"
    state = json.loads(state_file.read_text()) if state_file.exists() else {}
    items = collect(cfg)
    for it in sorted(items, key=lambda i: i.expires):
        print(f"{core.days_left(it, now):8.1f} d  {it.kind:4} {it.name}")
    alerts, new_state = core.due(items, state, lead, now)
    dated = []
    for it, b in alerts:
        title = f"judged: {it.name} " + ("EXPIRED" if b < 0 else f"expires in {core.days_left(it, now):.0f} days")
        dated.append(statement.Alert(f"{it.kind}:{it.name}", b, title, f"{it.kind} {it.name} expires {it.expires:%Y-%m-%d} (band {b})"))
    new_state.update({k: v for k, v in state.items() if k.startswith("source:")})     # a source that is offline today is not forgotten
    statement.deliver(dated + areas.news(cfg, areas.Ctx(now.date(), state_file.parent), state), new_state, state,
                      lambda title, body: notify.send(notify_urls(cfg), title, body), dry)
    if not dry:
        state_file.parent.mkdir(parents=True, exist_ok=True)
        state_file.write_text(json.dumps(new_state))
    return 0


AUTO_REPORT = "\0auto"


def report_dir() -> Path:
    return xdg("XDG_STATE_HOME", ".local/state") / "judged" / "reports"


def audit(cfg_path: Path, only: str | None, as_json: bool, report_to: str | None = None, notify_report: bool = False, soa: bool = False) -> int:
    """Collect machine evidence and roll it up into framework controls."""
    if not cfg_path.exists():
        raise conf.ConfError(f"no config at {cfg_path}: create one with `judged config template > {cfg_path}`")
    cfg = load(cfg_path)
    results = areas.run_all(cfg, areas.Ctx(date.today(), xdg("XDG_STATE_HOME", ".local/state") / "judged"))
    delivered = True
    if notify_report and not report_to:
        report_to = AUTO_REPORT
    if report_to:
        text = report.build(results, only)
        if report_to == AUTO_REPORT:
            where = report.save(text, report_dir(), results=results)
        else:
            where = Path(report_to)
            where.write_text(text, encoding="utf-8")
        print(f"report written to {where}")
        if notify_report:
            state, title, body = report.summary(results)
            delivered, how = notify.send_report(cfg.get("notify", {}), notify_urls(cfg), state, title, body, where, f"judged-audit-{date.today()}.md")
            print(("sent: " if delivered else "NOT SENT: ") + how, file=sys.stderr if not delivered else sys.stdout)
    elif as_json:
        print(json.dumps([r.__dict__ for r in results], indent=1))
    else:
        print((controls.soa if soa else controls.markdown)(controls.load_frameworks(), results, only))
    if any(r.status == "fail" for r in results):
        return 1
    return 0 if delivered else 3               # 3 = the audit is clean but the message did not leave


def renew_pass(cfg_path: Path, dry: bool, every_h: float = 6.0) -> int:
    cfg = load(cfg_path)
    sf = xdg("XDG_STATE_HOME", ".local/state") / "judged" / "renew.json"
    try:
        last = json.loads(sf.read_text()) if sf.exists() else {}
        if not isinstance(last, dict):
            raise ValueError("not a JSON object")
    except (OSError, ValueError) as ex:   # a damaged state file must not stop renewals; say so and start fresh
        print(f"warn         state file {sf} unreadable ({ex}); treating every host as never attempted")
        last = {}
    bad = 0
    for e in cfg.get("renew", []):
        name = e.get("name", e["host"])
        w = renew.window_warning(e, every_h)
        if w:
            print(f"warn         {name}: {w}")
        status, msg, tried = renew.renew_one(e, last.get(name), dry)
        print(f"{status:12} {name}: {msg}")
        if tried and not dry:      # saved at once: a crash later in the pass must not forget this attempt (ACME rate limits)
            last[name] = time.time()
            sf.parent.mkdir(parents=True, exist_ok=True)
            tmp = sf.with_suffix(".tmp")
            tmp.write_text(json.dumps(last))
            tmp.replace(sf)
        if status in ("renewed", "failed") and not dry:
            bad += status == "failed"
            try:
                sent = notify.send(notify_urls(cfg), f"judged: certificate {name} {status}", msg)
            except Exception as ex:   # apprise missing or broken: the renewal result stands, say the message was not sent
                sent, msg = False, f"{ex}"
            if not sent:
                print(f"warn         {name}: notification not sent ({msg if not sent and msg != '' else 'no channel configured'})")
    return 1 if bad else 0


def integrity_cmd(a) -> int:
    what = a.what if a.what in ("init", "accept", "show") else None
    if not what:
        print("integrity: say what to do: init (make the baseline), accept (replace it after review) or show (what changed)", file=sys.stderr)
        return 2
    cfg = load(a.config).get("integrity", {})
    if not cfg.get("paths"):
        print("integrity: no paths in the `integrity` section of the config", file=sys.stderr)
        return 2
    state = xdg("XDG_STATE_HOME", ".local/state") / "judged"
    bp = integrity.baseline_path(state, cfg)
    old = integrity.load(bp)
    if what == "show":
        for r in integrity.integrity_check(cfg, state):
            print(f"{r.status:8} {r.id}: {r.evidence}")
        return 0
    if what == "init" and old is not None:
        print(f"integrity: a baseline already exists ({bp}, made {old.get('made')}); review `judged integrity show`, then `judged integrity accept`", file=sys.stderr)
        return 2
    if what == "accept" and old is None:
        print("integrity: no baseline to replace: use `judged integrity init`", file=sys.stderr)
        return 2
    files, problems = integrity.scan(cfg["paths"], cfg.get("exclude", []), cfg.get("max_filesize_mb", 100), cfg.get("max_files", 200000))
    integrity.save(bp, files, cfg["paths"], datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), old)
    print(f"integrity: baseline of {len(files)} files written to {bp}")
    for p in problems:
        print(f"  note: {p}", file=sys.stderr)
    return 0


def links_cmd(a) -> int:
    cfg = load(a.config).get("links", {})
    if not cfg.get("paths"):
        print("links: no paths in the `links` section of the config", file=sys.stderr)
        return 2
    for line in links.listing(cfg):
        print(line)
    return 0


def sbom_cmd(a) -> int:
    fmts = sbom.formats()
    if a.format not in fmts:
        print(f"sbom: unknown format {a.format!r} (known: {', '.join(sorted(fmts))})", file=sys.stderr)
        return 2
    roots = [str(a.project)] if a.project else sbom.projects(load(a.config).get("deps", {}).get("projects", []))
    if not roots:
        print("sbom: no projects (set `deps projects=...` in the config or pass --project DIR)", file=sys.stderr)
        return 2
    if len(roots) > 1 and not a.out:
        print(f"sbom: {len(roots)} projects, one document each: give --out DIR", file=sys.stderr)
        return 2
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    for root in roots:
        comps, notes = sbom.collect(root)
        name = Path(root).expanduser().resolve().name
        text = fmts[a.format].render({"name": name, "created": now, "components": comps, "notes": notes})
        if a.out:
            a.out.mkdir(parents=True, exist_ok=True)
            (a.out / f"{name}{fmts[a.format].EXT}").write_text(text, encoding="utf-8")
        else:
            print(text, end="")
        print(f"sbom {name}: {len(comps)} components" + ("" if comps else " (EMPTY)"), file=sys.stderr)
        for n in notes:
            print(f"  note: {n}", file=sys.stderr)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(prog="judged")
    ap.add_argument("cmd", choices=["check", "run", "audit", "renew", "obligations", "licences", "report", "config", "diff", "sbom", "integrity", "links"])
    ap.add_argument("what", nargs="?", choices=["template", "check", "init", "accept", "show"], help="config: template = print a complete config with every option, check = validate the file; integrity: init = make the baseline, accept = replace it after review, show = what changed")
    ap.add_argument("-c", "--config", type=Path, default=xdg("XDG_CONFIG_HOME", ".config") / "judged" / "judged.conf")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--every", type=float, default=6.0, help="hours between passes (run)")
    ap.add_argument("--framework", choices=["ce", "gdpr", "iso27001"])
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--soa", action="store_true", help="audit: print the statement of applicability and what is still open before an audit")
    ap.add_argument("--report", nargs="?", const=AUTO_REPORT, metavar="FILE", help="write one readable report instead of printing (no FILE: into the state folder, see `judged report`)")
    ap.add_argument("--notify", action="store_true", help="audit: also send the summary and the full report through the notify section (notts or Apprise)")
    ap.add_argument("--old", type=Path, help="diff: older raport-*.json (default: the second newest)")
    ap.add_argument("--new", type=Path, help="diff: newer raport-*.json (default: the newest)")
    ap.add_argument("--format", default="cyclonedx", help="sbom: cyclonedx or spdx (one file per format in judged/sbom/)")
    ap.add_argument("--project", type=Path, help="sbom: one project folder instead of the deps.projects of the config")
    ap.add_argument("--out", type=Path, help="sbom: folder to write NAME.cdx.json / NAME.spdx.json into (needed for more than one project)")
    ap.add_argument("--path", action="store_true", help="report: print the path of the newest report, not its text")
    a = ap.parse_args()
    if a.cmd == "config":
        if a.what == "template":
            print(conf.template(), end="")
            return 0
        if a.what == "check":
            load(a.config)
            print(f"{a.config}: complete, every option is stated")
            return 0
        ap.error("config needs `template` or `check`")
    if a.cmd == "renew":
        return renew_pass(a.config, a.dry_run, a.every)
    if a.cmd == "obligations":
        print(obligations.report(load(a.config) if a.config.exists() else {}))
        return 0
    if a.cmd == "licences":
        print(licences.calendar(collect(load(a.config) if a.config.exists() else {}), datetime.now(timezone.utc)))
        return 0
    if a.cmd == "sbom":
        return sbom_cmd(a)
    if a.cmd == "integrity":
        return integrity_cmd(a)
    if a.cmd == "links":
        return links_cmd(a)
    if a.cmd == "diff":
        pair = (a.old, a.new) if a.old and a.new else report.last_two(report_dir())
        if pair is None:
            print("need two saved reports: run `judged audit --report` twice (or pass --old and --new)", file=sys.stderr)
            return 2
        try:
            d = report.diff(report.load_results(pair[0]), report.load_results(pair[1]))
        except ValueError as e:
            print(f"diff: {e}", file=sys.stderr)
            return 2
        print(report.render_diff(d, pair[0].stem.removeprefix("raport-"), pair[1].stem.removeprefix("raport-")))
        return 1 if report.has_regression(d) else 0
    if a.cmd == "report":
        newest = report.newest(report_dir())
        if newest is None:
            print("no report yet: run `judged audit --report`", file=sys.stderr)
            return 1
        print(newest if a.path else newest.read_text(encoding="utf-8"), end="\n" if a.path else "")
        return 0
    if a.cmd == "audit":
        return audit(a.config, a.framework, a.json, a.report, a.notify, a.soa)
    if a.cmd == "check":
        return once(a.config, a.dry_run)
    while True:
        once(a.config, a.dry_run)
        renew_pass(a.config, a.dry_run, a.every)
        time.sleep(a.every * 3600)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except conf.ConfError as e:
        print(f"config error: {e}", file=sys.stderr)
        sys.exit(2)
