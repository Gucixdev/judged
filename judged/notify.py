"""Delivery. Two doors: the `notts` command (a separate command: many services, phone included, grouping so a repeated
failing report is not sent twice) and Apprise URLs (discord://, tgram://, matrix://, mailtos://, ...). `via=notts|apprise|auto`
in the `notify` section; auto = notts when it is on PATH, else Apprise. A failed delivery is reported, never hidden, and judged
does not retry on the other door after notts answered (it may already have delivered part of it)."""
import json
import shutil
import subprocess


def send(urls: list[str], title: str, body: str, attach: str | None = None) -> bool:
    import apprise
    a = apprise.Apprise()
    for u in urls:
        a.add(u)
    if not urls:
        return False
    return bool(a.notify(title=title, body=body, attach=attach)) if attach else bool(a.notify(title=title, body=body))


def _answer(stdout: str) -> dict:
    """notts --json answer, or {} when it is not one (an older notts, a crash): the exit code still decides."""
    try:
        d = json.loads(stdout)
        return d if isinstance(d, dict) else {}
    except ValueError:
        return {}


def _said(out: dict, default: str) -> str:
    """One line from notts's own words: what happened to the message and per channel."""
    if not out.get("disposition"):
        return default
    chans = ", ".join(f"{c.get('name')}={c.get('status')}" + (f" ({c['detail']})" if c.get("detail") and c.get("status") != "sent" else "")
                      for c in out.get("results", [])[:6])
    return f"notts: {out['disposition']}" + (f" ({out['reason']})" if out.get("reason") else "") + (f"; {chans}" if chans else "")


def send_report(ncfg: dict, urls: list[str], state: str, title: str, body: str, report_path, name: str,
                run=subprocess.run, which=shutil.which, apprise_send=send) -> tuple:
    """Send the short summary and attach the full report. Returns (delivered, what happened in one line)."""
    via, cmd = ncfg.get("via", "auto"), ncfg.get("notts", "notts")
    if via not in ("auto", "notts", "apprise"):
        return False, f"notify via={via!r} is not one of auto, notts, apprise"
    if via != "apprise" and which(cmd):
        argv = [cmd, "send", "--app", "judged", "--key", "judged-audit", "--state", state, "--title", title,
                "--body-file", "-", "--json", "--attach", str(report_path), "--attach-name", name]
        try:
            r = run(argv, input=body, capture_output=True, text=True, timeout=180)
        except subprocess.TimeoutExpired:
            return False, "notts did not answer in 180 s; the report may or may not have been delivered"
        except OSError as e:
            return False, f"notts could not be started: {e}"
        out = _answer(r.stdout)
        if r.returncode == 0:
            return True, _said(out, "delivered through notts")
        if r.returncode == 3:                           # notts keeps it in its outbox and retries on `notts flush`
            return False, _said(out, "queued by notts, NOT delivered yet (run `notts flush`)")
        return False, f"notts exit {r.returncode}: {_said(out, (r.stderr or r.stdout).strip()[:200] or 'no message')}"
    if via == "notts":
        return False, f"notify via=notts but {cmd!r} is not on PATH"
    if not urls:
        return False, "nowhere to send: put Apprise URLs in ~/.config/judged/notify or install notts"
    try:
        ok = apprise_send(urls, title, body, attach=str(report_path))
    except Exception as e:                              # noqa: BLE001 - a broken URL must be said, not crash the audit
        return False, f"apprise failed: {type(e).__name__}: {e}"
    return ok, "delivered through apprise" if ok else "apprise reported a failure for at least one URL"
