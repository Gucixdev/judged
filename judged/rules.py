"""Your own rules, no code: a `check` line in judged.conf (or in a file it includes, e.g. rules/backup.rules) runs a
command. Exit 0 = pass, 1 = fail, `warn_exit` (default 2) = warn, anything else, a timeout or a missing program =
unknown. The first line it prints is the evidence. `maps=` ties the result to framework controls."""
import subprocess

from .controls import Result


def run(c: dict, runner=subprocess.run) -> Result:
    rid, title = "rule." + c["name"].lower().replace(" ", "-"), c["name"]
    maps = c.get("maps", {})
    try:
        r = runner(c["cmd"], capture_output=True, text=True, timeout=c.get("timeout", 30))
    except subprocess.TimeoutExpired:
        return Result(rid, title, "unknown", f"timed out after {c.get('timeout', 30)} s", maps)
    except OSError as e:
        return Result(rid, title, "unknown", f"cannot run {c['cmd'][0]}: {e}", maps)
    lines = (r.stdout or r.stderr).strip().splitlines()
    ev = lines[0][:200] if lines else f"exit {r.returncode}"
    status = {0: "pass", 1: "fail"}.get(r.returncode, "warn" if r.returncode == c.get("warn_exit", 2) else "unknown")
    return Result(rid, title, status, ev if status != "unknown" else f"exit {r.returncode}: {ev}", maps)
