"""Claude Code settings: permission mode, allow rules, hooks, env. User files and, for every repo in `repos`, the project files."""
import re

from . import M_AGENTS, load_json, repos, verdict
from ..controls import Result

NAME, ORDER = "claude", 10
SECRET_NAME = re.compile(r"(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)", re.I)
RISKY_CMD = ("curl", "wget", "sudo", "ssh", "scp", "nc", "ncat", "eval", "sh", "bash", "zsh", "python", "python3", "node", "npx", "rm", "dd", "chmod", "git push")
FETCH_PIPE = re.compile(r"(curl|wget)[^|;&]*\|\s*(sudo\s+)?(ba|z)?sh\b")


def literal(v) -> bool:
    return isinstance(v, str) and len(v) >= 8 and not v.startswith("$") and "${" not in v and v.lower() not in ("changeme", "xxx", "your-key-here")


def audit(data: dict, project: bool) -> list:
    f, perm = [], data.get("permissions") or {}
    mode = perm.get("defaultMode")
    if mode == "bypassPermissions":
        f.append(("fail", "defaultMode bypassPermissions: every tool runs without asking"))
    elif mode in ("auto", "dontAsk"):
        f.append(("warn", f"defaultMode {mode}: tools run without a prompt, only a classifier or the allow list stands in the way"))
    if data.get("skipDangerousModePermissionPrompt"):
        f.append(("warn", "skipDangerousModePermissionPrompt: the warning before bypass mode is switched off"))
    if data.get("enableAllProjectMcpServers"):
        f.append(("fail", "enableAllProjectMcpServers: any .mcp.json in any repo starts without approval"))
    for rule in perm.get("allow") or []:
        r = str(rule).strip()
        if r in ("*", "Bash", "Bash(*)", "Bash(:*)"):
            f.append(("fail", f"allow rule {r!r} permits every shell command"))
        elif any(r.startswith(f"Bash({c} ") or r.startswith(f"Bash({c}:") for c in RISKY_CMD) and ("*" in r):
            f.append(("warn", f"allow rule {r!r} lets the agent run arbitrary arguments of a command that can fetch, run or destroy"))
    hooks = data.get("hooks") or {}
    cmds = [h.get("command", "") for evs in hooks.values() if isinstance(evs, list) for e in evs if isinstance(e, dict)
            for h in (e.get("hooks") or []) if isinstance(h, dict)]
    if project and cmds:
        f.append(("warn", f"{len(cmds)} hook command(s) defined by the repository: they run on your machine when the repo is opened"))
    for c in cmds:
        if FETCH_PIPE.search(c or ""):
            f.append(("fail", "a hook pipes a download into a shell"))
    for k, v in (data.get("env") or {}).items():
        if SECRET_NAME.search(k) and literal(v):
            f.append(("fail", f"env {k} holds a literal secret (value not shown); reference an environment variable instead"))
    return f


def check(cfg, env) -> list:
    home, out = env.home(), []
    files = [(f"{home}/.claude/settings.json", False, "user"), (f"{home}/.claude/settings.local.json", False, "user-local")]
    for r in repos(cfg, env):
        name = r.rstrip("/").rsplit("/", 1)[-1]
        files += [(f"{r}/.claude/settings.json", True, name), (f"{r}/.claude/settings.local.json", True, name + "-local")]
    for path, project, label in files:
        data, why = load_json(env, path)
        if why:
            out.append(Result(f"agents.claude.{label}", f"Claude Code settings ({label})", "unknown", f"{path} is {why}", M_AGENTS))
        elif isinstance(data, dict):
            out.append(verdict(f"agents.claude.{label}", f"Claude Code settings ({label})", audit(data, project), f"{path}: no risky setting found"))
    return out
