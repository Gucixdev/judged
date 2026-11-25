"""MCP server configs: ~/.claude.json (global and per project), ~/.cursor/mcp.json, and in every repo .mcp.json, .cursor/mcp.json and
.vscode/mcp.json. An MCP server is code the agent runs or a service it sends your data to, so each one is read like a dependency."""
import re

from . import M_AGENTS, load_json, repos, verdict
from ..controls import Result

NAME, ORDER = "mcp", 20
RUNNERS = {"npx", "bunx", "uvx", "pipx", "pnpm", "yarn"}
SECRET_NAME = re.compile(r"(KEY|TOKEN|SECRET|PASSWORD|PASSWD|AUTH|CREDENTIAL)", re.I)
PINNED = re.compile(r"^(@[^/@\s]+/)?[^/@\s]+@(?!latest$|\*$|next$)[\w.\-+^~<>=]+$|^[^@]+==\S+$|^git\+\S+@\S+$")
LOCAL_HOST = re.compile(r"^https?://(localhost|127\.0\.0\.1|\[::1\])(:|/|$)", re.I)
FETCH_PIPE = re.compile(r"(curl|wget)[^|;&]*\|\s*(sudo\s+)?(ba|z)?sh\b")


def literal(v) -> bool:
    if not isinstance(v, str):
        return False
    v = v.split(" ", 1)[1] if v.lower().startswith(("bearer ", "token ", "basic ")) and " " in v else v
    return len(v) >= 8 and not v.startswith("$") and "${" not in v and not v.startswith("<")


def package_arg(cmd: str, args: list):
    """The package a runner will fetch: the first argument that is not a flag (pnpm and yarn only fetch after `dlx`)."""
    a = [str(x) for x in args]
    if cmd in ("pnpm", "yarn"):
        a = a[1:] if a and a[0] == "dlx" else []
    return next((x for x in a if not x.startswith("-")), None)


def audit_server(name: str, s: dict) -> list:
    f, cmd = [], str(s.get("command", "")).rsplit("/", 1)[-1]
    if cmd in RUNNERS:
        pkg = package_arg(cmd, s.get("args") or [])
        if pkg and not pkg.startswith((".", "/")) and not PINNED.match(pkg):
            f.append(("warn", f"{name}: {cmd} fetches {pkg} with no fixed version, so what runs changes without you"))
    full = " ".join([str(s.get("command", ""))] + [str(x) for x in s.get("args") or []])
    if FETCH_PIPE.search(full):
        f.append(("fail", f"{name}: the command pipes a download into a shell"))
    url = str(s.get("url", s.get("serverUrl", "")))
    if url.lower().startswith("http://") and not LOCAL_HOST.match(url):
        f.append(("fail", f"{name}: {url.split('?')[0]} is plain http, tokens and data cross the network unencrypted"))
    if "?" in url and re.search(r"[?&](api[_-]?key|token|key|secret)=[^&${]{6,}", url, re.I):
        f.append(("fail", f"{name}: a secret sits in the URL query (value not shown)"))
    for field in ("env", "headers"):
        for k, v in (s.get(field) or {}).items():
            if SECRET_NAME.search(k) and literal(v):
                f.append(("fail", f"{name}: {field} {k} holds a literal secret (value not shown); use ${{VAR}}"))
    return f


def servers_in(data: dict) -> dict:
    out = dict(data.get("mcpServers") or {}) | dict(data.get("servers") or {})
    for proj, pd in (data.get("projects") or {}).items():
        if isinstance(pd, dict):
            out |= {f"{k} ({proj.rstrip('/').rsplit('/', 1)[-1]})": v for k, v in (pd.get("mcpServers") or {}).items()}
    return {k: v for k, v in out.items() if isinstance(v, dict)}


def check(cfg, env) -> list:
    home, out, accept = env.home(), [], cfg.get("mcp_accept")
    files = [(f"{home}/.claude.json", "claude-json"), (f"{home}/.cursor/mcp.json", "cursor")]
    for r in repos(cfg, env):
        n = r.rstrip("/").rsplit("/", 1)[-1]
        files += [(f"{r}/.mcp.json", n), (f"{r}/.cursor/mcp.json", n + "-cursor"), (f"{r}/.vscode/mcp.json", n + "-vscode")]
    for path, label in files:
        data, why = load_json(env, path)
        if why:
            out.append(Result(f"agents.mcp.{label}", f"MCP servers ({label})", "unknown", f"{path} is {why}", M_AGENTS))
            continue
        if not isinstance(data, dict) or not (servers := servers_in(data)):
            continue
        f = [x for n, s in servers.items() for x in audit_server(n, s)]
        if accept:
            f += [("warn", f"{n}: not in mcp_accept, nobody approved this server") for n in servers if n.split(" (")[0] not in accept]
        out.append(verdict(f"agents.mcp.{label}", f"MCP servers ({label})", f, f"{path}: {len(servers)} server(s), versions fixed, no secret in the file"))
    return out
