"""What AI coding agents may do here: Claude Code settings, MCP servers, instruction files, provider keys (judged/agentchecks/, one file per audit)."""
from .. import agentchecks

NAME, ORDER = "agents", 14
SPEC = {"agents": ((), {"enabled": "bool", "repos": "list", "skip": "list", "mcp_accept": "list"}, "section")}
DEFAULTS = {"agents": {"enabled": True, "repos": [], "skip": [], "mcp_accept": []}}
DOC = {"agents": "enabled = run the audits in judged/agentchecks; repos = folder globs whose project settings, .mcp.json, instruction files and .env files are read "
                 "(your home files are always read); skip = audit names to leave out (claude, mcp, instructions, envkeys); "
                 "mcp_accept = MCP server names you approved: when the list is not empty, any other server is a warning"}


def run(cfg, ctx):
    a = cfg.get("agents")
    if not a or not a.get("enabled", True):
        return []
    return agentchecks.run_all(a)
