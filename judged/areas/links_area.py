"""Symlinks, broken symlinks and hardlinks (report only)."""
from .. import links

NAME, ORDER = "links", 66
SPEC = {"links": ((), {"enabled": "bool", "paths": "list", "exclude": "list", "max_files": "int"}, "section")}
DEFAULTS = {"links": {"enabled": False, "paths": [], "exclude": [], "max_files": 200000}}
DOC = {"links": "enabled = scan paths for broken symlinks, links into /tmp and setuid files with several names; exclude = globs to skip; "
                "judged only reports, it never repairs or removes a link"}


def run(cfg, ctx):
    c = cfg.get("links")
    if not c or not c.get("enabled", True):
        return []
    return links.links_check(c)
