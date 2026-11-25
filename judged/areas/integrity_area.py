"""File integrity baseline of chosen folders."""
from .. import integrity

NAME, ORDER = "integrity", 65
SPEC = {"integrity": ((), {"enabled": "bool", "paths": "list", "exclude": "list", "max_filesize_mb": "int", "max_files": "int", "baseline": "str"}, "section")}
DEFAULTS = {"integrity": {"enabled": False, "paths": [], "exclude": [], "max_filesize_mb": 100, "max_files": 200000, "baseline": ""}}
DOC = {"integrity": "enabled = compare paths with the baseline made by `judged integrity init`; exclude = globs (names or paths) to skip; "
                    "baseline = file for the manifest (empty = in judged's state folder); files over max_filesize_mb are not hashed (said in the report)"}


def run(cfg, ctx):
    c = cfg.get("integrity")
    if not c or not c.get("enabled", True):
        return []
    return integrity.integrity_check(c, ctx.state)
