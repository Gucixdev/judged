"""Coding standards on source folders (judged/codestd/): MISRA C, CERT C, shellcheck. A miss is a warning, the team decides."""
from .. import codestd

NAME, ORDER = "codestd", 90
SPEC = {"codestd": ((), {"enabled": "bool", "repos": "list", "skip": "list", "misra_rules": "str", "max_files": "int", "timeout": "int"}, "section")}
DEFAULTS = {"codestd": {"enabled": False, "repos": [], "skip": [], "misra_rules": "", "max_files": 300, "timeout": 300}}
DOC = {"codestd": "enabled = run the standard checkers in judged/codestd on the folders in repos (slow on big trees); skip = standard names to leave out "
                  "(misra-c, cert-c, shell); misra_rules = your own copy of the MISRA rule-text file (the text is MISRA's, not shipped); "
                  "max_files = files per standard and folder; a finding is a warning, never a failure"}


def run(cfg, ctx):
    c = cfg.get("codestd")
    if not c or not c.get("enabled", False):
        return []
    return codestd.run_all(c)
