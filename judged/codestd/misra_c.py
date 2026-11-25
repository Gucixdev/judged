"""MISRA C:2012 through the cppcheck addon. The addon prints rule numbers; the rule wording is MISRA's paid text, so it is only shown
when `misra_rules` points at the user's own copy of the rule-text file."""
import json
import re

NAME = "misra-c"
DOC = "MISRA C:2012 (cppcheck addon)"
TOOL = "cppcheck"
EXTS = (".c", ".h")
LINE = re.compile(r"^(.+?):(\d+):(?:\d+:)?(misra-c\d+-[\w.]+):")


def command(files, cfg):
    addon = {"script": "misra.py", "args": [f"--rule-texts={cfg['misra_rules']}"] if cfg.get("misra_rules") else []}
    return ["cppcheck", "--quiet", "--template={file}:{line}:{column}:{id}:{message}", "--addon=" + json.dumps(addon), *files]


def parse(rc, out, err):
    rows = [(m.group(3), m.group(1), int(m.group(2))) for m in map(LINE.match, (out + "\n" + err).splitlines()) if m]
    if not rows and rc not in (0, None) and "misra" not in err.lower() and err.strip():
        return None
    return rows
