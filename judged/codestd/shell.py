"""Shell scripts through shellcheck: quoting, unset variables and the other things that break a script on the first odd file name."""
import re

NAME = "shell"
DOC = "shell scripts (shellcheck)"
TOOL = "shellcheck"
EXTS = (".sh", ".bash")
LINE = re.compile(r"^(.+?):(\d+):\d+: (?:warning|error|note): .*\[(SC\d+)\]$")


def command(files, cfg):
    return ["shellcheck", "-f", "gcc", *files]


def parse(rc, out, err):
    rows = [(m.group(3), m.group(1), int(m.group(2))) for m in map(LINE.match, out.splitlines()) if m]
    if not rows and rc not in (0, 1):
        return None
    return rows
