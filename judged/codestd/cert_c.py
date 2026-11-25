"""SEI CERT C rules through clang-tidy's cert-* checks."""
import re

NAME = "cert-c"
DOC = "SEI CERT C (clang-tidy cert-*)"
TOOL = "clang-tidy"
EXTS = (".c",)
LINE = re.compile(r"^(.+?):(\d+):\d+: (?:warning|error): .*\[([\w.,-]*cert-[\w.-]+)[\w.,-]*\]$")


def command(files, cfg):
    return ["clang-tidy", "--quiet", "--checks=-*,cert-*", *files, "--", "-std=c11"]


def parse(rc, out, err):
    rows = [(m.group(3).split(",")[0], m.group(1), int(m.group(2))) for m in map(LINE.match, out.splitlines()) if m]
    if not rows and rc not in (0, None) and "error:" in (out + err):
        return None if "cert-" not in out else rows
    return rows
