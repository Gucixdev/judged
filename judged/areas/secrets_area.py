"""Secrets and identity leaks in repositories and folders."""
import glob
from pathlib import Path

from .. import secrets
from ..secrets import M_SECRETS
from ..controls import Result

NAME, ORDER = "secrets", 30


def run(cfg, ctx):
    sc, out = cfg.get("secrets", {}), []
    for pat in sc.get("repos", []):
        for r in sorted(glob.glob(str(Path(pat).expanduser()))):
            out += secrets.repo_check(r, sc.get("history", False), extra_terms=sc.get("extra_terms"), entropy=sc.get("entropy", True), max_file_mb=sc.get("max_file_mb", 1),
                                emails=sc.get("emails", True), email_accept=sc.get("email_accept"))
    for pth in sc.get("scan_paths", []):
        out += secrets.path_check(pth)
    skipped = []
    secrets.identity_terms(skipped, sc.get("extra_terms"))
    if sc.get("repos") and skipped:
        out.append(Result("secrets.identity.coverage", "owner identity detection", "warn",
                          "identity scan is partly off: " + "; ".join(skipped) + ". Set [secrets] extra_terms to cover it", M_SECRETS))
    return out
