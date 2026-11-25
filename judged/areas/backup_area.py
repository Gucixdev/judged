"""Backup evidence (restic, borg or a plain folder)."""
from .. import backup, backups

NAME, ORDER = "backup", 62
SPEC = {"backup": ((), {"enabled": "bool", "tool": "str", "repo": "str", "password_file": "str", "max_age_hours": "int", "must_include": "list",
                        "restore_tested": "str", "restore_tested_file": "str", "restore_max_age_days": "int"}, "section")}
DEFAULTS = {"backup": {"enabled": False, "tool": "folder", "repo": "", "password_file": "", "max_age_hours": 36, "must_include": [], "restore_tested": "", "restore_tested_file": "", "restore_max_age_days": 365}}
DOC = {"backup": "enabled = check the newest backup; tool = " + "/".join(["folder", "restic", "borg"]) + " (one file each in judged/backups); repo = path or URL; "
                 "password_file = restic password file (borg: set BORG_PASSCOMMAND in the environment); must_include = folders the newest backup must hold (restic only); "
                 "restore_tested = date of your last restore test YYYY-MM-DD; restore_tested_file = a file whose first word is that date, written by the tool that did the restore test (the newer date counts)"}


def run(cfg, ctx):
    b = cfg.get("backup")
    if not b or not b.get("enabled", True):
        return []
    return backup.backup_check(b, ctx.today)
