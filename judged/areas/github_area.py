"""GitHub account hygiene (gh api, metadata only)."""
from .. import github

NAME, ORDER = "github", 35
SPEC = {"github": ((), {"enabled": "bool", "owner": "str", "skip": "list", "max_repos": "int", "token_warn_days": "int", "deploy_key_max_age_days": "int",
                        "secret_max_age_days": "int", "deploy_keys_accept": "list"}, "section")}
DEFAULTS = {"github": {"enabled": False, "owner": "", "skip": [], "max_repos": 100, "token_warn_days": 14, "deploy_key_max_age_days": 365, "secret_max_age_days": 365,
                       "deploy_keys_accept": []}}
DOC = {"github": "enabled = ask GitHub through `gh api` (needs `gh auth login`; metadata only, secret values are never read); owner = user or organisation (empty = the logged-in user); "
                 "skip = repository names or globs; deploy_keys_accept = repo/title of keys that may stay read-write or old; token_warn_days, deploy_key_max_age_days, secret_max_age_days = limits"}


def run(cfg, ctx):
    g = cfg.get("github")
    if not g or not g.get("enabled", True):
        return []
    return github.github_check(g)
