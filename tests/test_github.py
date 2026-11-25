import json
from datetime import datetime, timezone

from judged import github

NOW = datetime(2026, 11, 24, 12, 0, tzinfo=timezone.utc)
SECRET_VALUE = "SUPERSECRETVALUE9f8e7d6c5b4a"


def head(expiry="", scopes="repo, read:org"):
    h = "HTTP/2.0 200 OK\nServer: GitHub.com\nX-Oauth-Scopes: " + scopes + "\n"
    if expiry:
        h += f"Github-Authentication-Token-Expiration: {expiry}\n"
    return h + "\n" + json.dumps({"login": "me"})


class Gh:
    """A fake `gh`: answers by the API path, records every call."""
    def __init__(self, user=None, repos=None, alerts=None, keys=None, secrets=None):
        self.user = head("2027-01-01 00:00:00 UTC") if user is None else user      # False = gh is not installed
        self.repos = repos if repos is not None else [{"nameWithOwner": "me/a", "isFork": False, "isArchived": False, "isPrivate": False}]
        self.alerts, self.keys, self.secrets, self.calls = alerts or {}, keys or {}, secrets or {}, []

    def __call__(self, cmd, timeout=40):
        self.calls.append(cmd)
        if cmd[:3] == ["gh", "api", "-i"]:
            return (None, "") if self.user is False else (0, self.user)
        if cmd[:3] == ["gh", "repo", "list"]:
            return (0, json.dumps(self.repos)) if self.repos != "fail" else (1, "")
        path = cmd[2]
        repo = path.split("/")[1] + "/" + path.split("/")[2]
        table = self.alerts if "secret-scanning" in path else self.keys if path.split("?")[0].endswith("/keys") else self.secrets
        ans = table.get(repo, [] if "secret-scanning" in path or path.endswith("100") and "/keys" in path else {"secrets": []})
        if isinstance(ans, tuple):
            return 1, json.dumps({"message": ans[0]})
        return 0, json.dumps(ans)


def by_id(res):
    return {r.id.split(".", 1)[1]: r for r in res}


def test_clean_account_passes_everything():
    r = by_id(github.github_check({}, Gh(), NOW))
    assert {k: v.status for k, v in r.items()} == {"token": "pass", "alerts": "pass", "deploy_keys": "pass", "actions_secrets": "pass"}
    assert "expires in 37 days" in r["token"].evidence and "scopes: repo, read:org" in r["token"].evidence
    assert "no open alerts in 1 of 1 repositories" in r["alerts"].evidence


def test_open_alert_fails_and_never_shows_the_secret():
    gh = Gh(alerts={"me/a": [{"number": 7, "secret_type_display_name": "GitHub Personal Access Token", "secret": SECRET_VALUE}]})
    r = by_id(github.github_check({}, gh, NOW))
    assert r["alerts"].status == "fail" and "me/a#7 GitHub Personal Access Token" in r["alerts"].evidence and "burnt" in r["alerts"].evidence
    assert SECRET_VALUE not in str([x.evidence for x in r.values()])


def test_disabled_scanning_is_a_warning_not_a_clean_bill():
    r = by_id(github.github_check({}, Gh(alerts={"me/a": ("Secret scanning is disabled on this repository.",)}), NOW))
    assert r["alerts_off"].status == "warn" and "me/a" in r["alerts_off"].evidence and "private" not in r["alerts_off"].evidence
    priv = [{"nameWithOwner": "me/p", "isFork": False, "isArchived": False, "isPrivate": True}, {"nameWithOwner": "me/q", "isFork": False, "isArchived": False, "isPrivate": False}]
    off = ("Secret scanning is disabled on this repository.",)
    r2 = by_id(github.github_check({}, Gh(repos=priv, alerts={"me/p": off, "me/q": off}), NOW))["alerts_off"]
    assert "me/p, me/q" in r2.evidence and "1 of them are private" in r2.evidence
    assert r["alerts"].status == "pass" and "no open alerts in 0 of 1" in r["alerts"].evidence


def test_refused_endpoint_is_unknown_coverage():
    r = by_id(github.github_check({}, Gh(keys={"me/a": ("Resource not accessible by personal access token",)}), NOW))
    assert r["coverage"].status == "unknown" and "me/a deploy keys (Resource not accessible" in r["coverage"].evidence


def test_deploy_keys_read_write_and_old():
    keys = {"me/a": [{"title": "ci", "read_only": False, "created_at": "2026-11-01T00:00:00Z"},
                      {"title": "old", "read_only": True, "created_at": "2024-11-24T11:59:59Z"},
                      {"title": "fine", "read_only": True, "created_at": "2026-01-01T00:00:00Z"},
                      {"title": "kept", "read_only": False, "created_at": "2020-01-01T00:00:00Z"}]}
    r = by_id(github.github_check({"deploy_keys_accept": ["me/a/kept"]}, Gh(keys=keys), NOW))["deploy_keys"]
    assert r.status == "warn" and "read-write keys: me/a/ci" in r.evidence and "me/a/old (730 days)" in r.evidence
    assert "fine" not in r.evidence and "kept" not in r.evidence
    assert "me/a/old" not in by_id(github.github_check({"deploy_key_max_age_days": 800}, Gh(keys=keys), NOW))["deploy_keys"].evidence


def test_deploy_key_age_boundary():
    k = lambda created: {"me/a": [{"title": "k", "read_only": True, "created_at": created}]}
    at = by_id(github.github_check({"deploy_key_max_age_days": 365}, Gh(keys=k("2025-11-24T12:00:00Z")), NOW))["deploy_keys"]
    over = by_id(github.github_check({"deploy_key_max_age_days": 365}, Gh(keys=k("2025-11-23T11:00:00Z")), NOW))["deploy_keys"]
    assert at.status == "pass" and over.status == "warn" and "(366 days)" in over.evidence


def test_actions_secrets_report_names_and_age_only():
    s = {"me/a": {"total_count": 2, "secrets": [{"name": "DEPLOY_TOKEN", "created_at": "2023-01-01T00:00:00Z", "updated_at": "2024-01-01T00:00:00Z"},
                                               {"name": "NEW", "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-10-01T00:00:00Z"}]}}
    r = by_id(github.github_check({}, Gh(secrets=s), NOW))["actions_secrets"]
    assert r.status == "warn" and "me/a:DEPLOY_TOKEN (1058 days)" in r.evidence and "NEW" not in r.evidence


def test_token_without_expiry_expiring_soon_and_broad():
    f = lambda u, cfg=None: by_id(github.github_check(cfg or {}, Gh(user=u), NOW))["token"]
    assert f(head("")).status == "warn" and "no expiry date" in f(head("")).evidence and "can also" not in f(head("")).evidence
    assert "can also delete_repo" in f(head("", "repo, delete_repo")).evidence
    soon = f(head("2026-12-08 12:00:00 UTC"))
    assert soon.status == "warn" and "expires in 14 days" in soon.evidence
    assert f(head("2026-12-09 12:00:00 UTC")).status == "pass"
    broad = f(head("2027-06-01 00:00:00 UTC", "repo, delete_repo, admin:org"))
    assert broad.status == "warn" and "admin:org, delete_repo" in broad.evidence
    assert f(head("2026-12-30 00:00:00 UTC"), {"token_warn_days": 60}).status == "warn"


def test_no_gh_or_not_logged_in_is_unknown_and_nothing_else_runs():
    for gh in (Gh(user=False), Gh(user="gh: To get started with GitHub CLI, please run: gh auth login\n")):
        r = github.github_check({}, gh, NOW)
        assert [x.status for x in r] == ["unknown"] and len(gh.calls) == 1


def test_repo_list_failure_is_unknown():
    r = github.github_check({}, Gh(repos="fail"), NOW)
    assert [x.id for x in r] == ["github.token", "github.repos"] and r[1].status == "unknown"


def test_forks_archived_skipped_and_max_repos_are_counted_in_the_evidence():
    repos = [{"nameWithOwner": f"me/{n}", "isFork": f, "isArchived": a, "isPrivate": False}
             for n, f, a in [("a", 0, 0), ("fork", 1, 0), ("old", 0, 1), ("tmp-x", 0, 0), ("b", 0, 0), ("c", 0, 0)]]
    gh = Gh(repos=repos)
    r = by_id(github.github_check({"skip": ["tmp-*"], "max_repos": 2}, gh, NOW))["alerts"]
    assert "no open alerts in 2 of 2" in r.evidence and "skipped 1 forks, 1 archived, 1 in skip, 1 over max_repos" in r.evidence
    assert sorted({c[2].split("/")[1] for c in gh.calls if c[2:3] and c[1] == "api" and c[2].startswith("repos/")}) == ["me"]
    assert len([c for c in gh.calls if "secret-scanning" in c[-1]]) == 2


def test_owner_is_passed_to_gh():
    gh = Gh()
    github.github_check({"owner": "acme"}, gh, NOW)
    assert ["gh", "repo", "list", "acme"] == gh.calls[1][:4]
    gh = Gh()
    github.github_check({}, gh, NOW)
    assert gh.calls[1][:3] == ["gh", "repo", "list"] and gh.calls[1][3] == "--limit"


def test_actions_secret_age_boundary():
    s = lambda upd: {"me/a": {"secrets": [{"name": "K", "updated_at": upd}]}}
    assert by_id(github.github_check({"secret_max_age_days": 365}, Gh(secrets=s("2025-11-24T12:00:00Z")), NOW))["actions_secrets"].status == "pass"
    assert by_id(github.github_check({"secret_max_age_days": 365}, Gh(secrets=s("2025-11-23T11:00:00Z")), NOW))["actions_secrets"].status == "warn"


def test_refused_alerts_endpoint_is_coverage_not_switched_off():
    r = by_id(github.github_check({}, Gh(alerts={"me/a": ("Must have admin rights to Repository.",)}), NOW))
    assert "alerts_off" not in r and r["coverage"].status == "unknown" and "me/a alerts (Must have admin rights" in r["coverage"].evidence
    assert "no open alerts in 0 of 1" in r["alerts"].evidence
