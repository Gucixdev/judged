"""GitHub account hygiene through `gh api`: metadata only, never a secret value.

Checks: the token that judged itself uses (expiry, broad scopes), open secret-scanning alerts, deploy keys (read-write, old), Actions secrets
(names and age: a secret nobody rotated in a year). A repository where an endpoint answers 403/404 is counted as not checked, never as clean."""
import fnmatch
import json
import subprocess
from datetime import datetime, timezone

from .controls import Result
from .secrets import M_SECRETS

BROAD_SCOPES = {"delete_repo", "admin:org", "admin:public_key", "admin:repo_hook", "admin:org_hook", "admin:gpg_key", "site_admin", "admin:enterprise"}


def _run(cmd, timeout=40):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout
    except (OSError, subprocess.TimeoutExpired):
        return None, ""


def _json(out):
    try:
        return json.loads(out)
    except ValueError:
        return None


def _when(s):
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def _days(s, now):
    t = _when(s)
    return None if t is None else (now - t).days


def _api(run, path):
    """(data, why): data is parsed JSON or None; why says what went wrong in words."""
    rc, out = run(["gh", "api", path])
    if rc is None:
        return None, "gh did not answer (not installed, or took too long)"
    data = _json(out) if out.strip() else None
    if rc != 0:
        msg = data.get("message") if isinstance(data, dict) else ""
        return None, (msg or "the request failed")[:90]
    if isinstance(data, (list, dict)):
        return data, ""
    return None, "unreadable answer"


def token_check(run, now, warn_days=14):
    rc, out = run(["gh", "api", "-i", "user"])
    if rc is None or not out:
        return Result("github.token", "GitHub token", "unknown", "gh is not installed, not logged in or did not answer: nothing about GitHub was checked", M_SECRETS)
    head = {}
    for line in out.split("\n\n", 1)[0].splitlines()[1:]:
        k, _, v = line.partition(":")
        head[k.strip().lower()] = v.strip()
    if rc != 0 or not out.startswith("HTTP/"):
        return Result("github.token", "GitHub token", "unknown", "gh is not logged in (or GitHub refused the token): nothing about GitHub was checked", M_SECRETS)
    scopes = [s.strip() for s in head.get("x-oauth-scopes", "").split(",") if s.strip()]
    broad = sorted(set(scopes) & BROAD_SCOPES)
    exp = head.get("github-authentication-token-expiration", "")
    left = None
    if exp:
        t = _when(exp.replace(" UTC", "+00:00").replace(" ", "T", 1))
        left = None if t is None else (t - now).days
    note = f"scopes: {', '.join(scopes) or 'none listed (fine-grained or app token)'}"
    if left is None:
        return Result("github.token", "GitHub token", "warn", f"the token judged uses has no expiry date ({note}): a token that never expires is a standing risk, give it an end date"
                      + (f"; it can also {', '.join(broad)}, which a fine-grained token would not need" if broad else ""), M_SECRETS)
    if left <= warn_days:
        return Result("github.token", "GitHub token", "warn", f"the token expires in {max(left, 0)} days ({exp}); {note}", M_SECRETS)
    if broad:
        return Result("github.token", "GitHub token", "warn", f"the token expires in {left} days but can do dangerous things: {', '.join(broad)}", M_SECRETS)
    return Result("github.token", "GitHub token", "pass", f"expires in {left} days; {note}", M_SECRETS)


def repos(run, owner, skip, max_repos):
    """(list of full names, counts of skipped, error)."""
    cmd = ["gh", "repo", "list"] + ([owner] if owner else []) + ["--limit", "1000", "--json", "nameWithOwner,isFork,isArchived,isPrivate"]
    rc, out = run(cmd)
    data = _json(out) if rc == 0 else None
    if not isinstance(data, list):
        return [], {}, "could not list repositories"
    keep, skipped = [], {"forks": 0, "archived": 0, "in skip": 0, "over max_repos": 0}
    for r in data:
        n = r.get("nameWithOwner", "")
        if r.get("isFork"):
            skipped["forks"] += 1
        elif r.get("isArchived"):
            skipped["archived"] += 1
        elif any(fnmatch.fnmatch(n, g) or fnmatch.fnmatch(n.split("/")[-1], g) for g in skip):
            skipped["in skip"] += 1
        elif len(keep) >= max_repos:
            skipped["over max_repos"] += 1
        else:
            keep.append((n, bool(r.get("isPrivate"))))
    return keep, {k: v for k, v in skipped.items() if v}, ""


def _brief(items, n=6):
    return ", ".join(items[:n]) + (f" (+{len(items) - n} more)" if len(items) > n else "")


def github_check(cfg: dict, run=_run, now: datetime | None = None) -> list:
    now = now or datetime.now(timezone.utc)
    out = [token_check(run, now, cfg.get("token_warn_days", 14))]
    if out[0].status == "unknown":
        return out
    rs, skipped, err = repos(run, cfg.get("owner", ""), cfg.get("skip", []), cfg.get("max_repos", 100))
    if err:
        return out + [Result("github.repos", "GitHub repositories", "unknown", err + ": nothing below was checked", M_SECRETS)]
    alerts, off, keys_rw, keys_old, sec_old, gaps, scanned = [], [], [], [], [], [], 0
    accept = set(cfg.get("deploy_keys_accept", []))
    key_days, sec_days = cfg.get("deploy_key_max_age_days", 365), cfg.get("secret_max_age_days", 365)
    for name, private in rs:
        a, why = _api(run, f"repos/{name}/secret-scanning/alerts?state=open&per_page=100")
        if a is None and "disabled" in why.lower():
            off.append((name, private))
        elif a is None:
            gaps.append(f"{name} alerts ({why})")
        else:
            scanned += 1
            alerts += [f"{name}#{x.get('number')} {x.get('secret_type_display_name') or x.get('secret_type') or 'secret'}" for x in a if isinstance(x, dict)]
        k, why = _api(run, f"repos/{name}/keys?per_page=100")
        if k is None:
            gaps.append(f"{name} deploy keys ({why})")
        else:
            for x in k if isinstance(k, list) else []:
                label, age = f"{name}/{x.get('title')}", _days(x.get("created_at"), now)
                if not x.get("read_only", True) and label not in accept:
                    keys_rw.append(label)
                if age is not None and age > key_days and label not in accept:
                    keys_old.append(f"{label} ({age} days)")
        s, why = _api(run, f"repos/{name}/actions/secrets?per_page=100")
        if s is None:
            gaps.append(f"{name} Actions secrets ({why})")
        else:
            for x in (s.get("secrets", []) if isinstance(s, dict) else []):
                age = _days(x.get("updated_at"), now)
                if age is not None and age > sec_days:
                    sec_old.append(f"{name}:{x.get('name')} ({age} days)")
    sk = ("; skipped " + ", ".join(f"{v} {k}" for k, v in skipped.items())) if skipped else ""
    out.append(Result("github.alerts", "GitHub secret-scanning alerts", "fail" if alerts else "pass",
                      (f"{len(alerts)} open: {_brief(alerts)}. A secret GitHub found is burnt: revoke it at the provider, then close the alert" if alerts
                       else f"no open alerts in {scanned} of {len(rs)} repositories") + sk, M_SECRETS))
    if off:
        out.append(Result("github.alerts_off", "GitHub secret scanning switched off", "warn", f"{len(off)} repositories have no secret scanning (nobody is told when a token is pushed): {_brief([n for n, _ in off])}"
                      + (f". {sum(p for _, p in off)} of them are private, where it needs GitHub Advanced Security (paid)" if any(p for _, p in off) else ""), M_SECRETS))
    out.append(Result("github.deploy_keys", "GitHub deploy keys", "warn" if keys_rw or keys_old else "pass",
                      "; ".join(x for x in [f"read-write keys: {_brief(keys_rw)}" if keys_rw else "", f"older than {key_days} days: {_brief(keys_old)}" if keys_old else ""] if x)
                      + (". Read-only is enough to deploy; list a key in deploy_keys_accept when it is meant to stay" if keys_rw or keys_old else f"none read-write or older than {key_days} days"), M_SECRETS))
    out.append(Result("github.actions_secrets", "GitHub Actions secrets", "warn" if sec_old else "pass",
                      f"not rotated for over {sec_days} days: {_brief(sec_old)} (names only, values are never readable)" if sec_old else f"every Actions secret was set within {sec_days} days (names and dates only)", M_SECRETS))
    if gaps:
        out.append(Result("github.coverage", "GitHub coverage", "unknown", f"{len(gaps)} requests were refused or failed, so these were not checked: {_brief(gaps)}", M_SECRETS))
    return out
