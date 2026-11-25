"""SPF and DMARC: whether a domain can be spoofed in mail. DKIM needs a selector, so it is not checked here."""
import re
import subprocess

from .controls import M_MAIL, Result


def txt(name: str) -> list | None:
    """TXT strings of a name via dig; quoted chunks of one record are joined. None if dig is missing."""
    try:
        r = subprocess.run(["dig", "+short", "TXT", name], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if r.returncode != 0:               # dig: 9 = no servers reachable, 10 = internal error; an empty answer alone is exit 0
        return None
    return ["".join(re.findall(r'"([^"]*)"', line)) or line.strip() for line in r.stdout.splitlines() if line.strip()]


def eval_spf(domain: str, records: list | None) -> Result:
    rid, title = f"mail.{domain}.spf", f"{domain} SPF"
    if records is None:
        return Result(rid, title, "unknown", "DNS lookup failed (dig missing or no resolver reachable)", M_MAIL)
    spf = [r for r in records if r.lower().startswith("v=spf1")]
    if not spf:
        return Result(rid, title, "fail", "no SPF record", M_MAIL)
    if len(spf) > 1:
        return Result(rid, title, "fail", "several SPF records (invalid, receivers return permerror)", M_MAIL)
    m = re.search(r"([-~?+]?)all\b", spf[0])
    if not m:
        return Result(rid, title, "warn" if "redirect=" in spf[0] else "fail",
                      "redirect= (target not followed here)" if "redirect=" in spf[0] else "no 'all' mechanism", M_MAIL)
    q = m.group(1)
    st = {"-": "pass", "~": "warn", "?": "fail", "+": "fail"}.get(q, "fail")
    return Result(rid, title, st, {"-": "-all (hard fail)", "~": "~all (soft fail: spoofed mail is only flagged)",
                                   "?": "?all (neutral: no protection)", "+": "+all (anyone may send)"}.get(q, "bare all = +all (anyone may send)"), M_MAIL)


def eval_dmarc(domain: str, records: list | None) -> Result:
    rid, title = f"mail.{domain}.dmarc", f"{domain} DMARC"
    if records is None:
        return Result(rid, title, "unknown", "DNS lookup failed (dig missing or no resolver reachable)", M_MAIL)
    dm = [r for r in records if r.lower().startswith("v=dmarc1")]
    if not dm:
        return Result(rid, title, "fail", "no DMARC record at _dmarc." + domain, M_MAIL)
    tags = dict(t.strip().split("=", 1) for t in dm[0].split(";") if "=" in t)
    p = tags.get("p", "").lower()
    rua = "with reports (rua)" if "rua" in tags else "no aggregate reports (rua)"
    if p in ("reject", "quarantine"):
        return Result(rid, title, "pass", f"p={p}, {rua}", M_MAIL)
    return Result(rid, title, "warn", f"p={p or 'missing'}: monitoring only, spoofed mail is still delivered ({rua})", M_MAIL)


def mail(domain: str) -> list:
    return [eval_spf(domain, txt(domain)), eval_dmarc(domain, txt("_dmarc." + domain))]
