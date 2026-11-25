"""Severity and fixed version of a known vulnerability, from the OSV record of one id (the batch query lists ids only).

Severity: the database's own label when it has one (GitHub advisories: LOW, MODERATE, HIGH, CRITICAL), else the CVSS v3 base score computed from
the vector (FIRST specification v3.1, scale 0.1-3.9 low, 4-6.9 medium, 7-8.9 high, 9+ critical), else "unrated". CVSS v4 vectors are not scored here:
they are reported as "unrated (CVSS v4)", never guessed. Fixed version: the lowest `fixed` event above the installed version in the entry for
exactly this package; the comparison is loose (numbers only), so it is a hint, said as such."""
import math
import re

AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
AC = {"L": 0.77, "H": 0.44}
UI = {"N": 0.85, "R": 0.62}
CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
PR = {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}}


def roundup(x: float) -> float:
    """CVSS 3.1 Roundup: the smallest number with one decimal that is not below x, immune to floating point noise."""
    n = round(x * 100000)
    return n / 100000.0 if n % 10000 == 0 else (math.floor(n / 10000) + 1) / 10.0


def cvss3(vector: str) -> float | None:
    """Base score of a CVSS:3.0 or CVSS:3.1 vector, None when the vector is not one of those or is incomplete."""
    m = dict(p.split(":", 1) for p in vector.split("/") if ":" in p)
    if m.get("CVSS") not in ("3.0", "3.1"):
        return None
    try:
        s = m["S"]
        iss = 1 - (1 - CIA[m["C"]]) * (1 - CIA[m["I"]]) * (1 - CIA[m["A"]])
        impact = 6.42 * iss if s == "U" else 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        expl = 8.22 * AV[m["AV"]] * AC[m["AC"]] * PR[s][m["PR"]] * UI[m["UI"]]
    except KeyError:
        return None
    if impact <= 0:
        return 0.0
    return roundup(min(impact + expl, 10)) if s == "U" else roundup(min(1.08 * (impact + expl), 10))


def band(score: float) -> str:
    return "CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW" if score > 0 else "NONE"


def severity(rec: dict) -> tuple:
    """(label, score or None). label: CRITICAL | HIGH | MEDIUM | LOW | NONE | UNRATED."""
    lab = str((rec.get("database_specific") or {}).get("severity", "")).upper().replace("MODERATE", "MEDIUM")
    score = None
    for s in rec.get("severity") or []:
        v = str(s.get("score", ""))
        if s.get("type", "").startswith("CVSS_V3") or v.startswith("CVSS:3"):
            score = cvss3(v)
            if score is not None:
                break
    if lab in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        return lab, score
    if score is not None:
        return band(score), score
    v4 = any(str(s.get("score", "")).startswith("CVSS:4") for s in rec.get("severity") or [])
    return ("UNRATED (CVSS v4)" if v4 else "UNRATED"), None


def _key(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v))


def fixed_hint(rec: dict, eco: str, name: str, installed: str) -> str | None:
    """Lowest fixed version above `installed` among the entries for exactly this package; None when the record lists no fix."""
    fixes = []
    for a in rec.get("affected") or []:
        p = a.get("package") or {}
        if p.get("ecosystem") != eco or p.get("name") != name:
            continue
        for r in a.get("ranges") or []:
            fixes += [e["fixed"] for e in r.get("events", []) if "fixed" in e]
    if not fixes:
        return None
    have = _key(installed)
    above = sorted((f for f in fixes if _key(f) > have), key=_key)
    return above[0] if above else None


def details(hit: dict, get, limit: int = 40, aliases: dict | None = None) -> dict:
    """{(eco, name, ver): [(id, label, score, fixed)]} for the first `limit` distinct ids; an id that cannot be fetched is UNRATED with no fix."""
    cache, out = {}, {}
    for pkg, ids in hit.items():
        rows = []
        for i in ids:
            if i not in cache:
                if len(cache) >= limit:
                    cache[i] = None
                else:
                    try:
                        cache[i] = get(f"https://api.osv.dev/v1/vulns/{i}")
                    except (OSError, ValueError):
                        cache[i] = None
            rec = cache[i]
            if not isinstance(rec, dict) or "id" not in rec and "severity" not in rec and "affected" not in rec:
                rows.append((i, "UNRATED", None, None))
                continue
            if aliases is not None:
                aliases[i] = {x for x in [rec.get("id", i), *(rec.get("aliases") or [])] if str(x).startswith("CVE-")}
            lab, score = severity(rec)
            rows.append((i, lab, score, fixed_hint(rec, *pkg)))
        out[pkg] = rows
    return out
