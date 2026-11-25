"""Licences, two meanings. (1) Licences you BUY (software seats, certificates, support contracts): items with an
expiry, a cost and an owner, listed per year so the budget and the renewals are visible a year ahead.
(2) Licences you USE: the licence of every Python dependency, classified and checked against your policy.
The classification is a keyword heuristic and says so: anything it cannot place is `unknown`, never `ok`."""
import re
from importlib import metadata
from pathlib import Path

from .controls import Result

M_LICENCE = {"iso27001": ["A.5.32"]}      # A.5.32 = intellectual property rights (unverified)
RANK = {"permissive": 0, "weak-copyleft": 1, "strong-copyleft": 2, "restricted": 3, "unknown": 4}
# restricted = you may not use it freely in a product: non-commercial, no-derivatives, source-available, proprietary.
KEYWORDS = [   # first match wins: restricted terms beat any family name in the same string, AGPL and LGPL come before GPL
    (r"non-?commercial|(?<![a-z0-9])nc(?![a-z0-9])", "restricted", "non-commercial"),
    (r"no-?deriv|(?<![a-z0-9])nd(?![a-z0-9])", "restricted", "no-derivatives"),
    (r"\bbusl|business source", "restricted", "BUSL"), (r"elastic", "restricted", "Elastic"),
    (r"commons clause", "restricted", "Commons-Clause"), (r"proprietary|all rights reserved", "restricted", "proprietary"),
    (r"\bagpl|affero", "strong-copyleft", "AGPL"), (r"\bsspl\b", "strong-copyleft", "SSPL"),
    (r"\blgpl|lesser general|\blgplr", "weak-copyleft", "LGPL"), (r"\bgpl|general public", "strong-copyleft", "GPL"),
    (r"\bgfdl|free documentation", "strong-copyleft", "GFDL"), (r"\beupl|european union public", "strong-copyleft", "EUPL"),
    (r"\bosl-|open software license", "strong-copyleft", "OSL"), (r"by-sa|share-?alike", "strong-copyleft", "CC-BY-SA"),
    (r"\bmpl|mozilla", "weak-copyleft", "MPL"), (r"\bepl|eclipse public", "weak-copyleft", "EPL"),
    (r"\bcddl|common development", "weak-copyleft", "CDDL"), (r"\bcpl\b|common public", "weak-copyleft", "CPL"),
    (r"\blppl|latex project", "weak-copyleft", "LPPL"),
    (r"apache", "permissive", "Apache-2.0"), (r"\bbsd", "permissive", "BSD"), (r"\bmit\b|mit license", "permissive", "MIT"),
    (r"\bisc\b", "permissive", "ISC"), (r"\bpsf|python software foundation|\bpython-", "permissive", "PSF"),
    (r"artistic", "permissive", "Artistic"), (r"\bbsl-1|boost software", "permissive", "BSL-1.0"),
    (r"\bofl\b|open font", "permissive", "OFL"), (r"unicode", "permissive", "Unicode"), (r"blueoak", "permissive", "BlueOak"),
    (r"hpnd|\bw3c|wtfpl|\bzpl|zope|\bphp-|\bruby\b|fsfap|\bx11\b|\bcurl\b|libpng|\bncsa", "permissive", "permissive-other"),
    (r"cc-by|attribution", "permissive", "CC-BY"),
    (r"unlicense|public domain|\bcc0|\b0bsd|\bzlib|pddc", "permissive", "public-domain-like"),
]
# an exception after WITH that lets you link without the copyleft reaching your program
LINKING_EXCEPTION = re.compile(r"classpath|gcc-exception|linking-exception|linux-syscall-note|autoconf|bison|libtool|font-exception|openjdk-assembly", re.I)
MAX_TEXT, MAX_DEPTH = 1000, 16


def _atom(text: str) -> tuple:
    low = text.strip().lower().rstrip("+")
    for rx, cls, label in KEYWORDS:
        if re.search(rx, low):
            return cls, label
    return "unknown", text.strip()[:40]


def _parse(tokens: list, pos: int, depth: int) -> tuple:
    """SPDX grammar: or := and (OR and)* ; and := atom (AND atom)* ; atom := '(' or ')' | id [WITH exception]. AND binds tighter."""
    if depth > MAX_DEPTH:
        raise ValueError("too deep")
    alts = []
    while True:
        parts = []
        while True:
            if pos >= len(tokens):
                raise ValueError("expression ends early")
            tok = tokens[pos]
            if tok == "(":
                got, pos = _parse(tokens, pos + 1, depth + 1)
                if pos >= len(tokens) or tokens[pos] != ")":
                    raise ValueError("unclosed (")
                pos += 1
            elif tok in (")",) or tok.upper() in ("AND", "OR", "WITH"):
                raise ValueError("operator where an id was expected")
            else:
                got, pos = _atom(tok), pos + 1
                if pos < len(tokens) and tokens[pos].upper() == "WITH":
                    if pos + 1 >= len(tokens):
                        raise ValueError("WITH without an exception")
                    exc = tokens[pos + 1]
                    pos += 2
                    if got[0] in ("strong-copyleft", "weak-copyleft") and LINKING_EXCEPTION.search(exc):
                        got = ("weak-copyleft", got[1] + "-with-exception")
                    else:
                        got = (got[0], got[1] + " WITH " + exc[:30])
            parts.append(got)
            if pos < len(tokens) and tokens[pos].upper() == "AND":
                pos += 1
                continue
            break
        alts.append(max(parts, key=lambda g: RANK[g[0]]))
        if pos < len(tokens) and tokens[pos].upper() == "OR":
            pos += 1
            continue
        return min(alts, key=lambda g: RANK[g[0]]), pos


def _spdx(t: str):
    """Parse an SPDX expression, or None when the text is not one (a licence name in words, unbalanced brackets)."""
    tokens = re.findall(r"\(|\)|[^\s()]+", t)
    try:
        got, pos = _parse(tokens, 0, 0)
    except ValueError:
        return None
    return got if pos == len(tokens) else None


def classify(text: str) -> tuple:
    """(class, label) for a licence string. SPDX expressions are parsed (OR = you may pick the easier side, AND = both bind,
    WITH = exception); words such as 'GNU General Public License v3 or later (GPLv3+)' go through the keyword list."""
    t = (text or "").strip()[:MAX_TEXT]
    if not t or t.upper() in ("UNKNOWN", "NONE"):
        return "unknown", "?"
    got = _spdx(t)
    if got is not None:
        return got
    t = re.sub(r"\b(or|and) (any )?later( version)?\b", "", t, flags=re.I)             # 'v3 or later' is one licence, not two
    for sep, pick in ((r"\s+OR\s+", min), (r"\s+AND\s+", max)):
        parts = [p for p in re.split(sep, t, flags=re.I) if p.strip(" ()")]
        if len(parts) > 1:
            return pick((classify(p.strip(" ()")) for p in parts), key=lambda g: RANK[g[0]])
    return _atom(t)


def dist_licence(d) -> str:
    md = d.metadata
    expr = md.get("License-Expression")
    if expr:
        return expr
    lic = md.get("License") or ""
    if lic and len(lic) < 80 and lic.strip().upper() != "UNKNOWN":          # long values are whole licence texts
        return lic
    cl = [c.split("::")[-1].strip() for c in md.get_all("Classifier") or [] if c.startswith("License ::")]
    return " OR ".join(cl)


def env_check(site: str, deny: list, allow_packages: list) -> Result:
    """site-packages (or any dir of *.dist-info). `deny` = labels such as ["AGPL", "GPL"]; `allow_packages` = reviewed exceptions."""
    name = Path(site).parent.parent.parent.name if "site-packages" in site else Path(site).name
    rid = f"licences.{name.lstrip('.')}"
    try:
        dists = list(metadata.distributions(path=[str(Path(site).expanduser())]))
    except OSError as e:
        return Result(rid, f"{name} dependency licences", "unknown", f"cannot read {site}: {e}", M_LICENCE)
    by, unknown, denied = {}, [], []
    for d in dists:
        pkg = (d.metadata.get("Name") or "?").lower()
        if pkg in allow_packages:
            continue
        cls, label = classify(dist_licence(d))
        by.setdefault(cls, []).append(f"{pkg} ({label})")
        if cls == "unknown":
            unknown.append(pkg)
        if label in deny:
            denied.append(f"{pkg} ({label})")
    summary = ", ".join(f"{len(v)} {k}" for k, v in sorted(by.items(), key=lambda kv: RANK[kv[0]]))
    if denied:
        return Result(rid, f"{name} dependency licences", "fail", f"denied by policy: {', '.join(denied[:6])}. {summary}", M_LICENCE)
    flagged = by.get("restricted", []) + by.get("strong-copyleft", [])
    if flagged or unknown:
        ev = (f"review: {', '.join(flagged[:6])}. " if flagged else "") + (f"unknown: {', '.join(unknown[:6])}. " if unknown else "")
        return Result(rid, f"{name} dependency licences", "warn", ev + summary
                      + ". Copyleft matters only if you distribute the result; unknown means no licence text found", M_LICENCE)
    return Result(rid, f"{name} dependency licences", "pass", summary or "no packages", M_LICENCE)


def calendar(items: list, now) -> str:
    """Bought licences per year of expiry, with cost totals. Items come from [[item]] kind = "licence"."""
    rows = sorted((i for i in items if i.kind == "licence"), key=lambda i: i.expires)
    if not rows:
        return "no licence items: add [[item]] kind = \"licence\" with name, expires, optionally cost, vendor, owner, auto_renews"
    out, year, total, cur = [], None, 0.0, None
    for i in rows:
        if i.expires.year != year:
            if year is not None:
                out.append(f"  total {year}: {total:.2f} {cur or ''}".rstrip())
            year, total = i.expires.year, 0.0
            out.append(f"\n{year}")
        m = i.meta
        cost = m.get("cost")
        total += float(cost) if cost is not None else 0.0
        cur = m.get("currency", cur)
        flags = ("EXPIRED " if i.expires < now else "") + ("auto-renews " if m.get("auto_renews") else "")
        out.append(f"  {i.expires:%Y-%m-%d}  {i.name:30} {m.get('vendor', ''):16} "
                   f"{(f'{cost:g} ' + m.get('currency', '')) if cost is not None else 'cost ?':>14}  {m.get('owner', ''):10} {flags}".rstrip())
    out.append(f"  total {year}: {total:.2f} {cur or ''}".rstrip())
    out.append("\n(cost '?' counts as 0: the total is a floor, not the budget)")
    return "\n".join(out)
