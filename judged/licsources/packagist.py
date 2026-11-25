"""Packagist (PHP). The `p2` metadata is minified (composer/2.0): only the first entry that sets a field carries it and every older entry inherits
it until one sets it again, and the value "__unset" removes it. Checked live against monolog/monolog: the newest entry has `license`, the next 90 do not."""
import urllib.error
import urllib.request

ECOSYSTEMS = ("Packagist",)


def expand(entries: list, field: str = "license") -> list:
    """[(version, normalized version, value or None)] in the order given, with inherited values filled in."""
    cur, out = None, []
    for x in entries:
        if field in x:
            cur = None if x[field] == "__unset" else x[field]
        out.append((str(x.get("version", "")), str(x.get("version_normalized", "")), cur))
    return out


def licence(eco, name, version, get):
    try:
        d = get(f"https://repo.packagist.org/p2/{urllib.request.quote(name.lower(), safe='/')}.json")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None                                       # not on Packagist (a private repository): unknown, not an error
        raise
    entries = (d.get("packages") or {}).get(name.lower()) or []
    want = version.lstrip("v")
    for v, norm, lic in expand(entries):
        if v.lstrip("v") == want or norm == want:
            if lic is None:
                return ""
            return " AND ".join(lic) if isinstance(lic, list) else str(lic)
    return None
