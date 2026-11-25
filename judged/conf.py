"""The one config format: a line is a directive, its arguments, then key=value pairs.

    tls   github.com
    licence "IDE seats" 2027-03-01  cost=1200 currency=EUR owner=dev
    secrets repos=~/dev/* history=no
    renew www.example.com cmd="certbot renew" reload="systemctl reload nginx" when_days=21

`#` starts a comment, a trailing `\\` continues the line, quotes group words (shlex). Lists are comma separated,
yes/no are booleans, YYYY-MM-DD is a date. An unknown directive or key is an error with its line number: a typo
must not silently turn a check off. The shipped catalog (controls, obligations) uses the same format."""
import re
import shlex
from datetime import date
from pathlib import Path

LISTS = {"list", "ints", "argv"}
# directive -> (positional names with kinds, allowed keys with kinds, where it lands)
SPEC = {
    "notify":     ((), {"lead_days": "ints", "urls": "list", "urls_file": "str", "via": "str", "notts": "str"}, "section"),
    "company":    ((), {"regions": "list", "mail_domains": "list"}, "section"),
    "secrets":    ((), {"repos": "list", "history": "bool", "scan_paths": "list", "extra_terms": "list", "entropy": "bool", "max_file_mb": "int", "emails": "bool", "email_accept": "list"}, "section"),
    "licences":   ((), {"envs": "list", "deny": "list", "reviewed_packages": "list"}, "section"),
    "deps":       ((), {"projects": "list", "deny": "list", "max_lookups": "int"}, "section"),
    "flatpak":    ((), {"enabled": "bool", "accept": "list", "ignore": "list", "leftovers": "bool"}, "section"),
    "containers": ((), {"enabled": "bool", "projects": "list", "accept": "list", "max_image_age_days": "int", "scan": "bool", "max_scan_mb": "int", "max_images": "int"}, "section"),
    "tls":        ((("host", "str"),), {"port": "int", "name": "str"}, "item"),
    "gpg":        ((), {"homedir": "str"}, "item"),
    "domain":     ((("host", "str"),), {}, "item"),
    "site":       ((("host", "str"),), {"images": "bool"}, "item"),
    "date":       ((("name", "str"), ("expires", "date")), {}, "item"),
    "waive":      ((("id", "str"), ("expires", "date")), {"owner": "str", "reason": "str", "package": "str"}, "item"),
    "licence":    ((("name", "str"), ("expires", "date")),
                   {"cost": "float", "currency": "str", "vendor": "str", "owner": "str", "auto_renews": "bool"}, "item"),
    "obligation": ((("id", "str"),), {"last_done": "date"}, "obligation"),
    "renew":      ((("host", "str"),), {"name": "str", "cmd": "argv", "reload": "argv", "when_days": "float",
                                        "min_interval_hours": "float", "port": "int", "cafile": "str", "homedir": "str", "extend_by": "str", "timeout": "int"}, "renew"),
    "include":    ((("path", "str"),), {}, "include"),
    "check":      ((("name", "str"),), {"cmd": "argv", "maps": "maps", "warn_exit": "int", "timeout": "int"}, "check"),
    "framework":  ((("id", "str"), ("name", "str")), {}, "framework"),
    "control":    ((("framework", "str"), ("id", "str"), ("title", "str")), {}, "control"),
    "duty":       ((("id", "str"),), {"region": "list", "framework": "str", "title": "str", "cadence_days": "int",
                                      "deadline": "str", "verify": "str", "reviewed": "date"}, "duty"),
}


# Every option of every section with the value it has when you do nothing. Strict loading (below) demands that a config states
# ALL of them, so nothing is decided silently; `judged config template` prints this table as a ready file.
# An area (judged/areas/) declares its own DEFAULTS and DOC next to its SPEC.
DEFAULTS = {
    "notify":     {"lead_days": [30, 14, 7, 1], "urls": [], "urls_file": "", "via": "auto", "notts": "notts"},
    "company":    {"regions": [], "mail_domains": []},
    "secrets":    {"repos": [], "history": True, "scan_paths": [], "extra_terms": [], "entropy": True, "max_file_mb": 1, "emails": True, "email_accept": []},
    "licences":   {"envs": [], "deny": [], "reviewed_packages": []},
    "deps":       {"projects": [], "deny": [], "max_lookups": 300},
    "flatpak":    {"enabled": True, "accept": [], "ignore": [], "leftovers": True},
    "containers": {"enabled": False, "projects": [], "accept": [], "max_image_age_days": 180, "scan": True, "max_scan_mb": 1000, "max_images": 10},
}
DOC = {
    "notify":     "where alerts go: lead_days = days before expiry to alert; via = auto|notts|apprise; urls/urls_file = Apprise targets",
    "company":    "regions (UK, PL, EU...) pick the legal obligations; mail_domains get SPF/DMARC checks",
    "secrets":    "repos (globs) and scan_paths to search for secrets and your identity; history = also search git history (on by default; a search that takes over 60 s is reported as unknown); entropy = also flag long random-looking strings with no keyword next to them (to review); max_file_mb = text files are read up to this size, bigger ones and binary files are listed as not scanned; emails = warn about e-mail addresses in files (personal data), shown masked; email_accept = addresses or domains you publish on purpose",
    "licences":   "envs = Python environments (globs) to classify; deny = licence labels that fail the audit; reviewed_packages = ones a person approved",
    "deps":       "projects (globs) with lockfiles: vulnerabilities and licences; max_lookups limits licence requests",
    "flatpak":    "enabled = audit Flatpak apps; accept/ignore = permissions or apps you accept; leftovers = report orphaned data and unused runtimes",
    "containers": "enabled = audit podman/docker; projects = folders with Dockerfiles/compose; scan = vulnerability scan of images with trivy",
}


class ConfError(ValueError):
    pass


def defaults() -> dict:
    from . import areas
    return {**DEFAULTS, **areas.defaults()}


def docs() -> dict:
    from . import areas
    return {**DOC, **areas.docs()}


def _sections() -> dict:
    return {d: list(keys) for d, (pos, keys, dest) in spec().items() if dest == "section"}


def missing(cfg: dict) -> dict:
    """{section: [keys not stated]}; a section that is absent entirely lists all its keys."""
    out = {}
    for sec, keys in _sections().items():
        have = cfg.get(sec)
        gone = keys if have is None else [k for k in keys if k not in have]
        if gone:
            out[sec] = gone
    return out


def _fmt(v) -> str:
    if isinstance(v, bool):
        return "1" if v else "0"
    if isinstance(v, list):
        return ",".join(str(x) for x in v)
    return shlex.quote(str(v)) if str(v) and not str(v).replace("/", "").replace("_", "").replace("-", "").replace(".", "").replace("~", "").isalnum() else str(v)


def line_for(sec: str, keys: list) -> str:
    d = defaults()[sec]
    return sec + " " + " ".join(f"{k}={_fmt(d[k])}" for k in keys)


def require_complete(cfg: dict, where: str) -> dict:
    """Strict mode: every option must be written down. A missing one is an error that lists what to add, with the default."""
    gone = missing(cfg)
    if gone:
        lines = [f"  {line_for(sec, keys)}" for sec, keys in gone.items()]
        raise ConfError(f"{where} is incomplete: every option must be stated (1/0 or true/false, a path or a list; empty = nothing). Add:\n"
                        + "\n".join(lines) + "\nSee all of them with `judged config template`.")
    return cfg


def template() -> str:
    """A complete config with every option at its default, one commented block per section."""
    docs_, out = docs(), ["# judged.conf: every option is written down on purpose. A missing one is an error, not a silent default.",
                          "# 1/0 or true/false for switches; empty after = means nothing/off; lists are comma separated.", ""]
    for sec, keys in _sections().items():
        out.append(f"# {docs_.get(sec, sec)}")
        out.append(line_for(sec, keys))
        out.append("")
    out.append("# Entries (repeat as needed): tls HOST, site HOST, domain HOST, date NAME YYYY-MM-DD, licence NAME YYYY-MM-DD cost=..,")
    out.append("# waive ID YYYY-MM-DD owner=.. reason=\"..\", obligation ID last_done=YYYY-MM-DD, renew HOST cmd=\"..\", check NAME cmd=\"..\" maps=fw:ctl")
    return "\n".join(out) + "\n"


def load_strict(path: Path) -> dict:
    return require_complete(load(path), Path(path).name)


def spec() -> dict:
    """Core directives plus whatever the audit areas declare in their own SPEC (judged/areas/)."""
    from . import areas
    return {**SPEC, **areas.specs()}


def value(kind: str, raw: str):
    try:
        if kind == "str":
            return raw
        if kind == "int":
            return int(raw)
        if kind == "float":
            return float(raw)
        if kind == "bool":
            if raw.lower() in ("1", "yes", "true", "on"):
                return True
            if raw.lower() in ("0", "no", "false", "off"):
                return False
            raise ValueError("expected 1/0, true/false, yes/no or on/off")
        if kind == "date":
            return date.fromisoformat(raw)
        if kind == "list":
            return [x for x in raw.split(",") if x]
        if kind == "ints":
            return [int(x) for x in raw.split(",") if x]
        if kind == "argv":
            return shlex.split(raw)
        if kind == "maps":      # ce:updates,iso27001:A.8.8  ->  {"ce": ["updates"], "iso27001": ["A.8.8"]}
            out = {}
            for pair in [x for x in raw.split(",") if x]:
                fw, sep, cid = pair.partition(":")
                if not sep or not cid:
                    raise ValueError(f"{pair!r} should be framework:control")
                out.setdefault(fw, []).append(cid)
            return out
    except ValueError as e:
        raise ValueError(f"{raw!r} is not a valid {kind} ({e})") from None
    raise AssertionError(kind)


def logical_lines(text: str):
    buf, start = "", 0
    for n, line in enumerate(text.splitlines(), 1):
        if not buf:
            start = n
        if line.rstrip().endswith("\\"):
            buf += line.rstrip()[:-1] + " "
            continue
        yield start, buf + line
        buf = ""
    if buf:
        yield start, buf


def parse(text: str, name: str = "config") -> dict:
    cfg = {"item": [], "obligation": [], "renew": [], "frameworks": {}, "duties": [], "checks": [], "includes": []}
    table = spec()
    for n, line in logical_lines(text):
        try:
            words = shlex.split(line, comments=True)
        except ValueError as e:
            raise ConfError(f"{name}:{n}: {e}") from None
        if not words:
            continue
        d, rest = words[0], words[1:]
        if d not in table:
            raise ConfError(f"{name}:{n}: unknown directive {d!r} (known: {', '.join(table)})")
        pos, keys, dest = table[d]
        kvs = [w for w in rest if re.match(r"[a-z_]+=", w)]
        args = [w for w in rest if not re.match(r"[a-z_]+=", w)]
        if len(args) != len(pos):
            raise ConfError(f"{name}:{n}: {d} takes {len(pos)} argument(s) ({' '.join(p for p, _ in pos) or 'none'}), got {len(args)}")
        rec = {}
        try:
            for (field, kind), raw in zip(pos, args):
                rec[field] = value(kind, raw)
            for kv in kvs:
                k, _, raw = kv.partition("=")
                if k not in keys:
                    raise ValueError(f"unknown key {k!r} for {d} (known: {', '.join(keys) or 'none'})")
                rec[k] = value(keys[k], raw)
        except ValueError as e:
            raise ConfError(f"{name}:{n}: {e}") from None
        if dest == "section":
            cfg.setdefault(d, {}).update(rec)
        elif dest == "item":
            cfg["item"].append({"kind": d, **rec})
        elif dest == "include":
            cfg["includes"].append(rec["path"])
        elif dest == "check":
            if "cmd" not in rec:
                raise ConfError(f"{name}:{n}: check {rec['name']!r} needs cmd=\"...\"")
            cfg["checks"].append(rec)
        elif dest == "renew" and "cmd" not in rec and not str(rec["host"]).startswith("gpg:"):
            raise ConfError(f"{name}:{n}: renew {rec['host']!r} needs cmd=\"...\" (the command that renews the certificate)")
        elif dest in ("obligation", "renew"):
            cfg[dest].append(rec)
        elif dest == "framework":
            cfg["frameworks"].setdefault(rec["id"], {"controls": {}})["name"] = rec["name"]
        elif dest == "control":
            fw = cfg["frameworks"].setdefault(rec["framework"], {"controls": {}})
            fw["controls"][rec["id"]] = rec["title"]
        elif dest == "duty":
            rec["kind"] = "periodic" if "cadence_days" in rec else "event"
            rec.setdefault("region", [])
            cfg["duties"].append(rec)
    return cfg


def merge(base: dict, extra: dict) -> dict:
    for k, v in extra.items():
        if isinstance(v, list):
            base.setdefault(k, []).extend(v)
        elif k == "frameworks":
            for fid, f in v.items():
                dst = base["frameworks"].setdefault(fid, {"controls": {}})
                dst["name"] = f.get("name", dst.get("name", fid))
                dst["controls"].update(f["controls"])
        else:
            base.setdefault(k, {}).update(v)
    return base


def load(path: Path, _depth: int = 0) -> dict:
    """Parse a file and, recursively, the files it `include`s (globs, relative to the including file), e.g.
    `include rules/*.rules`. Included files use the same syntax; a missing include glob is an error."""
    path = Path(path)
    cfg = parse(path.read_text(), path.name)
    if cfg["includes"] and _depth >= 5:
        raise ConfError(f"{path.name}: includes nested deeper than 5 (a loop?)")
    for pat in cfg.pop("includes"):
        found = sorted(path.parent.glob(str(Path(pat).expanduser())) if not Path(pat).expanduser().is_absolute()
                       else map(Path, __import__("glob").glob(str(Path(pat).expanduser()))))
        if not found:
            raise ConfError(f"{path.name}: include {pat!r} matches no file")
        for f in found:
            merge(cfg, load(f, _depth + 1))
    cfg.setdefault("includes", [])
    return cfg


def catalog() -> dict:
    return load(Path(__file__).with_name("catalog.conf"))
