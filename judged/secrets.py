"""Secrets hygiene. Two scanners: git repos (what is tracked, what `git add .` would add, whether .gitignore
covers the usual secret names, optionally history) and plain paths such as chat logs, where a token pasted into
a conversation is a leaked token. Same token shapes as ~/.claude/skills/publish-anything/scripts/publish-check.
A value is NEVER returned: only kind, file and line number."""
import getpass
import math
import os
import stat
import re
import socket
import subprocess
from pathlib import Path

from .controls import Result

M_SECRETS = {"iso27001": ["A.5.17"], "gdpr": ["art32", "art5-1f"]}

SHAPES = {
    "github-token": r"(?<![A-Za-z0-9])gh[pousr]_[A-Za-z0-9]{30,}",
    "github-pat": r"github_pat_[A-Za-z0-9_]{30,}",
    "api-key-sk": r"(?<![A-Za-z0-9])sk-[A-Za-z0-9_-]{30,}",
    "aws-key-id": r"AKIA[0-9A-Z]{16}",
    "slack-token": r"xox[baprs]-[A-Za-z0-9-]{10,}",
}
# a header alone is just text (tests and docs quote it); a key has a body of base64 right after it
PRIVATE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----(?:\\n|\s)*(?P<body>[A-Za-z0-9+/=]{40,})")
STRONG = re.compile("|".join(f"(?P<{k.replace('-', '_')}>{v})" for k, v in SHAPES.items()))
GENERIC = re.compile(r"""(?i)(passw(or)?d|secret|token|api[_-]?key)\s*[:=]\s*["']?[A-Za-z0-9/+_.\-]{12,}(?![A-Za-z0-9/+_.\-(])""")
SECRET_NAME = re.compile(r"(^|/)(\.env(\.[^/]*)?|id_(rsa|dsa|ecdsa|ed25519)|[^/]*\.(pem|key|p12|pfx|kdbx|jks|keystore)|"
                         r"credentials(\.json)?|\.netrc|\.npmrc|\.pypirc|secrets?\.(json|ya?ml|toml))$", re.I)
DATA_NAME = re.compile(r"\.(sqlite3?|db)$", re.I)
SAFE_NAME = re.compile(r"\.(example|sample|template|dist|pub)$", re.I)
PROBES = [".env", "id_rsa", "secrets.json", "x.pem", "x.key"]   # names .gitignore should already cover
TEXT_SUFFIX = {".jsonl", ".json", ".md", ".txt", ".log", ".yaml", ".yml", ".toml", ".env", ".conf", ".cfg", ".ini", ".sh", ".py"}


def identity_terms(skipped: list | None = None, extra: list | None = None) -> dict:
    """What identifies the owner, detected at run time (never typed, never printed): username, home path,
    hostname, git name and email. Too-short or generic values are skipped so they do not match everything."""
    terms = {}
    home = str(Path.home())
    if home not in ("/", "/root"):
        terms["home path"] = home
    for kind, key in (("git email", "user.email"), ("git name", "user.name")):
        try:
            v = subprocess.run(["git", "config", "--global", "--get", key], capture_output=True, text=True, timeout=10).stdout.strip()
        except (OSError, subprocess.TimeoutExpired):
            v = ""
        if len(v) >= 4:
            terms[kind] = v
    def skip(why: str):
        if skipped is not None:
            skipped.append(why)
    user = getpass.getuser()
    if len(user) >= 4 and user not in {"root", "user", "admin", "ubuntu", "debian"}:
        terms["username"] = user
    else:
        skip("username too short or generic, not searched")
    host = socket.gethostname()
    if len(host) >= 5 and host != "localhost":
        terms["hostname"] = host
    else:
        skip("hostname too short or generic, not searched")
    if "home path" not in terms:
        skip("home path is / or /root, not searched")
    for kind, key in (("git email", "user.email"), ("git name", "user.name")):
        if kind not in terms:
            skip(f"{kind} unset or shorter than 4 characters, not searched")
    for v in extra or []:
        terms[f"extra term {len(terms)}"] = v
    return terms


def scan_identity(text: str, terms: dict) -> list:
    """[(kind, line)], one per line, the first matching kind; the matched value is never returned."""
    out = []
    for n, line in enumerate(text.splitlines(), 1):
        for kind, v in terms.items():
            if v in line:
                out.append((kind, n))
                break
    return out


def name_class(path: str) -> str | None:
    if SAFE_NAME.search(path):
        return None
    if SECRET_NAME.search(path):
        return "secret"
    return "data" if DATA_NAME.search(path) else None


def placeholder(s: str) -> bool:
    """A real token is random: ~25 distinct characters in 40. A run of one character, or a documented
    example, is a placeholder. The private-key header has no body to judge, so it always counts."""
    if len(set(s)) < 10 or "example" in s.lower():
        return True
    if s.startswith(("sk-", "gh", "github_pat_")):   # base62 secrets mix a digit, upper and lower case; slugs and prose do not
        return not (re.search(r"\d", s) and re.search(r"[A-Z]", s) and re.search(r"[a-z]", s))
    return False


def strong(line: str) -> str | None:
    """Kind of the first real (non-placeholder) token shape in the text, else None."""
    for m in PRIVATE.finditer(line):
        if len(set(m.group("body"))) >= 10:
            return "private-key"
    for m in STRONG.finditer(line):
        if not placeholder(m.group(0)):
            return m.lastgroup.replace("_", "-")
    return None


CANDIDATE = re.compile(r"""(?:^|[\s"'=:,(\[])([A-Za-z0-9+/_\-]{24,}={0,2})(?=$|[\s"',;)\]])""")
NO_ENTROPY_NAME = re.compile(r"(lock|\.min\.|\.map$|\.svg$|\.sum$|\.snap$)", re.I)       # hashes and bundles are random by design


def shannon(s: str) -> float:
    from collections import Counter
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


WORDS = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+")


def word_length(s: str) -> float:
    """Average length of the camelCase / snake_case words in s (digits and separators ignored). Identifiers have long words, random strings short ones:
    OneMinusSrc1Alpha is 4.3, a random base64 string is about 2."""
    w = WORDS.findall(s)
    return sum(map(len, w)) / len(w) if w else 0.0


def random_looking(s: str) -> bool:
    """A string that looks like a generated secret with NO keyword next to it: long, many kinds of characters, high entropy. Not a hash, a UUID,
    an alphabet table, an identifier made of words, a URL path or an SRI hash (sha512-...). A judgement: a hit is `to review`, never a proven secret."""
    if s.startswith(("sha256-", "sha384-", "sha512-", "sha1-")) or re.match(r"(?i)sha\d+/+", s):
        return False
    if not (re.search(r"\d", s) and re.search(r"[A-Z]", s) and re.search(r"[a-z]", s)):
        return False
    if re.search(r"(?i)(example|placeholder|changeme|xxxx|your[_-])", s):
        return False
    if re.search(r"(?i)(abcdefgh|bcdefghi|01234567|12345678|qwertyui)", s):      # an alphabet table, not a secret
        return False
    if "/" in s and re.fullmatch(r"[a-z][a-z-]*", s.split("/")[0]):             # text-to-speech/ID: a URL path, the ID is public
        return False
    parts = re.split(r"[_-]", s)
    if len(parts) >= 3 and sum(bool(re.fullmatch(r"[A-Za-z]{2,}\d{0,3}|\d{1,4}", x)) for x in parts) >= 0.8 * len(parts):      # BR_TLS_DH_anon_WITH_AES_256: words joined by _ or -
        return False
    if word_length(s) >= 3.6:                                                    # WGPUBlendFactor_OneMinusSrc1: an identifier made of words
        return False
    return shannon(s) >= 4.2                     # needs 19+ different characters, so hex hashes (16) and UUIDs (17) never pass


def scan_entropy(text: str, name: str = "") -> list:
    """[(kind, line)]: random-looking strings. Off for lock files and bundles. A line that already has a strong token shape is left to `strong`."""
    if NO_ENTROPY_NAME.search(name):
        return []
    out = []
    for n, line in enumerate(text.splitlines(), 1):
        if len(line) > 2000 or STRONG.search(line):                  # minified lines are all noise
            continue
        for m in CANDIDATE.finditer(line):
            if "://" in line and re.search(r"[?&][\w.\-]+=$", line[:m.start(1)]):     # a URL query value (tracking id, public key in a link): not a stored secret
                continue
            if re.search(r"(?i)(sha\d*[:/]{1,2}|fingerprint[:=\s]+)$", line[:m.start(1)]):     # a public key fingerprint or pin, not a secret
                continue
            if random_looking(m.group(1)):
                out.append(("high-entropy", n))
                break
    return out


def scan_text(text: str, generic: bool = True) -> list:
    """[(kind, line)] with no values. `generic` adds the noisy name=value pattern."""
    out = []
    lines = text.splitlines()
    for n, line in enumerate(lines, 1):
        k = strong(line)
        if not k and "PRIVATE KEY" in line:
            k = strong(line + "\n" + (lines[n] if n < len(lines) else ""))      # in files the key body is on the next line
        if k:
            out.append((k, n))
        elif generic and not STRONG.search(line) and GENERIC.search(line):   # a placeholder token is not an assignment either
            out.append(("name=value", n))
    return out


EMAIL = re.compile(r"([A-Za-z0-9][A-Za-z0-9._%+\-]*)@([A-Za-z][A-Za-z0-9\-]*(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,})")
NOT_PERSONAL_LOCAL = {"git", "noreply", "no-reply", "donotreply", "do-not-reply"}
NOT_PERSONAL_DOMAIN = re.compile(r"(^|\.)(example\.(com|org|net)|invalid|test|users\.noreply\.github\.com)$", re.I)


def scan_emails(text: str, accept: list | None = None) -> list:
    """[(masked address, line)]. An address is personal data. Skipped: ssh remotes (git@host), noreply and example addresses, and the
    addresses or domains in `accept` (role mailboxes you chose to publish). The shown form keeps one letter: a***@domain."""
    ok = {a.lower() for a in (accept or [])}
    out = []
    for n, line in enumerate(text.splitlines(), 1):
        if len(line) > 2000:
            continue
        for m in EMAIL.finditer(line):
            local, dom = m.group(1), m.group(2)
            full = f"{local}@{dom}".lower()
            if local.lower() in NOT_PERSONAL_LOCAL or NOT_PERSONAL_DOMAIN.search(dom) or full in ok or dom.lower() in ok:
                continue
            out.append((f"{local[0]}***@{dom}", n))
    return out


def _git(repo: str, *args: str) -> list | None:
    try:
        r = subprocess.run(["git", "-C", repo, *args], capture_output=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return r.stdout.decode("utf-8", "replace").split("\0") if r.returncode == 0 else None


def _read_text(p: Path, cap: int = 1_000_000) -> str | None:
    try:
        if not stat.S_ISREG(p.lstat().st_mode):      # symlinks, FIFOs, devices: reading them can block or never end
            return None
        with p.open("rb") as fh:
            b = fh.read(cap)
    except OSError:
        return None
    return None if b"\0" in b[:8192] else b.decode("utf-8", "replace")


def _brief(items: list, n: int = 5) -> str:
    return ", ".join(items[:n]) + (f" (+{len(items) - n} more)" if len(items) > n else "")


def repo_check(path: str, history: bool = False, max_files: int = 5000, extra_terms: list | None = None, entropy: bool = True, max_file_mb: int = 1, emails: bool = True, email_accept: list | None = None) -> list:
    repo, name = str(Path(path).expanduser()), Path(path).expanduser().name
    tracked = _git(repo, "ls-files", "-z")
    if tracked is None:
        return [Result(f"secrets.{name}.git", f"{name} repository", "unknown", "not a git repository (nothing to check against .gitignore)", M_SECRETS)]
    tracked = [t for t in tracked if t]
    loose = [t for t in (_git(repo, "ls-files", "-o", "--exclude-standard", "-z") or []) if t]
    res = []
    for label, files in (("tracked", tracked), ("untracked and NOT ignored (git add . would take it)", loose)):
        sec = [f for f in files if name_class(f) == "secret"]
        dat = [f for f in files if name_class(f) == "data"]
        if sec:
            res.append(Result(f"secrets.{name}.names.{label.split()[0]}", f"{name} secret-named files, {label.split()[0]}",
                              "fail", f"{label}: {_brief(sec)}", M_SECRETS))
        if dat:
            res.append(Result(f"secrets.{name}.data.{label.split()[0]}", f"{name} database files, {label.split()[0]}",
                              "warn", f"{label}: {_brief(dat)}", M_SECRETS))
    hits, ident, mails, terms = [], [], [], identity_terms(extra=extra_terms)
    media = {".pyc", ".webp", ".ttf", ".otf", ".woff", ".wasm", ".mp3", ".mp4", ".webm", ".ogg", ".wav", ".flac", ".jpeg", ".bmp", ".tiff", ".svgz", ".mov"}
    cap, gaps = max_file_mb * 1_000_000, {"binary": [], "too big": [], "unreadable": [], "not looked at (max_files)": [], "images and archives": 0}
    every = tracked + loose
    gaps["not looked at (max_files)"] = every[max_files:]
    for f in every[:max_files]:
        if Path(f).suffix.lower() in {".png", ".jpg", ".gif", ".pdf", ".zip", ".gz", ".woff2", ".ico"} | media:
            gaps["images and archives"] += 1
            continue
        fp = Path(repo) / f
        try:
            if fp.is_file() and not fp.is_symlink() and fp.stat().st_size > cap:
                gaps["too big"].append(f)
        except OSError:
            pass
        t = _read_text(fp, cap)
        if t is None:
            try:
                if fp.is_symlink() or fp.is_dir():              # a link or a submodule: its content is not this repository's file
                    continue
                (gaps["binary"] if fp.is_file() else gaps["unreadable"]).append(f)
            except OSError:
                gaps["unreadable"].append(f)
            continue
        for kind, line in scan_text(t):
            hits.append((kind, f"{f}:{line}"))
        if entropy:
            for kind, line in scan_entropy(t, f):
                hits.append((kind, f"{f}:{line}"))
        for kind, line in scan_identity(t, terms):
            ident.append((kind, f"{f}:{line}"))
        if emails and not NO_ENTROPY_NAME.search(f):
            for masked, line in scan_emails(t, email_accept):
                mails.append((masked, f"{f}:{line}"))
    strong_hits = [h for h in hits if h[0] not in ("name=value", "high-entropy")]
    weak = [h for h in hits if h[0] in ("name=value", "high-entropy")]
    if strong_hits:
        res.append(Result(f"secrets.{name}.shapes", f"{name} token shapes in files", "fail",
                          f"{len(strong_hits)} in files: " + _brief([f"{k} {w}" for k, w in strong_hits]) + " (values not shown)", M_SECRETS))
    if weak:
        res.append(Result(f"secrets.{name}.assign", f"{name} password/token assignments", "warn",
                          f"{len(weak)} lines to review ({len([1 for k, _ in weak if k == 'high-entropy'])} look random, the rest are name=value): " + _brief([w for _, w in weak]) + " (values not shown)", M_SECRETS))
    skipped = {k: v for k, v in gaps.items() if v}
    if skipped:
        res.append(Result(f"secrets.{name}.coverage", f"{name} scan coverage", "warn",
                          "not (fully) scanned: " + "; ".join(f"{len(v) if isinstance(v, list) else v} {k}" + (f" ({_brief(v, 3)})" if isinstance(v, list) else "") for k, v in skipped.items())
                          + f". Text files are read up to {max_file_mb} MB; a secret inside a binary or beyond that is not seen", M_SECRETS))
    if not (strong_hits or weak or [r for r in res if r.status == "fail"]):
        res.append(Result(f"secrets.{name}.files", f"{name} files", "pass", f"{len(tracked)} tracked files scanned, nothing found", M_SECRETS))
    if ident:
        res.append(Result(f"secrets.{name}.identity", f"{name} owner identity in files", "warn",
                          f"{len(ident)} lines name the owner (detected, values not shown): "
                          + _brief([f"{k} {w}" for k, w in ident]) + ". Fine in a private repo, a leak in a public one", M_SECRETS))
    if mails:
        who = sorted({m for m, _ in mails})
        res.append(Result(f"secrets.{name}.emails", f"{name} e-mail addresses in files", "warn",
                          f"{len(mails)} lines hold {len(who)} address(es) ({_brief(who, 4)}), first at {_brief([w for _, w in mails], 3)}. "
                          "An address is personal data: fine in a private repo, a leak in a public one. Role mailboxes you publish on purpose go in email_accept", M_SECRETS))
    uncovered = [p for p in PROBES if subprocess.run(["git", "-C", repo, "check-ignore", "-q", p], capture_output=True).returncode != 0]
    res.append(Result(f"secrets.{name}.gitignore", f"{name} .gitignore", "warn" if uncovered else "pass",
                      ("does not cover: " + ", ".join(uncovered)) if uncovered else "covers .env, keys, *.pem, *.key", M_SECRETS))
    if history:
        rx = "|".join(v.replace("(?<![A-Za-z0-9])", "") for v in SHAPES.values()) + "|-----BEGIN [A-Z ]*PRIVATE KEY-----"   # git -G is POSIX ERE: no lookbehind
        log = _git(repo, "log", "--all", "-G" + rx, "--format=%h", "-n", "20")
        if log is None:                                              # timed out or git failed: that is NOT "nothing found"
            res.append(Result(f"secrets.{name}.history", f"{name} history", "unknown", "history search failed or took over 60 s, so nothing is known about old commits", M_SECRETS))
            return res
        cands = [c for c in log[0].split("\n") if c]
        commits = []
        for c in cands:
            diff = _git(repo, "show", c, "--format=", "-U0") or [""]
            if any(strong(l[1:]) for l in diff[0].splitlines() if l.startswith("+") and not l.startswith("+++")):
                commits.append(c)
        res.append(Result(f"secrets.{name}.history", f"{name} history", "fail" if commits else "pass",
                          f"{len(commits)} commits contain token shapes ({_brief(commits)}): revoke at the provider first, then clean"
                          if commits else "no token shapes in history", M_SECRETS))
    return res


def path_check(path: str, max_bytes: int = 300_000_000) -> list:
    """Chat logs and other folders: token shapes only (the name=value pattern is far too noisy in conversations)."""
    root, seen, hits, files = Path(path).expanduser(), 0, [], 0
    if not root.exists():
        return [Result(f"secrets.path.{root.name}", f"{root.name}", "unknown", "path does not exist", M_SECRETS)]
    for dp, _, names in os.walk(root):
        for n in names:
            p = Path(dp) / n
            if p.suffix.lower() not in TEXT_SUFFIX:
                continue
            try:
                size = p.stat().st_size
            except OSError:
                continue
            if seen + size > max_bytes:
                continue
            seen += size
            files += 1
            try:
                with p.open("r", encoding="utf-8", errors="replace") as fh:
                    for i, line in enumerate(fh, 1):
                        k = strong(line)
                        if k:
                            hits.append((k, f"{p.relative_to(root)}:{i}"))
            except OSError:
                pass
    st = "fail" if hits else "pass"
    ev = (f"{len(hits)} token shapes in {files} files: " + _brief([f"{k} {w}" for k, w in hits]) + " (values not shown; revoke them)"
          if hits else f"{files} files, {seen // 1_000_000} MB scanned, no token shapes")
    return [Result(f"secrets.path.{root.name}", f"{root.name} (chats and logs)", st, ev, M_SECRETS)]
