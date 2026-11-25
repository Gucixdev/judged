"""Lockfile -> [(ecosystem, name, version)]. Lockfiles are the one place every ecosystem writes down exactly what is
installed, so one small parser per format replaces one scanner per language. Ecosystem names are OSV's.
Only registry packages are returned: path/git dependencies (often private) never leave the machine."""
import json
import re
import tomllib
from pathlib import Path

SKIP_DIRS = {"node_modules", ".venv", "venv", "target", ".git", "vendor", "dist", "build", "__pycache__"}


def package_lock(text: str) -> list:
    out = []
    for path, p in json.loads(text).get("packages", {}).items():
        v = p.get("version")
        if path and v and not p.get("link") and str(p.get("resolved", "")).startswith("http"):
            out.append(("npm", path.split("node_modules/")[-1], v))
    return out


def cargo_lock(text: str) -> list:
    return [("crates.io", p["name"], p["version"]) for p in tomllib.loads(text).get("package", [])
            if str(p.get("source", "")).startswith("registry+")]


def composer_lock(text: str) -> list:
    d = json.loads(text)
    return [("Packagist", p["name"], p["version"].lstrip("v")) for k in ("packages", "packages-dev") for p in d.get(k, [])
            if p.get("dist", {}).get("type") != "path"]


def go_mod(text: str) -> list:
    return [("Go", m.group(1), m.group(2)) for m in re.finditer(r"^\s*(?:require\s+)?([\w.\-/]+\.[\w.\-/]+)\s+(v[\w.\-+]+)", text, re.M)
            if "=>" not in m.group(0)]


def toml_lock(text: str) -> list:       # poetry.lock and uv.lock
    out = []
    for p in tomllib.loads(text).get("package", []):
        src = p.get("source", {})
        if isinstance(src, dict) and src.get("type") not in (None, "legacy", "registry") and "registry" not in src:
            continue
        out.append(("PyPI", p["name"], p["version"]))
    return out


def pipfile_lock(text: str) -> list:
    d = json.loads(text)
    return [("PyPI", n, p["version"].lstrip("=")) for k in ("default", "develop") for n, p in d.get(k, {}).items() if "version" in p]


def requirements(text: str) -> list:
    return [("PyPI", m.group(1), m.group(2)) for m in re.finditer(r"^\s*([A-Za-z0-9_.\-]+)\s*==\s*([\w.\-+]+)", text, re.M)]


def pnpm_lock(text: str) -> list:
    """pnpm-lock.yaml (v5 to v9), line based: the `packages:` section only; tarball, directory and git sources are dropped."""
    out, in_pkgs, key, resolution = [], False, None, ""

    def flush():
        if key and not re.search(r"tarball:|directory:|repo:|type: git", resolution):
            out.append(("npm", key[0], key[1]))
    for ln in text.splitlines():
        if re.match(r"^\S", ln):
            flush(); key, resolution = None, ""
            in_pkgs = ln.startswith("packages:")
        elif in_pkgs and re.match(r"^  [^ ].*:$", ln):                  # any entry ends the previous one, even one we cannot read
            flush(); key, resolution = None, ""
            m = re.match(r"^  '?\"?/?((?:@[^/@\s'\"]+/)?[^/@\s'\"]+)(?:@|/)(\d[^:'\"\s(_]*)", ln)
            if m:
                key = (m.group(1), m.group(2))
        elif key and re.match(r"^    resolution:", ln):                 # not `deprecated:` texts that happen to say "repo:"
            resolution = ln
    flush()
    return out


def yarn_lock(text: str) -> list:
    """yarn.lock, classic (v1) and Berry. Registry packages only: Berry `@npm:` resolutions, v1 http(s) `resolved` that is not git."""
    out, head, ver, src = [], None, None, None

    def flush():
        if head and ver and src:
            if "@npm:" in src:                                      # berry: "name@npm:1.2.3"
                out.append(("npm", src.split("@npm:")[0].strip('"'), ver))
            elif src.startswith("http") and "codeload.github.com" not in src and ".git#" not in src:      # v1: a registry tarball, not a git archive
                out.append(("npm", head, ver))
    for ln in text.splitlines():
        if not ln.strip() or ln.startswith("#"):
            continue
        if not ln.startswith(" "):
            flush()
            first = ln.rstrip(":").split(",")[0].strip().strip('"')
            head = first.rsplit("@", 1)[0] if "@" in first[1:] else None
            ver = src = None
            continue
        m = re.match(r"^\s+version:?\s+\"?([^\"\s]+)", ln)
        if m and ver is None:
            ver = m.group(1)
        m = re.match(r"^\s+(?:resolved|resolution):?\s+\"?([^\"\s]+)", ln)
        if m:
            src = m.group(1)
    flush()
    return out


def gemfile_lock(text: str) -> list:
    """Gemfile.lock: the `specs:` of GEM blocks (rubygems.org); GIT and PATH blocks are private and skipped."""
    out, section, in_specs = [], None, False
    for ln in text.splitlines():
        if re.match(r"^[A-Z]+$", ln):
            section, in_specs = ln, False
        elif ln.strip() == "specs:":
            in_specs = section == "GEM"
        elif in_specs:
            m = re.match(r"^    ([^\s()]+) \(([^)\s]+)\)$", ln)          # four spaces: a gem; six: its dependency ranges
            if m:
                ver = re.sub(r"-(?:x86_64|x86|arm64|aarch64|java|universal|mingw|mswin|darwin|linux|ruby).*$", "", m.group(2))
                out.append(("RubyGems", m.group(1), ver))
    return out


PARSERS = {"package-lock.json": package_lock, "Cargo.lock": cargo_lock, "composer.lock": composer_lock, "go.mod": go_mod,
           "poetry.lock": toml_lock, "uv.lock": toml_lock, "Pipfile.lock": pipfile_lock, "requirements.txt": requirements,
           "pnpm-lock.yaml": pnpm_lock, "yarn.lock": yarn_lock, "Gemfile.lock": gemfile_lock}


def find(root: str, depth: int = 3) -> list:
    root_p, out = Path(root).expanduser(), []
    if not root_p.is_dir():
        return out

    def walk(d: Path, level: int):
        try:
            entries = sorted(d.iterdir())
        except OSError:
            return
        for e in entries:
            if e.is_file() and e.name in PARSERS:
                out.append(e)
            elif e.is_dir() and level < depth and e.name not in SKIP_DIRS and not e.is_symlink():
                walk(e, level + 1)
    walk(root_p, 0)
    return out


def read(path: Path) -> tuple:
    """(packages, error). A broken lockfile is reported, never silently empty."""
    try:
        return sorted(set(PARSERS[path.name](path.read_text(errors="replace")))), None
    except (ValueError, KeyError, OSError, tomllib.TOMLDecodeError) as e:
        return [], f"{path}: {e}"
