"""deps.dev: npm, Cargo, Go, PyPI, Maven, RubyGems, NuGet (checked live; Packagist answers 404 there)."""
import urllib.request

SYSTEMS = {"npm": "npm", "crates.io": "cargo", "Go": "go", "PyPI": "pypi", "Maven": "maven", "RubyGems": "rubygems", "NuGet": "nuget"}
ECOSYSTEMS = tuple(SYSTEMS)


def licence(eco, name, version, get):
    q = urllib.request.quote
    d = get(f"https://api.deps.dev/v3/systems/{SYSTEMS[eco]}/packages/{q(name, safe='')}/versions/{q(version, safe='')}")
    return " AND ".join(d.get("licenses", [])) or ""
