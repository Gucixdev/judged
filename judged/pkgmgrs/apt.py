"""apt (Debian, Ubuntu). NOT checked against a real apt: `apt-get -s upgrade` (simulation) lines starting with `Inst ` are upgrades."""
NAME, TOOL = "apt", "apt-get"
DB_GLOBS = ["/var/lib/apt/lists/*_Packages*", "/var/lib/apt/lists/*_InRelease"]


def pending(run):
    rc, out = run(["apt-get", "-s", "upgrade"])
    return None if rc is None else len([l for l in out.splitlines() if l.startswith("Inst ")])
