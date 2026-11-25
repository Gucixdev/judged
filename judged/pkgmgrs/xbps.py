"""xbps (Void). NOT checked against a real xbps: `xbps-install -Mun` (local repo data, dry run, list) is from its manual."""
NAME, TOOL = "xbps", "xbps-install"
DB_GLOBS = ["/var/db/xbps/*.plist"]


def pending(run):
    rc, out = run(["xbps-install", "-Mun"])
    return None if rc is None else len([l for l in out.splitlines() if l.strip()])
