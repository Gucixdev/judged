"""pacman / paru (Arch, CachyOS). Checked on this machine."""
NAME, TOOL = "pacman", "pacman"
DB_GLOBS = ["/var/lib/pacman/sync/*.db"]


def pending(run):
    rc, out = run(["pacman", "-Qu"])
    return None if rc is None else len([l for l in out.splitlines() if l.strip()])
