"""dnf (Fedora, RHEL). NOT checked against a real dnf: `dnf -q check-update` exits 100 when updates exist and prints one package per line."""
NAME, TOOL = "dnf", "dnf"
DB_GLOBS = ["/var/cache/dnf/*/repodata/repomd.xml"]


def pending(run):
    rc, out = run(["dnf", "-q", "check-update"])
    if rc is None or rc not in (0, 100):
        return None
    return 0 if rc == 0 else len([l for l in out.splitlines() if l.strip() and not l.startswith(("Obsoleting", "Security:")) and len(l.split()) == 3])
