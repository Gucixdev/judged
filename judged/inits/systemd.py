"""systemd (checked on this machine)."""
NAME = "systemd"


def detect(pid1, exists):
    return pid1 == "systemd"


def active(unit, run):
    rc, out = run(["systemctl", "is-active", unit])
    if rc is None:
        return None
    return out.strip() == "active"
