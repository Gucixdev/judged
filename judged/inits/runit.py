"""runit (Void Linux). NOT checked against a real runit: the commands are from its documentation."""
NAME = "runit"


def detect(pid1, exists):
    return pid1 == "runit"


def active(unit, run):
    rc, out = run(["sv", "status", unit])
    if rc is None:
        return None
    return out.lstrip().startswith("run:")
