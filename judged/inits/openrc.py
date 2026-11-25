"""OpenRC. NOT checked against a real OpenRC: the commands are from its documentation."""
NAME = "openrc"


def detect(pid1, exists):
    return pid1 == "openrc-init" or (pid1 == "init" and exists("/run/openrc"))


def active(unit, run):
    rc, _ = run(["rc-service", unit, "status"])
    return None if rc is None else rc == 0
