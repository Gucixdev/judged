"""dinit. NOT checked against a real dinit (none on this machine): the commands are from its documentation."""
NAME = "dinit"


def detect(pid1, exists):
    return pid1 == "dinit"


def active(unit, run):
    rc, _ = run(["dinitctl", "list"])
    if rc != 0:                              # daemon unreachable or dinitctl missing: say "could not ask", not "down"
        return None
    rc, _ = run(["dinitctl", "is-started", unit])
    return None if rc is None else rc == 0
