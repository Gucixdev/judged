import pytest

from judged import host, inits, pkgmgrs
from judged.controls import M_FIREWALL
from judged.inits import dinit, openrc, runit, systemd
from judged.pkgmgrs import apt, dnf, pacman, xbps


def runs(table):
    """A fake `run`: command tuple -> (rc, stdout); anything else -> (None, '') as if the tool were missing."""
    return lambda cmd, timeout=20: table.get(tuple(cmd), (None, ""))


NOPE = lambda p: False


def test_every_init_system_has_a_file_and_the_known_ones_are_found():
    assert {"systemd", "dinit", "openrc", "runit"} <= {m.NAME for m in inits.discover()}


@pytest.mark.parametrize("pid1,exists,want", [
    ("systemd", NOPE, "systemd"), ("dinit", NOPE, "dinit"), ("runit", NOPE, "runit"), ("openrc-init", NOPE, "openrc"),
    ("init", lambda p: p == "/run/openrc", "openrc"), ("init", NOPE, None), ("s6-svscan", NOPE, None)])
def test_detection_from_pid1(pid1, exists, want):
    m, name = inits.current(read=lambda p: pid1 + "\n", exists=exists)
    assert (m.NAME if m else None) == want and name == pid1


def test_detection_without_proc_is_none():
    def boom(p):
        raise OSError
    assert inits.current(read=boom) == (None, "")


def test_systemd_answers():
    up = {("systemctl", "is-active", "ufw"): (0, "active\n"), ("systemctl", "is-active", "x"): (3, "inactive\n"), ("systemctl", "is-active", "f"): (3, "failed\n")}
    assert systemd.active("ufw", runs(up)) is True and systemd.active("x", runs(up)) is False and systemd.active("f", runs(up)) is False
    assert systemd.active("ufw", runs({})) is None                      # no systemctl: could not ask


def test_dinit_unreachable_daemon_is_none_not_down():
    ok = {("dinitctl", "list"): (0, ""), ("dinitctl", "is-started", "a"): (0, ""), ("dinitctl", "is-started", "b"): (1, "")}
    assert dinit.active("a", runs(ok)) is True and dinit.active("b", runs(ok)) is False
    assert dinit.active("a", runs({("dinitctl", "list"): (1, ""), ("dinitctl", "is-started", "a"): (1, "")})) is None
    assert dinit.active("a", runs({})) is None


def test_openrc_and_runit_answers():
    assert openrc.active("sshd", runs({("rc-service", "sshd", "status"): (0, "")})) is True
    assert openrc.active("sshd", runs({("rc-service", "sshd", "status"): (3, "")})) is False
    assert openrc.active("sshd", runs({})) is None
    assert runit.active("sshd", runs({("sv", "status", "sshd"): (0, "run: sshd: (pid 12) 5s\n")})) is True
    assert runit.active("sshd", runs({("sv", "status", "sshd"): (1, "down: sshd: 3s\n")})) is False
    assert runit.active("sshd", runs({("sv", "status", "sshd"): (1, "fail: sshd: unable to change to service directory\n")})) is False
    assert runit.active("sshd", runs({("sv", "status", "sshd"): (0, "runaway: not a runit state\n")})) is False          # only the exact `run:` state counts
    assert runit.active("sshd", runs({})) is None


def test_active_takes_the_first_unit_that_is_up_and_keeps_false_apart_from_none():
    r = runs({("systemctl", "is-active", "a"): (3, "inactive\n"), ("systemctl", "is-active", "b"): (0, "active\n")})
    assert inits.active(["a", "b"], r, read=lambda p: "systemd", exists=NOPE) == (True, "b", "systemd")
    assert inits.active(["a"], r, read=lambda p: "systemd", exists=NOPE) == (False, "", "systemd")
    assert inits.active(["zzz"], r, read=lambda p: "systemd", exists=NOPE) == (None, "", "systemd")      # the tool could not answer
    assert inits.active(["a"], r, read=lambda p: "s6-svscan", exists=NOPE) == (None, "", "s6-svscan")   # an init we have no file for


def test_host_service_reports_pass_warn_and_unknown(monkeypatch):
    real = inits.current
    monkeypatch.setattr(host, "run", runs({("sv", "status", "ufw"): (0, "run: ufw: (pid 1) 1s\n"), ("sv", "status", "nftables"): (1, "down: nftables: 1s\n")}))
    monkeypatch.setattr(inits, "current", lambda read=None, exists=None: real(read=lambda p: "runit", exists=NOPE))
    r = host.service(("ufw",), "T", "i", M_FIREWALL, "none")
    assert r.status == "pass" and "ufw is active (runit)" in r.evidence
    r = host.service(("nftables",), "T", "i", M_FIREWALL, "nothing up")
    assert r.status == "warn" and r.evidence == "nothing up (runit)"
    monkeypatch.setattr(inits, "current", lambda read=None, exists=None: real(read=lambda p: "s6-svscan", exists=NOPE))
    r = host.service(("ufw",), "T", "i", M_FIREWALL, "nothing up")
    assert r.status == "unknown" and "s6-svscan" in r.evidence


def test_package_manager_counts_and_missing_tools():
    assert pacman.pending(runs({("pacman", "-Qu"): (0, "a 1 -> 2\nb 1 -> 2\n")})) == 2 and pacman.pending(runs({})) is None
    assert xbps.pending(runs({("xbps-install", "-Mun"): (0, "a-1_1 update x\nb-1_1 update y\n\n")})) == 2
    assert apt.pending(runs({("apt-get", "-s", "upgrade"): (0, "Reading...\nInst libc6 [1] (2 x)\nInst bash [1] (2 x)\nConf bash\nIgnoring held back package\n")})) == 2
    assert dnf.pending(runs({("dnf", "-q", "check-update"): (100, "kernel.x86_64   6.1   updates\nbash.x86_64   5.2   updates\n")})) == 2
    assert dnf.pending(runs({("dnf", "-q", "check-update"): (0, "")})) == 0
    assert dnf.pending(runs({("dnf", "-q", "check-update"): (1, "error")})) is None


def test_pkgmgr_current_picks_the_installed_tool_and_updates_say_unknown_without_one(monkeypatch):
    assert pkgmgrs.current(which=lambda t: "/x" if t == "xbps-install" else None).NAME == "xbps"
    assert pkgmgrs.current(which=lambda t: None) is None
    monkeypatch.setattr(pkgmgrs, "current", lambda which=None: None)
    r = host.updates()
    assert r.status == "unknown" and "apt" in r.evidence and "xbps" in r.evidence


def test_updates_unknown_when_the_manager_does_not_answer_and_pass_when_nothing_pending(monkeypatch):
    class Fake:
        NAME, DB_GLOBS = "fake", []
        n = None
        pending = staticmethod(lambda run: Fake.n)
    monkeypatch.setattr(pkgmgrs, "current", lambda which=None: Fake)
    assert host.updates().status == "unknown"
    Fake.n = 0
    r = host.updates()
    assert r.status == "pass" and "0 pending (fake)" in r.evidence and "age of the package lists unknown" in r.evidence
    Fake.n = 3
    assert host.updates().status == "warn"
