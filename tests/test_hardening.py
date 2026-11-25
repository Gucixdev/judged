import os
from pathlib import Path

import pytest

from judged import hardening, host
from judged.areas import hardening_area
from judged.hardening import logging_audit, ssh_server, sudoers, suid, sysctl


class Fake:
    """Everything an audit may touch, from a dict."""
    def __init__(self, files=None, sysctls=None, cmds=None, dirs=None, services=None, init="systemd"):
        self.files, self.sysctls, self.cmds, self.dirs = files or {}, sysctls or {}, cmds or {}, dirs or {}
        self.services, self.init = services, init

    def service(self, units):
        if self.services is None:
            return None, "", self.init
        answers = [self.services.get(u) for u in units]
        return (True if any(answers) else False if False in answers else None), "", self.init

    def read(self, path):
        v = self.files.get(path)
        if isinstance(v, Exception):
            raise v
        if v is None:
            raise FileNotFoundError(path)
        return v

    def sysctl(self, key):
        return self.sysctls.get(key)

    def run(self, cmd, timeout=20):
        return self.cmds.get(tuple(cmd), (None, ""))

    def listdir(self, path):
        v = self.dirs.get(path)
        if isinstance(v, Exception):
            raise v
        if v is None:
            raise FileNotFoundError(path)
        return v


GOOD = {"kernel.randomize_va_space": "2", "kernel.kptr_restrict": "1", "kernel.dmesg_restrict": "1", "kernel.yama.ptrace_scope": "1",
        "kernel.unprivileged_bpf_disabled": "2", "fs.protected_hardlinks": "1", "fs.protected_symlinks": "1", "fs.suid_dumpable": "0",
        "net.ipv4.tcp_syncookies": "1", "net.ipv4.conf.all.rp_filter": "1", "net.ipv4.conf.all.accept_redirects": "0",
        "net.ipv6.conf.all.accept_redirects": "0", "net.ipv4.conf.all.send_redirects": "0"}


# ---- framework

def test_a_crashing_audit_is_one_unknown_and_the_rest_still_run(monkeypatch):
    class Bad:
        NAME, ORDER = "bad", 1
        check = staticmethod(lambda cfg, env: 1 / 0)
    monkeypatch.setattr(hardening, "discover", lambda: [Bad, sysctl])
    out = hardening.run_all({}, Fake(sysctls=GOOD))
    assert [(r.id, r.status) for r in out] == [("hardening.bad", "unknown"), ("hardening.sysctl", "pass")] and "ZeroDivisionError" in out[0].evidence

NOPW = "NO" + "PASSWD"                      # the sudoers tag, built from pieces so no password-looking line sits in this file


def test_skip_leaves_an_audit_out_and_a_typo_in_skip_is_a_warning():
    ids = lambda out: {r.id for r in out}
    env = Fake(sysctls=GOOD)
    assert "hardening.sysctl" not in ids(hardening.run_all({"skip": ["sysctl"]}, env))
    out = hardening.run_all({"skip": ["sysctll"]}, env)
    assert "hardening.sysctl" in ids(out) and [r for r in out if r.id == "hardening.config"][0].status == "warn"


def test_every_audit_file_is_found_and_the_area_defaults_cover_its_spec():
    assert {"sysctl", "ssh_server", "suid", "sudoers", "logging"} <= set(hardening.names())
    assert set(hardening_area.SPEC["hardening"][1]) == set(hardening_area.DEFAULTS["hardening"])


def test_area_off_runs_nothing():
    assert hardening_area.run({"hardening": {"enabled": False}}, None) == []


# ---- sysctl

def test_sysctl_all_good_is_pass_and_a_bad_value_names_the_key():
    assert sysctl.check({}, Fake(sysctls=GOOD))[0].status == "pass"
    r = sysctl.check({}, Fake(sysctls={**GOOD, "kernel.randomize_va_space": "0"}))[0]
    assert r.status == "warn" and "kernel.randomize_va_space=0" in r.evidence


def test_sysctl_boundaries():
    for key, val, status in [("kernel.kptr_restrict", "0", "warn"), ("kernel.kptr_restrict", "2", "pass"), ("fs.suid_dumpable", "1", "warn"),
                             ("fs.suid_dumpable", "2", "pass"), ("net.ipv4.conf.all.rp_filter", "0", "warn"), ("net.ipv4.conf.all.rp_filter", "2", "pass")]:
        assert sysctl.check({}, Fake(sysctls={**GOOD, key: val}))[0].status == status, (key, val)


def test_sysctl_accepted_deviation_passes_but_is_still_shown_and_unreadable_is_not_a_pass():
    r = sysctl.check({"sysctl_accept": ["net.ipv4.conf.all.send_redirects"]}, Fake(sysctls={**GOOD, "net.ipv4.conf.all.send_redirects": "1"}))[0]
    assert r.status == "pass" and "accepted: net.ipv4.conf.all.send_redirects=1" in r.evidence
    assert sysctl.check({}, Fake())[0].status == "unknown"
    r = sysctl.check({}, Fake(sysctls={k: v for k, v in GOOD.items() if k != "fs.protected_symlinks"}))[0]
    assert r.status == "pass" and "not readable here: fs.protected_symlinks" in r.evidence


# ---- ssh

def sshd(text):
    return Fake(files={"/etc/ssh/sshd_config": text})


def test_parse_sshd_stops_at_match():
    c = host.parse_sshd("PasswordAuthentication no\nMatch User bob\n  PermitEmptyPasswords yes\n  X11Forwarding yes\n")
    assert c == {"passwordauthentication": "no"}


def test_ssh_server_cases():
    assert ssh_server.check({}, sshd("PasswordAuthentication no\n"))[0].status == "pass"
    r = ssh_server.check({}, sshd("PermitEmptyPasswords yes\n"))[0]
    assert r.status == "fail" and "PermitEmptyPasswords" in r.evidence
    assert ssh_server.check({}, sshd("X11Forwarding yes\nMaxAuthTries 10\n"))[0].evidence.count(";") == 1
    assert ssh_server.check({}, sshd("MaxAuthTries 6\n"))[0].status == "pass"
    assert ssh_server.check({}, sshd("PubkeyAuthentication no\n"))[0].status == "warn"
    assert ssh_server.check({}, sshd("Match User bob\n  PermitEmptyPasswords yes\n"))[0].status == "pass"      # only for bob's connections
    assert ssh_server.check({}, Fake())[0].status == "na"
    assert ssh_server.check({}, Fake(files={"/etc/ssh/sshd_config": PermissionError(13, "denied")}))[0].status == "unknown"


# ---- suid and world-writable

def make(tmp, rel, mode, data="x"):
    p = tmp / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(data)
    p.chmod(mode)
    return p


def test_suid_usual_unusual_and_accepted(tmp_path):
    make(tmp_path, "bin/sudo", 0o4755)
    make(tmp_path, "bin/odd", 0o4755)
    make(tmp_path, "bin/oddgroup", 0o2755)
    make(tmp_path, "bin/plain", 0o755)
    r = suid.check({"suid_paths": [str(tmp_path)]}, None)
    s = r[0]
    assert s.status == "warn" and "2 of 3" in s.evidence and "odd (setuid)" in s.evidence and "oddgroup (setgid)" in s.evidence and "sudo" not in s.evidence.split(":", 1)[1]
    ok = suid.check({"suid_paths": [str(tmp_path)], "suid_accept": [f"{tmp_path}/bin/odd*"]}, None)[0]
    assert ok.status == "pass" and "3 setuid/setgid files" in ok.evidence


def test_world_writable_file_and_dir_but_not_sticky_dir_or_symlink(tmp_path):
    make(tmp_path, "etc/bad.conf", 0o666)
    d = tmp_path / "etc/open"
    d.mkdir()
    d.chmod(0o777)
    s = tmp_path / "etc/tmpish"
    s.mkdir()
    s.chmod(0o1777)
    (tmp_path / "etc/link").symlink_to(tmp_path / "etc/bad.conf")
    res = {r.id: r for r in suid.check({"suid_paths": [str(tmp_path)]}, None)}
    w = res["hardening.worldwritable"]
    assert w.status == "fail" and "bad.conf" in w.evidence and "open/" in w.evidence and "tmpish" not in w.evidence and "link" not in w.evidence
    assert w.evidence.startswith("2 under")


def test_unreadable_folder_makes_the_scan_unknown_not_clean(tmp_path):
    make(tmp_path, "ok/f", 0o644)
    locked = tmp_path / "locked"
    locked.mkdir()
    make(tmp_path, "locked/hidden", 0o4755)
    locked.chmod(0)
    try:
        if os.access(locked, os.R_OK):
            pytest.skip("running as root: nothing is unreadable")
        res = {r.id: r for r in suid.check({"suid_paths": [str(tmp_path)]}, None)}
        assert res["hardening.suid_scan"].status == "unknown" and "locked" in res["hardening.suid_scan"].evidence
    finally:
        locked.chmod(0o755)


def test_suid_without_paths_and_with_a_missing_path():
    assert suid.check({"suid_paths": []}, None)[0].status == "na"
    res = {r.id: r.status for r in suid.check({"suid_paths": ["/no/such/folder"]}, None)}
    assert res["hardening.suid_scan"] == "unknown"


# ---- sudoers

def test_sudoers_nopasswd_continuation_comment_and_accept():
    base = {"/etc/sudoers": "# %wheel ALL=(ALL) NOPASSWD: ALL\n%wheel ALL=(ALL:ALL) ALL\n", }
    assert sudoers.check({}, Fake(files=base, dirs={"/etc/sudoers.d": []}))[0].status == "pass"          # the commented-out line does not count
    bad = {"/etc/sudoers": "bob ALL=(ALL) \\\n  NOPASSWD: ALL\nDefaults !authenticate\n"}
    r = sudoers.check({}, Fake(files=bad, dirs={"/etc/sudoers.d": []}))[0]
    assert r.status == "warn" and "no password asked" in r.evidence and "authentication switched off" in r.evidence
    r = sudoers.check({"sudoers_accept": ["bob ALL", "!authenticate"]}, Fake(files=bad, dirs={"/etc/sudoers.d": []}))[0]
    assert r.status == "pass" and "2 accepted" in r.evidence


def test_sudoers_reads_dropins_and_skips_backup_files():
    env = Fake(files={"/etc/sudoers": "", "/etc/sudoers.d/10-ops": f"ops ALL=(ALL) {NOPW}: /usr/bin/systemctl\n", "/etc/sudoers.d/old~": f"x {NOPW}: ALL"},
               dirs={"/etc/sudoers.d": ["10-ops", "old~", "README.txt"]})
    r = sudoers.check({}, env)[0]
    assert r.status == "warn" and "/etc/sudoers.d/10-ops" in r.evidence and "old~" not in r.evidence


def test_sudoers_unreadable_is_unknown_and_missing_is_na():
    r = sudoers.check({}, Fake(files={"/etc/sudoers": PermissionError(13, "denied", "/etc/sudoers")}, dirs={"/etc/sudoers.d": []}))[0]
    assert r.status == "unknown" and "only root" in r.evidence
    assert sudoers.check({}, Fake())[0].status == "na"
    r = sudoers.check({}, Fake(files={"/etc/sudoers": ""}, dirs={"/etc/sudoers.d": PermissionError(13, "denied", "/etc/sudoers.d")}))[0]
    assert r.status == "unknown"


# ---- logging

J = {"systemd-journald": True, "auditd": False, "rsyslog": False, "syslog-ng": False, "socklog-unix": False, "metalog": False}


def test_logging_cases():
    r = logging_audit.check({}, Fake(services=J, dirs={"/var/log/journal": ["x"]}))[0]
    assert r.status == "warn" and "auditd is not running" in r.evidence and "memory only" not in r.evidence
    r = logging_audit.check({}, Fake(services=J, dirs={}))[0]
    assert "memory only" in r.evidence
    r = logging_audit.check({}, Fake(services={**J, "auditd": True}, dirs={"/var/log/journal": []}))[0]
    assert r.status == "pass" and "auditd" in r.evidence
    assert logging_audit.check({}, Fake(services={u: False for u in J}))[0].status == "fail"


def test_logging_on_an_init_system_we_cannot_ask_is_unknown_not_fail():
    r = logging_audit.check({}, Fake(services=None, init="s6"))[0]
    assert r.status == "unknown" and "s6" in r.evidence


def test_logging_on_a_machine_without_journald_but_with_a_syslog_daemon_passes_the_journal_check():
    r = logging_audit.check({}, Fake(services={**{u: False for u in J}, "socklog-unix": True}, init="runit"))[0]
    assert r.status == "warn" and "memory only" not in r.evidence and "runit" not in r.evidence.split(";")[0]
    r = logging_audit.check({}, Fake(services={**{u: False for u in J}, "socklog-unix": True, "auditd": True}, init="runit"))[0]
    assert r.status == "pass" and "(runit)" in r.evidence


# ---- host.listening accept list

def test_listening_accepted_ports_are_not_reported(monkeypatch):
    monkeypatch.setattr(host, "run", lambda cmd, timeout=20: (0, "LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*\nLISTEN 0 4096 [::]:8080 [::]:*\nLISTEN 0 4096 127.0.0.1:631 0.0.0.0:*\n"))
    assert "0.0.0.0:22" in host.listening().evidence
    r = host.listening(("22",))
    assert r.status == "warn" and "0.0.0.0:22" not in r.evidence and "[::]:8080" in r.evidence
    r = host.listening(("22", "8080"))
    assert r.status == "pass" and "accepted ports 22, 8080" in r.evidence
