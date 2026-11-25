"""Is anything keeping logs, and do they survive a reboot (ISO 27001 A.8.15). Works on any init system judged/inits knows."""
from ..controls import M_LOGGING, Result

NAME, ORDER = "logging", 50
LOGGERS = ("systemd-journald", "auditd", "rsyslog", "syslog-ng", "socklog-unix", "metalog")


def check(cfg, env):
    on, asked, init = [], 0, ""
    for unit in LOGGERS:
        state, _, init = env.service([unit])
        if state is not None:
            asked += 1
        if state:
            on.append(unit)
    if not asked:
        return [Result("hardening.logging", "Logging", "unknown", f"cannot ask the init system ({init or 'unknown'}): not supported here or not reachable", M_LOGGING)]
    if not on:
        return [Result("hardening.logging", "Logging", "fail", f"no journald, auditd or syslog service is active ({init})", M_LOGGING)]
    notes = []
    if "systemd-journald" in on and not ({"rsyslog", "syslog-ng"} & set(on)):
        try:
            env.listdir("/var/log/journal")
        except OSError:
            notes.append("journal is kept in memory only (/var/log/journal missing): logs are lost at reboot")
    if "auditd" not in on:
        notes.append("auditd is not running (no record of who changed what at the system-call level)")
    return [Result("hardening.logging", "Logging", "warn" if notes else "pass", "; ".join(notes) or f"running: {', '.join(on)} ({init})", M_LOGGING)]
