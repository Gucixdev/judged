"""Kernel hardening settings from /proc/sys (readable without root)."""
from ..controls import M_CONFIG, Result

NAME, ORDER = "sysctl", 10

# key -> (what is wanted, test on the integer value). The list is my reading of common hardening guides (CIS, KSPP, kernel docs), not a standard.
WANT = {
    "kernel.randomize_va_space": ("2 (full address randomisation)", lambda v: v == 2),
    "kernel.kptr_restrict": ("1 or 2 (kernel addresses hidden)", lambda v: v >= 1),
    "kernel.dmesg_restrict": ("1 (kernel log for root only)", lambda v: v == 1),
    "kernel.yama.ptrace_scope": ("1 or more (no tracing of other users' processes)", lambda v: v >= 1),
    "kernel.unprivileged_bpf_disabled": ("1 or 2 (no BPF for ordinary users)", lambda v: v >= 1),
    "fs.protected_hardlinks": ("1", lambda v: v == 1),
    "fs.protected_symlinks": ("1", lambda v: v == 1),
    "fs.suid_dumpable": ("0 or 2 (1 lets setuid programs dump readable memory)", lambda v: v != 1),
    "net.ipv4.tcp_syncookies": ("1", lambda v: v == 1),
    "net.ipv4.conf.all.rp_filter": ("1 or 2 (spoofed source addresses dropped)", lambda v: v >= 1),
    "net.ipv4.conf.all.accept_redirects": ("0", lambda v: v == 0),
    "net.ipv6.conf.all.accept_redirects": ("0", lambda v: v == 0),
    "net.ipv4.conf.all.send_redirects": ("0 (unless this machine is a router)", lambda v: v == 0),
}


def check(cfg, env):
    accept, bad, accepted, unread = set(cfg.get("sysctl_accept", [])), [], [], []
    for key, (want, ok) in WANT.items():
        raw = env.sysctl(key)
        try:
            val = int(raw)
        except (TypeError, ValueError):
            unread.append(key)
            continue
        if not ok(val):
            (accepted if key in accept else bad).append(f"{key}={val} (want {want})")
    read = len(WANT) - len(unread)
    note = f"; accepted: {', '.join(accepted)}" if accepted else ""
    if not read:
        return [Result("hardening.sysctl", "Kernel hardening settings", "unknown", "no setting could be read (/proc/sys not available)", M_CONFIG)]
    if bad:
        return [Result("hardening.sysctl", "Kernel hardening settings", "warn", "; ".join(bad) + note + (f"; not readable: {', '.join(unread)}" if unread else ""), M_CONFIG)]
    return [Result("hardening.sysctl", "Kernel hardening settings", "pass",
                   f"{read} of {len(WANT)} settings checked, all as wanted" + note + (f"; not readable here: {', '.join(unread)}" if unread else ""), M_CONFIG)]
