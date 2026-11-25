"""Setuid/setgid programs and world-writable files under the chosen paths."""
import fnmatch
import os
import stat

from ..controls import M_CONFIG, Result

NAME, ORDER = "suid", 30

# Programs that are normally setuid/setgid on a desktop or server Linux. A judgement, not a standard: a name here is "usual", not "safe".
USUAL = {"sudo", "su", "passwd", "chsh", "chfn", "chage", "expiry", "gpasswd", "newgrp", "mount", "umount", "pkexec", "fusermount", "fusermount3",
         "ping", "unix_chkpwd", "crontab", "at", "ssh-keysign", "newuidmap", "newgidmap", "doas", "polkit-agent-helper-1", "mount.nfs",
         "dbus-daemon-launch-helper", "Xorg.wrap", "lockdev", "wall", "write", "locate", "plocate", "ssh-agent", "chrome-sandbox", "bwrap", "sg", "vmware-user-suid-wrapper", "mount.cifs", "nvidia-modprobe", "ksu"}


def scan(paths: list):
    """(setid, world_writable, errors). Symlinks are not followed and mounts are not crossed, so /proc and other trees stay out."""
    setid, writable, errors = [], [], []
    for top in paths:
        try:
            dev = os.lstat(top).st_dev
        except OSError as e:
            errors.append(f"{top}: {e.strerror}")
            continue
        for root, dirs, files in os.walk(top, onerror=lambda e: errors.append(f"{e.filename}: {e.strerror}")):
            dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(root, d)) and os.lstat(os.path.join(root, d)).st_dev == dev]
            for name in files:
                p = os.path.join(root, name)
                try:
                    m = os.lstat(p).st_mode
                except OSError:
                    continue
                if stat.S_ISLNK(m) or not stat.S_ISREG(m):
                    continue
                if m & (stat.S_ISUID | stat.S_ISGID):
                    setid.append((p, "setuid" if m & stat.S_ISUID else "setgid"))
                if m & stat.S_IWOTH:
                    writable.append(p)
            for d in list(dirs):
                p = os.path.join(root, d)
                m = os.lstat(p).st_mode
                if m & stat.S_IWOTH and not m & stat.S_ISVTX:           # world-writable directory without the sticky bit: anyone can delete anyone's files
                    writable.append(p + "/")
    return sorted(setid), sorted(writable), errors


def check(cfg, env):
    paths = cfg.get("suid_paths", [])
    if not paths:
        return [Result("hardening.suid", "Setuid programs", "na", "no suid_paths in the config: nothing scanned", M_CONFIG)]
    setid, writable, errors = scan([os.path.expanduser(p) for p in paths])
    accept = cfg.get("suid_accept", [])
    unusual = [f"{p} ({k})" for p, k in setid if os.path.basename(p) not in USUAL and not any(fnmatch.fnmatch(p, a) for a in accept)]
    res = [Result("hardening.suid", "Setuid and setgid programs", "warn" if unusual else "pass",
                  (f"{len(unusual)} of {len(setid)} not on the usual list and not accepted: " + ", ".join(unusual[:12]) + (" ..." if len(unusual) > 12 else "")) if unusual
                  else f"{len(setid)} setuid/setgid files, all usual or accepted", M_CONFIG)]
    res.append(Result("hardening.worldwritable", "World-writable files", "fail" if writable else "pass",
                      (f"{len(writable)} under {', '.join(paths)}: " + ", ".join(writable[:10]) + (" ..." if len(writable) > 10 else "")) if writable
                      else f"none under {', '.join(paths)}", M_CONFIG))
    if errors:
        res.append(Result("hardening.suid_scan", "Setuid scan coverage", "unknown", f"{len(errors)} places could not be read, so the lists above may be short: " + "; ".join(errors[:4]), M_CONFIG))
    return res
