"""SSH server settings beyond root login and passwords (those two are `host.ssh`). Read from sshd_config, not from `sshd -T` (needs root),
so a setting that only a drop-in file or the compiled-in default decides is shown as such."""
from .. import host
from ..controls import M_ACCESS, Result

NAME, ORDER = "ssh_server", 20


def check(cfg, env):
    try:
        c = host.parse_sshd(env.read("/etc/ssh/sshd_config"), env.read)
    except FileNotFoundError:
        return [Result("hardening.ssh_server", "SSH server settings", "na", "no sshd_config: no SSH server installed", M_ACCESS)]
    except OSError as e:
        return [Result("hardening.ssh_server", "SSH server settings", "unknown", f"cannot read sshd_config: {e}", M_ACCESS)]
    bad, fail = [], []
    if c.get("permitemptypasswords", "no") == "yes":
        fail.append("PermitEmptyPasswords yes: accounts without a password can log in")
    if c.get("pubkeyauthentication", "yes") == "no":
        bad.append("PubkeyAuthentication no: keys are switched off")
    if c.get("x11forwarding", "no") == "yes":
        bad.append("X11Forwarding yes")
    if c.get("hostbasedauthentication", "no") == "yes":
        bad.append("HostbasedAuthentication yes")
    tries = c.get("maxauthtries", "6")
    if tries.isdigit() and int(tries) > 6:
        bad.append(f"MaxAuthTries {tries} (more than 6 guesses per connection)")
    if c.get("permituserenvironment", "no") == "yes":
        bad.append("PermitUserEnvironment yes")
    if c.get("allowagentforwarding", "yes") == "yes" and c.get("allowtcpforwarding", "yes") == "yes" and cfg.get("ssh_strict_forwarding", False):
        bad.append("agent and TCP forwarding both allowed")
    shown = "; ".join(fail + bad)
    return [Result("hardening.ssh_server", "SSH server settings", "fail" if fail else "warn" if bad else "pass",
                   shown or "empty passwords refused, keys on, X11 and host-based login off, at most 6 tries (defaults counted where nothing is set)", M_ACCESS)]
