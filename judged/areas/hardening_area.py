"""Host hardening audits (judged/hardening/, one file per audit)."""
from .. import hardening

NAME, ORDER = "hardening", 12
SPEC = {"hardening": ((), {"enabled": "bool", "skip": "list", "accept_ports": "list", "sysctl_accept": "list", "suid_paths": "list", "suid_accept": "list",
                           "sudoers_accept": "list", "ssh_strict_forwarding": "bool", "ssh_dir": "str", "ssh_key_max_age_days": "int",
                           "ssh_min_rsa_bits": "int", "ssh_keys_accept": "list"}, "section")}
DEFAULTS = {"hardening": {"enabled": True, "skip": [], "accept_ports": [], "sysctl_accept": [], "suid_paths": ["/usr", "/etc"], "suid_accept": [],
                          "sudoers_accept": [], "ssh_strict_forwarding": False, "ssh_dir": "~/.ssh", "ssh_key_max_age_days": 730,
                          "ssh_min_rsa_bits": 3072, "ssh_keys_accept": []}}
DOC = {"hardening": "enabled = run the audits in judged/hardening; skip = audit names to leave out; accept_ports = listening ports you know about; "
                    "sysctl_accept = kernel settings you chose to leave; suid_paths = folders scanned for setuid and world-writable files; "
                    "suid_accept = path globs of setuid files you reviewed; sudoers_accept = text of sudo rules you reviewed; ssh_dir = folder with your SSH keys; ssh_key_max_age_days = key files older than this are flagged for rotation; ssh_min_rsa_bits = smallest RSA key accepted; ssh_keys_accept = private key file names allowed without a passphrase"}


def run(cfg, ctx):
    h = cfg.get("hardening")
    if not h or not h.get("enabled", True):
        return []
    return hardening.run_all(h)
