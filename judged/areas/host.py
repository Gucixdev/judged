"""This machine: OS hardening evidence and GPG keys."""
from .. import host, net

NAME, ORDER = "host", 10


def run(cfg, ctx):
    return host.all_checks(tuple(str(p) for p in cfg.get("hardening", {}).get("accept_ports", []))) + net.gpg()
