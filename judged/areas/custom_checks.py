"""Your own `check NAME cmd=... maps=...` lines."""
from .. import rules

NAME, ORDER = "custom checks", 70


def run(cfg, ctx):
    return [rules.run(c) for c in cfg.get("checks", [])]
