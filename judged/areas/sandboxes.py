"""Flatpak apps and permissions, leftovers; containers and their images."""
from .. import containers, sandbox

NAME, ORDER = "sandboxes", 40


def run(cfg, ctx):
    out = []
    fp = cfg.get("flatpak")
    if fp is not None and fp.get("enabled", True):
        out += sandbox.flatpak_check(fp.get("accept"), fp.get("ignore"))
        if fp.get("leftovers", True):
            out += sandbox.flatpak_leftovers()
    ct = cfg.get("containers")
    if ct is not None and ct.get("enabled", True):
        out += containers.containers_check(ct.get("accept"), ct.get("max_image_age_days", 180), ct.get("scan", True),
                                           ct.get("max_scan_mb", 1000), ct.get("max_images", 10))
        out += containers.files_check(ct.get("projects", []))
    return out
