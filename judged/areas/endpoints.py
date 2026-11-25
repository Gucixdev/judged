"""TLS and website items from the config: `tls HOST`, `site HOST`."""
from .. import net, pageassets, web

NAME, ORDER = "endpoints", 20


def run(cfg, ctx):
    out = []
    for e in cfg.get("item", []):
        if e["kind"] == "tls":
            out += net.tls(e["host"], port=e.get("port", 443))
        elif e["kind"] == "site":
            out += web.site(e["host"])
            out.append(web.dnssec(e["host"]))
            if e.get("images", True):
                out += pageassets.check(e["host"], web.fetch)
    return out
