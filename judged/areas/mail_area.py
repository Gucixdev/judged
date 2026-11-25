"""SPF, DKIM-less basics and DMARC of your mail domains."""
from .. import mail

NAME, ORDER = "mail", 100


def run(cfg, ctx):
    out = []
    for d in cfg.get("company", {}).get("mail_domains", []):
        out += mail.mail(d)
    return out
