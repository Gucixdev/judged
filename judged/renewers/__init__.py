"""Things judged can renew besides TLS certificates. One file per kind, found automatically. A file here has

    NAME = "gpg"
    def handles(e: dict) -> bool                                           # does this `renew` entry belong to me
    def renew_one(e, last_attempt, dry, now, run) -> (status, message, attempted)    # same answer as renew.renew_one

status: ok | wait | would-renew | renewed | failed. A new kind is a new file, nothing else changes."""
import importlib
import pkgutil


def discover() -> list:
    return [importlib.import_module(f"{__name__}.{m.name}") for m in pkgutil.iter_modules(__path__)]


def find(e: dict):
    for m in discover():
        if m.handles(e):
            return m
    return None
