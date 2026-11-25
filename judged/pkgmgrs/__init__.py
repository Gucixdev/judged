"""Which package manager this machine uses, and how many updates wait. One file per package manager, found automatically:

    NAME = "xbps"
    TOOL = "xbps-install"                          # the program that must exist
    def pending(run) -> int | None                 # number of upgradable packages, None if it could not be listed
    DB_GLOBS = ["/var/db/xbps/*.plist"]            # package lists whose age tells how stale the answer is (optional)

A new package manager is a new file. The first one whose TOOL is on PATH answers; none means `unknown`, not "no updates"."""
import importlib
import pkgutil
import shutil


def discover() -> list:
    return [importlib.import_module(f"{__name__}.{m.name}") for m in pkgutil.iter_modules(__path__)]


def current(which=shutil.which):
    for m in sorted(discover(), key=lambda m: m.NAME):
        if which(m.TOOL):
            return m
    return None
