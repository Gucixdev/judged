import os
import shutil
import subprocess
import time
from types import SimpleNamespace

import pytest

from judged import conf, renew, renewers
from judged.renewers import gpg

FPR = "0123456789ABCDEF0123456789ABCDEF01234567"
NOW = 1_800_000_000.0
DAY = 86400


def colons(expiry, state="u"):
    return f"tru::1:1:1:0:3:1:5\npub:{state}:255:22:AAAABBBBCCCCDDDD:1700000000:{expiry}::u:::scESC:::::ed25519:::0:\nfpr:::::::::{FPR}:\n"


class Gpg:
    """A fake gpg: --list-keys answers from `expiry`; --quick-set-expire moves it (or fails)."""
    def __init__(self, expiry, state="u", set_rc=0, move=True, list_rc=0, subs_rc=None):
        self.expiry, self.state, self.set_rc, self.move, self.list_rc, self.subs_rc, self.calls = expiry, state, set_rc, move, list_rc, subs_rc, []

    def __call__(self, cmd, capture_output=True, text=True, timeout=0):
        self.calls.append(cmd)
        if "--list-keys" in cmd:
            return SimpleNamespace(returncode=self.list_rc, stdout=colons(self.expiry, self.state) if self.list_rc == 0 else "", stderr="gpg: error reading key: No public key\n")
        rc = self.subs_rc if (self.subs_rc is not None and cmd[-1] == "*") else self.set_rc
        if rc == 0 and self.move and cmd[-1] != "*":
            self.expiry = int(NOW + 365 * DAY)
        return SimpleNamespace(returncode=rc, stdout="", stderr="gpg: signing failed: No pinentry\n" if rc else "")


def e(**kw):
    return {"host": "gpg:" + FPR, "when_days": 30, "extend_by": "1y", **kw}


def test_handles_only_gpg_hosts_and_the_loader_finds_it():
    assert gpg.handles({"host": "gpg:" + FPR}) and not gpg.handles({"host": "www.example.com"})
    assert renewers.find({"host": "gpg:x"}) is gpg and renewers.find({"host": "example.com"}) is None


def test_plenty_of_time_does_nothing():
    g = Gpg(int(NOW + 31 * DAY))
    assert gpg.renew_one(e(), None, False, NOW, g) == ("ok", "31 days left", False)
    assert len(g.calls) == 1                                           # only the read


def test_boundary_exactly_when_days_is_due():
    assert gpg.renew_one(e(), None, True, NOW, Gpg(int(NOW + 30 * DAY)))[0] == "would-renew"
    assert gpg.renew_one(e(), None, True, NOW, Gpg(int(NOW + 30 * DAY + 3600)))[0] == "ok"


def test_dry_run_changes_nothing():
    g = Gpg(int(NOW + 5 * DAY))
    st, msg, tried = gpg.renew_one(e(), None, True, NOW, g)
    assert (st, tried) == ("would-renew", False) and "5 days left" in msg and len(g.calls) == 1


def test_renewal_extends_primary_then_subkeys_and_verifies():
    g = Gpg(int(NOW + 5 * DAY))
    st, msg, tried = gpg.renew_one(e(homedir="/h"), None, False, NOW, g)
    assert (st, tried) == ("renewed", True) and "365 days" in msg and "publish it again" in msg and "does not upload" in msg
    setters = [c for c in g.calls if "--quick-set-expire" in c]
    assert setters == [["gpg", "--batch", "--homedir", "/h", "--yes", "--quick-set-expire", FPR, "1y"],
                       ["gpg", "--batch", "--homedir", "/h", "--yes", "--quick-set-expire", FPR, "1y", "*"]]
    assert g.calls[0][:4] == ["gpg", "--batch", "--homedir", "/h"] and g.calls[0][-1] == FPR and "--fixed-list-mode" in g.calls[0]


def test_an_expired_key_is_extended_too():
    st, msg, _ = gpg.renew_one(e(), None, False, NOW, Gpg(int(NOW - 3 * DAY), state="e"))
    assert st == "renewed"


def test_revoked_and_no_expiry_are_left_alone():
    g = Gpg(int(NOW + DAY), state="r")
    assert gpg.renew_one(e(), None, False, NOW, g)[:1] == ("failed",) and len(g.calls) == 1 and "revoked" in gpg.renew_one(e(), None, False, NOW, Gpg(1, state="r"))[1]
    g = Gpg("")
    assert gpg.renew_one(e(), None, False, NOW, g) == ("ok", "the key has no expiry date, nothing to extend", False)
    assert len(g.calls) == 1


def test_wait_when_tried_recently_and_retry_after_the_interval():
    assert gpg.renew_one(e(), NOW - 3600, False, NOW, Gpg(int(NOW + DAY)))[0] == "wait"
    assert gpg.renew_one(e(), NOW - 7 * 3600, False, NOW, Gpg(int(NOW + DAY)))[0] == "renewed"


def test_failures_are_reported_and_counted_as_an_attempt_when_gpg_ran():
    st, msg, tried = gpg.renew_one(e(), None, False, NOW, Gpg(int(NOW + DAY), set_rc=2))
    assert (st, tried) == ("failed", True) and "gpg exit 2 for the primary key" in msg and "No pinentry" in msg
    g = Gpg(int(NOW + DAY), subs_rc=1)
    st, msg, tried = gpg.renew_one(e(), None, False, NOW, g)
    assert (st, tried) == ("failed", True) and "for the subkeys" in msg
    st, msg, tried = gpg.renew_one(e(), None, False, NOW, Gpg(int(NOW + DAY), move=False))
    assert (st, tried) == ("failed", True) and "did not move" in msg


def test_timeout_and_missing_gpg():
    def hang(cmd, **kw):
        if "--list-keys" in cmd:
            return Gpg(int(NOW + DAY))(cmd)
        raise subprocess.TimeoutExpired(cmd, 1)
    st, msg, tried = gpg.renew_one(e(), None, False, NOW, hang)
    assert (st, tried) == ("failed", True) and "passphrase prompt" in msg
    def none(cmd, **kw):
        raise FileNotFoundError("gpg")
    st, msg, tried = gpg.renew_one(e(), None, False, NOW, none)
    assert (st, tried) == ("failed", False) and "cannot read the key" in msg


def test_unknown_key_and_bad_input_never_reach_gpg_set():
    g = Gpg(0, list_rc=2)
    st, msg, tried = gpg.renew_one(e(), None, False, NOW, g)
    assert (st, tried) == ("failed", False) and "No public key" in msg
    for host, kw, word in [("gpg:0123ABCD", {}, "not a full fingerprint"), ("gpg:" + FPR, {"extend_by": "forever"}, "extend_by"), ("gpg:" + FPR[:-1] + "Z", {}, "not a full fingerprint"),
                         ("gpg:" + FPR[:16], {}, "not a full fingerprint"), ("gpg:" + FPR[:-1], {}, "not a full fingerprint"), ("gpg:" + FPR + "0", {}, "not a full fingerprint")]:
        g = Gpg(int(NOW + DAY))
        st, msg, tried = gpg.renew_one({"host": host, "when_days": 30, **kw}, None, False, NOW, g)
        assert st == "failed" and word in msg and not tried and g.calls == []
    for ok in ("2y", "6m", "30d", "1w", "2030-01-31", "20300131T000000"):
        assert gpg.SPAN.match(ok)
    assert gpg.renew_one({"host": "gpg:" + "a" * 64, "extend_by": "1y"}, None, True, NOW, Gpg(int(NOW + DAY)))[0] == "would-renew"


def test_the_tls_renewer_dispatches_to_the_gpg_plugin():
    g = Gpg(int(NOW + DAY))
    assert renew.renew_one(e(), None, True, NOW, g)[0] == "would-renew"


def test_config_accepts_gpg_renew_without_cmd_and_still_requires_it_for_hosts(tmp_path):
    p = tmp_path / "c.conf"
    p.write_text(f"renew gpg:{FPR} when_days=30 extend_by=2y homedir=/h\n")
    assert conf.load(p)["renew"][0]["extend_by"] == "2y"
    p.write_text("renew www.example.com when_days=21\n")
    with pytest.raises(conf.ConfError):
        conf.load(p)


@pytest.mark.skipif(shutil.which("gpg") is None, reason="gpg not installed")
def test_real_gpg_extends_primary_key_and_subkeys(tmp_path):
    home = tmp_path / "g"
    home.mkdir(mode=0o700)
    base = ["gpg", "--homedir", str(home), "--batch"]
    try:
        subprocess.run(base + ["--pinentry-mode", "loopback", "--passphrase", "", "--quick-gen-key", "judged-test@example.invalid", "default", "default", "10d"],
                       check=True, capture_output=True, timeout=120)
        fpr = [l.split(":")[9] for l in subprocess.run(base + ["--list-keys", "--with-colons"], capture_output=True, text=True).stdout.splitlines() if l.startswith("fpr")][0]
        ent = {"host": "gpg:" + fpr, "homedir": str(home), "when_days": 30, "extend_by": "1y"}
        st, msg, _ = gpg.renew_one(ent, None, False)
        assert st == "renewed", msg
        out = subprocess.run(base + ["--list-keys", "--with-colons", "--fixed-list-mode", fpr], capture_output=True, text=True).stdout
        exps = [int(l.split(":")[6]) for l in out.splitlines() if l.startswith(("pub", "sub"))]
        assert len(exps) == 2 and all(abs(x - (time.time() + 365 * DAY)) < 3600 for x in exps)
        assert gpg.renew_one(ent, None, False)[0] == "ok"
    finally:
        subprocess.run(["gpgconf", "--homedir", str(home), "--kill", "all"], capture_output=True)


def test_defaults_are_30_days_window_and_2_years():
    d = {"host": "gpg:" + FPR}
    assert gpg.renew_one(d, None, True, NOW, Gpg(int(NOW + 31 * DAY)))[0] == "ok" and gpg.renew_one(d, None, True, NOW, Gpg(int(NOW + 29 * DAY)))[0] == "would-renew"
    g = Gpg(int(NOW + DAY))
    gpg.renew_one(d, None, False, NOW, g)
    assert [c for c in g.calls if "--quick-set-expire" in c][0][-1] == "2y"
