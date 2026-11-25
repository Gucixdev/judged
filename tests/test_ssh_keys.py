import time

from judged.hardening import ssh_keys

DAY = 86400
ED = "256 SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA person@example.com (ED25519)\n"
RSA2K = "2048 SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB old (RSA)\n"
RSA4K = "4096 SHA256:CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC ok (RSA)\n"
DSA = "1024 SHA256:DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD d (DSA)\n"


class Box:
    """A fake ~/.ssh: files = {name: (first bytes, mode, age in days, nopass)}; authorized_keys given as text + ssh-keygen output."""
    def __init__(self, files=None, auth=None, auth_out="", auth_mode=0o600, auth_rc=0, keygen=None):
        self.files, self.auth, self.auth_out, self.auth_mode, self.auth_rc, self.keygen = files or {}, auth, auth_out, auth_mode, auth_rc, keygen or {}

    def listdir(self, d):
        if d == "/nowhere":
            raise FileNotFoundError(d)
        return sorted(self.files) + (["authorized_keys"] if self.auth is not None else [])

    def head(self, p, n=64):
        if p.endswith("authorized_keys"):
            return (self.auth or "")[:n]
        return self.files[p.rsplit("/", 1)[1]][0]

    def stat(self, p):
        n = p.rsplit("/", 1)[1]
        if n == "authorized_keys":
            return self.auth_mode, time.time()
        _, mode, age, _ = self.files[n]
        return mode, time.time() - age * DAY

    def read(self, p):
        if self.auth is None:
            raise FileNotFoundError(p)
        return self.auth

    def run(self, cmd, timeout=20):
        if cmd[1] == "-y":
            n = cmd[-1].rsplit("/", 1)[1]
            return (0 if self.files[n][3] else 255), ""
        n = cmd[-1].rsplit("/", 1)[1]
        if n == "authorized_keys":
            return self.auth_rc, self.auth_out
        return (0, self.keygen.get(n, ED))


PRIV = "-----BEGIN OPENSSH " + "PRIVATE KEY-----"


def one(**kw):
    return ssh_keys.check({"ssh_dir": "/d", **kw.pop("cfg", {})}, Box(**kw))


def test_parse_drops_the_comment_and_ignores_noise():
    assert ssh_keys.parse(ED + "garbage\n" + RSA4K) == [(256, "SHA256:" + "A" * 43, "ED25519"), (4096, "SHA256:" + "C" * 43, "RSA")]


def test_a_good_protected_key_passes_and_the_comment_never_appears():
    r = one(files={"id": (PRIV, 0o600, 10, False)})
    assert [x.status for x in r] == ["pass"] and "person@example.com" not in r[0].evidence and "1 private keys" in r[0].evidence


def test_no_passphrase_warns_and_accept_by_file_name_silences_it():
    f = {"ci": (PRIV, 0o600, 10, True)}
    assert one(files=f)[0].status == "warn" and "ci: no passphrase" in one(files=f)[0].evidence
    assert one(files=f, cfg={"ssh_keys_accept": ["ci"]})[0].status == "pass"


def test_weak_keys_and_boundaries():
    assert "RSA 2048 bits" in one(files={"k": (PRIV, 0o600, 1, False)}, keygen={"k": RSA2K})[0].evidence
    assert one(files={"k": (PRIV, 0o600, 1, False)}, keygen={"k": RSA4K})[0].status == "pass"
    assert one(files={"k": (PRIV, 0o600, 1, False)}, keygen={"k": RSA2K.replace("2048", "3072")})[0].status == "pass"          # the limit itself is fine
    assert "DSA is obsolete" in one(files={"k": (PRIV, 0o600, 1, False)}, keygen={"k": DSA})[0].evidence


def test_permissions_make_it_a_fail_and_age_a_warning_at_the_limit():
    r = one(files={"k": (PRIV, 0o644, 1, False)})[0]
    assert r.status == "fail" and "permissions 644" in r.evidence
    assert one(files={"k": (PRIV, 0o600, 731, False)})[0].status == "warn" and "years old" in one(files={"k": (PRIV, 0o600, 731, False)})[0].evidence
    assert one(files={"k": (PRIV, 0o600, 729, False)})[0].status == "pass"
    assert one(files={"k": (PRIV, 0o600, 400, False)}, cfg={"ssh_key_max_age_days": 365})[0].status == "warn"


def test_public_keys_and_other_files_are_not_treated_as_private():
    r = one(files={"k.pub": ("ssh-ed25519 AAAA", 0o644, 1, False), "config": ("Host x", 0o600, 1, False)})
    assert [x.status for x in r] == ["na"]


def test_authorized_keys_duplicates_weak_and_permissions():
    out = ED + ED + RSA2K
    r = one(auth="x", auth_out=out)[0]
    assert r.status == "warn" and "the same key twice" in r.evidence and "RSA 2048" in r.evidence and "3 authorized keys" in r.evidence
    r = one(auth="x", auth_out=ED, auth_mode=0o666)[0]
    assert r.status == "fail" and "other users can add keys" in r.evidence
    assert one(auth="x", auth_out=ED, auth_mode=0o644)[0].status == "pass"                                  # group/world READ is harmless, write is not
    assert one(auth="x", auth_out=ED, auth_mode=0o620)[0].status == "fail"


def test_unreadable_authorized_keys_is_unknown_not_clean():
    r = one(auth="ssh-ed25519 AAAA key\n", auth_out="", auth_rc=1)
    assert any(x.status == "unknown" and "could not read" in x.evidence for x in r)
    assert not any(x.status == "pass" for x in r)
    assert one(auth="# only a comment\n", auth_out="", auth_rc=1)[0].status == "pass"


def test_missing_folder_is_na_and_unreadable_key_description_is_unknown():
    assert ssh_keys.check({"ssh_dir": "/nowhere"}, Box())[0].status == "na"
    box = Box(files={"k": (PRIV, 0o600, 1, False)}, keygen={"k": "garbage\n"})
    assert ssh_keys.check({"ssh_dir": "/d"}, box)[0].status == "unknown"
