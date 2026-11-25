from datetime import datetime, timezone

from judged import controls, host, net

NOW = datetime(2026, 11, 24, tzinfo=timezone.utc)


def test_sshd_first_value_wins():
    c = host.parse_sshd("PermitRootLogin no\nPasswordAuthentication no\nPermitRootLogin yes\n# x\n")
    assert c["permitrootlogin"] == "no" and c["passwordauthentication"] == "no"


def test_root_encrypted():
    tree = {"name": "sda", "type": "disk", "mountpoints": [None], "children": [
        {"name": "luks", "type": "crypt", "mountpoints": [None], "children": [
            {"name": "root", "type": "lvm", "mountpoints": ["/"]}]}]}
    assert host.root_encrypted(tree) is True
    plain = {"name": "sda1", "type": "part", "mountpoints": ["/"]}
    assert host.root_encrypted(plain) is False
    assert host.root_encrypted({"name": "x", "type": "disk", "mountpoints": [None]}) is None


def test_gpg_hygiene():
    s = ("pub:u:2048:1:AAAAAAAAAAAA1111:1:::u:::scESC:\n"       # RSA 2048, no expiry
         "pub:u:1024:17:BBBBBBBBBBBB2222:1:1900000000::u:::sc:\n"  # DSA
         "pub:u:255:22:CCCCCCCCCCCC3333:1:1900000000::u:::sc:\n"   # EdDSA with expiry
         "pub:e:4096:1:DDDDDDDDDDDD4444:1:1600000000::e:::sc:\n")  # expired
    st = {r.id: r.status for r in net.gpg_hygiene(s)}
    assert st == {"gpg.AAAA1111": "warn", "gpg.BBBB2222": "fail", "gpg.CCCC3333": "pass", "gpg.DDDD4444": "fail"}


def fake(version="TLSv1.3", days=60, life=90):
    import ssl
    na = datetime.fromtimestamp(NOW.timestamp() + days * 86400, timezone.utc)
    nb = datetime.fromtimestamp(na.timestamp() - life * 86400, timezone.utc)
    fmt = lambda d: d.strftime("%b %e %H:%M:%S %Y GMT")
    return {"version": version, "cert": {"notAfter": fmt(na), "notBefore": fmt(nb),
                                          "issuer": ((("organizationName", "Let's Encrypt"),),)}}


def test_tls_evaluation():
    r = {x.id.split(".")[-1]: x.status for x in net.evaluate_tls("h", fake(), "max-age=1", "0 issue letsencrypt.org", NOW)}
    assert r == {"version": "pass", "expiry": "pass", "acme": "pass", "hsts": "pass", "caa": "pass"}
    r = {x.id.split(".")[-1]: x.status for x in net.evaluate_tls("h", fake("TLSv1.1", 5, 365), None, "", NOW)}
    assert r == {"version": "fail", "expiry": "warn", "acme": "warn", "hsts": "warn", "caa": "warn"}


def test_control_rollup_and_manual():
    R = controls.Result
    maps = {"ce": ["firewalls"]}
    rs = [R("a", "a", "pass", "", maps), R("b", "b", "warn", "", maps), R("c", "c", "na", "", {"ce": ["malware"]})]
    fw = controls.load_frameworks()["ce"]
    rows = {cid: st for cid, _, st, _ in controls.assemble("ce", fw, rs)}
    assert rows["firewalls"] == "warn"
    assert rows["malware"] == "manual"          # only 'na' evidence: a person must supply it
    assert rows["user-access"] == "manual"      # nothing mapped at all
