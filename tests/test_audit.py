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
    maps = {"iso27001": ["A.8.20"]}
    rs = [R("a", "a", "pass", "", maps), R("b", "b", "warn", "", maps), R("c", "c", "na", "", {"iso27001": ["A.8.7"]})]
    fw = controls.load_frameworks()["iso27001"]
    rows = {cid: st for cid, _, st, _ in controls.assemble("iso27001", fw, rs)}
    assert rows["A.8.20"] == "warn"
    assert rows["A.8.7"] == "manual"            # only 'na' evidence: a person must supply it
    assert rows["A.8.2"] == "manual"            # nothing mapped at all


def test_a_cyber_essentials_requirement_never_passes_on_a_measurement_alone():
    R, fw = controls.Result, controls.load_frameworks()["ce"]
    maps = {"ce": ["fw-every-device"]}

    def status(*results):
        return next(st for cid, _, st, _ in controls.assemble("ce", fw, list(results)) if cid == "fw-every-device")

    def measured(s):
        return R("m", "m", s, "", maps)

    def said(s):
        return R("s", "s", s, "", maps, attested=True)

    assert status(measured("pass")) == "manual"
    assert status(measured("pass"), said("pass")) == "pass"
    assert status(said("pass")) == "pass"
    for bad in ("fail", "warn", "unknown"):
        assert status(measured(bad), said("pass")) == bad       # a statement never hides what was measured
    assert status(measured("pass"), said("warn")) == "warn"
    assert status(measured("pass"), said("na")) == "manual"     # an exclusion is not a pass for what is still measured
    report = controls.markdown({"ce": fw}, [measured("pass")])
    assert "A measurement can fail a requirement" in report and "| manual | m: " in report


