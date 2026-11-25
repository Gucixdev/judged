import json
import subprocess
from types import SimpleNamespace

from judged import conf, containers, sandbox

META = """[Context]
shared=network;
sockets=wayland;x11;if:x11:!has-wayland;
devices=dri;
filesystems=xdg-download;/data/dev:ro;

[Session Bus Policy]
org.mozilla.firefox.*=own
"""


def fake(table):
    """A runner that answers by command prefix: {('flatpak','info'): 'text'}; missing = nonzero exit."""
    def run(cmd, **kw):
        for k, out in table.items():
            if tuple(cmd[:len(k)]) == k:
                return SimpleNamespace(returncode=0, stdout=out if isinstance(out, str) else json.dumps(out), stderr="")
        return SimpleNamespace(returncode=1, stdout="", stderr="no")
    return run


def keys(perms):
    return {k: s for k, s, _ in sandbox.findings(perms)}


def test_normal_app_is_clean_and_conditional_x11_is_ignored():
    p = sandbox.merge([sandbox.parse_keyfile(META)])
    assert "x11" in p["sockets"] and "if:x11:!has-wayland" not in p["sockets"]
    assert keys(p) == {}


def test_wide_permissions_are_found():
    meta = "[Context]\nsockets=session-bus;ssh-auth;x11;\ndevices=all;\nfeatures=devel;\nfilesystems=host;~/.ssh:ro;home:ro;\n" \
           "[Session Bus Policy]\norg.freedesktop.Flatpak=talk\norg.freedesktop.secrets=talk\n"
    k = keys(sandbox.merge([sandbox.parse_keyfile(meta)]))
    assert k["socket:session-bus"] == "fail" and k["fs:host"] == "fail" and k["fs:.ssh"] == "fail"
    assert k["fs:home"] == "warn" and k["socket:x11-only"] == "warn" and k["bus:org.freedesktop.Flatpak"] == "fail"
    assert k["bus:org.freedesktop.secrets"] == "warn" and k["dev:all"] == "warn" and k["feature:devel"] == "warn"


def test_override_negation_beats_metadata():
    base = sandbox.parse_keyfile("[Context]\nfilesystems=host;\nsockets=session-bus;\n[Session Bus Policy]\norg.freedesktop.Flatpak=talk\n")
    ov = sandbox.parse_keyfile("[Context]\nfilesystems=!host;\nsockets=!session-bus;\n[Session Bus Policy]\norg.freedesktop.Flatpak=none\n")
    assert keys(sandbox.merge([base, ov])) == {}
    # and a mode change replaces the old entry instead of adding a second one
    p = sandbox.merge([sandbox.parse_keyfile("[Context]\nfilesystems=home;\n"), sandbox.parse_keyfile("[Context]\nfilesystems=home:ro;\n")])
    assert p["filesystems"] == ["home:ro"]


def test_check_reports_status_accept_and_unknown():
    wide = "[Context]\nsockets=session-bus;wayland;\ndevices=all;\n"
    run = fake({("flatpak", "list"): "org.a.App\tuser\norg.b.App\tuser\n",
                ("flatpak", "info", "--show-permissions", "org.a.App"): wide,
                ("flatpak", "info", "--show-permissions", "org.b.App"): META,
                ("flatpak", "remotes"): "flathub\tuser\nbad\tuser,no-gpg-verify\n",
                ("flatpak", "remote-ls"): "x\ny\n"})
    r = {x.id: x for x in sandbox.flatpak_check(run=run)}
    assert r["flatpak.org.a.App"].status == "fail" and r["flatpak.org.b.App"].status == "pass"
    assert r["flatpak.remotes"].status == "fail" and "bad" in r["flatpak.remotes"].evidence
    assert r["flatpak.updates"].status == "warn" and "2 update" in r["flatpak.updates"].evidence
    r = {x.id: x for x in sandbox.flatpak_check(accept=["org.a.App=socket:session-bus"], run=run)}
    assert r["flatpak.org.a.App"].status == "warn" and "accepted: full D-Bus" in r["flatpak.org.a.App"].evidence
    run2 = fake({("flatpak", "list"): "org.a.App\tuser\n", ("flatpak", "remote-ls"): "x\n"})   # info fails
    r = {x.id: x for x in sandbox.flatpak_check(run=run2)}
    assert r["flatpak.org.a.App"].status == "unknown"
    assert sandbox.flatpak_check(run=fake({}))[0].status == "na"
    r = {x.id: x for x in sandbox.flatpak_check(run=fake({("flatpak", "list"): "org.a.App\tuser\n", ("flatpak", "info"): META}))}
    assert r["flatpak.updates"].status == "unknown"


def test_container_judgement():
    bad = {"HostConfig": {"Privileged": True, "NetworkMode": "host", "CapAdd": ["CAP_SYS_ADMIN"],
                          "Binds": ["/run/user/1000/podman/podman.sock:/s", "/etc:/e:ro", "/data/x:/x"],
                          "PortBindings": {"80/tcp": [{"HostIp": "", "HostPort": "80"}]}, "SecurityOpt": ["seccomp=unconfined"]},
           "Config": {"Image": "nginx", "User": ""}}
    j = containers.judge_container(bad, rootless=False)
    text = " | ".join(t for _, _, t in j)
    assert {k for k, _, _ in j} >= {"privileged", "cap:SYS_ADMIN", "net:host", "socket:/run/user/1000/podman/podman.sock", "mount:/etc",
                                    "port:80/tcp", "secopt:seccomp=unconfined", "root", "unpinned"}
    for s in ("privileged", "SYS_ADMIN", "host network", "runtime socket", "/etc", "every interface", "seccomp", "root inside", "not pinned"):
        assert s in text, s
    assert "/data/x" not in text
    ok = {"HostConfig": {"PortBindings": {"80/tcp": [{"HostIp": "127.0.0.1"}]}}, "Config": {"Image": "localhost/mine:latest", "User": "1000"}}
    assert containers.judge_container(ok, rootless=True) == []
    assert not any("root inside" in t for _, _, t in containers.judge_container({"HostConfig": {}, "Config": {"Image": "a:1"}}, rootless=True))


def test_containers_check_end_to_end_with_fakes():
    doc = [{"HostConfig": {"Privileged": True}, "Config": {"Image": "a:1", "User": "1"}}]
    run = fake({("podman", "info"): {"host": {"security": {"rootless": True}}},
                ("podman", "ps"): [{"Id": "abc123", "Names": ["web"]}],
                ("podman", "inspect"): doc,
                ("podman", "images"): [{"Id": "i1", "Names": ["old:1"], "Created": 1000}, {"Id": "i2", "Names": ["new:1"], "Created": 2_000_000_000}]})
    which = lambda n: "/usr/bin/podman" if n == "podman" else None
    r = {x.id: x for x in containers.containers_check(run=run, which=which, now=2_000_000_100)}
    assert r["containers.runtime"].status == "pass"
    assert r["containers.web"].status == "fail"
    assert r["containers.images.age"].status == "warn" and "old:1" in r["containers.images.age"].evidence
    assert r["containers.images.vulns"].status == "unknown"            # no scanner: never a pass
    assert containers.containers_check(which=lambda n: None)[0].status == "na"
    assert containers.containers_check(run=fake({}), which=which)[0].status == "unknown"
    r = {x.id: x for x in containers.containers_check(accept=["web=privileged"], run=run, which=which)}
    assert r["containers.web"].status == "pass" and "accepted" in r["containers.web"].evidence
    # one key accepts one finding only: accepting SYS_ADMIN must not accept NET_ADMIN or privileged
    many = {"HostConfig": {"Privileged": True, "CapAdd": ["SYS_ADMIN", "NET_ADMIN"]}, "Config": {"Image": "a:1", "User": "1"}}
    run3 = fake({("podman", "info"): {"host": {"security": {"rootless": True}}}, ("podman", "ps"): [{"Id": "abc", "Names": ["web"]}],
                 ("podman", "inspect"): [many], ("podman", "images"): []})
    r = {x.id: x for x in containers.containers_check(accept=["web=cap:SYS_ADMIN"], run=run3, which=which)}
    assert r["containers.web"].status == "fail" and "accepted: added capability SYS_ADMIN" in r["containers.web"].evidence
    assert "fail: privileged" in r["containers.web"].evidence and "warn: added capability NET_ADMIN" in r["containers.web"].evidence
    # an image list without readable dates is unknown, never pass
    run4 = fake({("podman", "info"): {"host": {"security": {"rootless": True}}}, ("podman", "ps"): [], ("podman", "images"): [{"Id": "x", "CreatedAt": "yesterday"}]})
    r = {x.id: x for x in containers.containers_check(run=run4, which=which)}
    assert r["containers.images.age"].status == "unknown"


def test_dockerfile_lint(tmp_path):
    secret_value = "hunter2hunter2"
    bad = f"FROM python\nADD https://x.example/a.tgz /a\nRUN curl -s https://x.example/i | sh\nENV API_TOKEN={secret_value}\nRUN chmod 777 /x\n"
    msgs = " | ".join(t for _, _, t in containers.lint_dockerfile(bad))
    for s in ("not pinned", "ADD of a remote URL", "pipes to a shell", "secret-looking", "chmod 777", "never sets USER"):
        assert s in msgs, s
    assert secret_value not in msgs
    good = "FROM python:3.13-slim@sha256:" + "a" * 64 + "\nRUN useradd app\nUSER app\n"
    assert containers.lint_dockerfile(good) == []
    assert any("never sets USER" in t for _, _, t in containers.lint_dockerfile("FROM scratch\nCOPY a /a\n"))
    (tmp_path / "Containerfile").write_text(bad)
    (tmp_path / "docker-compose.yml").write_text("services:\n  a:\n    privileged: true\n    ports:\n      - \"8080:80\"\n      - 127.0.0.1:9000:90\n"
                                                  "    environment:\n      DB_PASSWORD: s3cretvalue\n    cap_add:\n      - SYS_ADMIN\n    volumes:\n      - /var/run/docker.sock:/s\n")
    res = {x.id.split(".file.")[1].split("/")[-1]: x for x in containers.files_check([str(tmp_path)])}
    assert res["Containerfile"].status == "fail" and res["docker-compose.yml"].status == "fail"
    ev = res["docker-compose.yml"].evidence
    assert "8080:80" in ev and "127.0.0.1:9000" not in ev and "SYS_ADMIN" in ev and "runtime socket" in ev and "s3cretvalue" not in ev


def test_config_sections():
    cfg = conf.parse('flatpak accept=org.a.App=socket:session-bus,*=fs:home ignore=org.x.App\ncontainers projects="~/dev/*" accept=web=privileged max_image_age_days=90\n')
    assert cfg["flatpak"]["accept"] == ["org.a.App=socket:session-bus", "*=fs:home"]
    assert cfg["containers"]["max_image_age_days"] == 90
