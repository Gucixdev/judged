"""Edge cases: empty, malformed, hostile and odd-but-legal inputs for the sandbox, container and scan code."""
import json
import subprocess
from types import SimpleNamespace

from judged import containers, sandbox

from test_sandbox import fake


# ---- trivy summary ----
def test_trivy_summary_cases():
    s = containers.trivy_summary
    assert s({})[0] == "unknown"                                               # nothing readable
    assert s({"Results": None, "Metadata": {"OS": {"Family": "debian"}}})[0] == "pass"   # OS known, no findings
    assert s({"Results": [{"Vulnerabilities": None}], "Metadata": {"OS": {}}})[0] == "pass"
    hi = {"Results": [{"Vulnerabilities": [{"Severity": "HIGH", "VulnerabilityID": "CVE-1", "FixedVersion": "2"}]}], "Metadata": {"OS": {}}}
    st, ev = s(hi)
    assert st == "warn" and "1 high" in ev and "1 have a fixed" in ev
    crit = {"Results": [{"Vulnerabilities": [{"Severity": "CRITICAL", "VulnerabilityID": f"CVE-{i}"} for i in range(5)]}]}
    st, ev = s(crit)
    assert st == "fail" and "5 critical" in ev and "CVE-0, CVE-1, CVE-2" in ev and "CVE-3" not in ev
    odd = {"Results": [{"Vulnerabilities": [{"Severity": "LOW"}, {"Severity": "UNKNOWN"}, {}]}], "Metadata": {"OS": {}}}
    assert s(odd)[0] == "pass"                                                 # severities we did not ask for do not count


# ---- scan_images with a fake runner ----
VULN = {"Results": [{"Vulnerabilities": [{"Severity": "CRITICAL", "VulnerabilityID": "CVE-9"}]}], "Metadata": {"OS": {}}}


def runner(save=0, trivy=0, out=None, raises=None):
    def run(cmd, **kw):
        if raises and cmd[0] == "trivy":
            raise raises
        if cmd[1] == "save":
            return SimpleNamespace(returncode=save, stdout="", stderr="no space left")
        return SimpleNamespace(returncode=trivy, stdout=json.dumps(out if out is not None else VULN) if trivy == 0 else "", stderr="db download failed")
    return run


def img(name, size=10 * 1048576, iid=None):
    return {"Names": [name] if name else None, "Id": iid or name or "x", "Size": size}


def one(imgs, **kw):
    return {r.id: r for r in containers.scan_images("podman", imgs, **kw)}


def test_scan_images_failure_modes_are_unknown_never_pass():
    assert one([img("a:1")], run=runner())["containers.vuln.a:1"].status == "fail"
    assert one([img("a:1")], run=runner(save=1))["containers.vuln.a:1"].status == "unknown"
    r = one([img("a:1")], run=runner(trivy=1))["containers.vuln.a:1"]
    assert r.status == "unknown" and "db download failed" in r.evidence
    assert one([img("a:1")], run=runner(raises=subprocess.TimeoutExpired("trivy", 1)))["containers.vuln.a:1"].status == "unknown"
    assert one([img("a:1")], run=runner(raises=FileNotFoundError("trivy")))["containers.vuln.a:1"].status == "unknown"

    def junk(cmd, **kw):
        return SimpleNamespace(returncode=0, stdout="<html>", stderr="")
    assert one([img("a:1")], run=junk)["containers.vuln.a:1"].status == "unknown"


def test_scan_images_selection():
    res = one([img(None), img("a:1", iid="same"), img("a:2", iid="same"), img("big:1", size=5000 * 1048576)], run=runner())
    assert list(res) == ["containers.vuln.a:1", "containers.vuln.skipped"]    # dangling dropped, duplicate id once, big listed
    assert "big:1" in res["containers.vuln.skipped"].evidence and res["containers.vuln.skipped"].status == "unknown"
    many = one([img(f"i{n}:1") for n in range(6)], max_images=2, run=runner())
    assert len([k for k in many if k != "containers.vuln.skipped"]) == 2 and "4 more" in many["containers.vuln.skipped"].evidence
    assert one([], run=runner()) == {}
    acc = one([img("a:1")], accept=["a:1=vulns"], run=runner())["containers.vuln.a:1"]
    assert acc.status == "pass" and acc.evidence.startswith("accepted:")


def test_scan_off_and_missing_trivy_are_unknown():
    base = {("podman", "info"): {"host": {"security": {"rootless": True}}}, ("podman", "ps"): [], ("podman", "images"): [img("a:1")]}
    which = lambda n: "/usr/bin/podman" if n == "podman" else None
    r = {x.id: x for x in containers.containers_check(run=fake(base), which=which)}
    assert r["containers.images.vulns"].status == "unknown" and "not installed" in r["containers.images.vulns"].evidence
    r = {x.id: x for x in containers.containers_check(scan=False, run=fake(base), which=which)}
    assert "switched off" in r["containers.images.vulns"].evidence


# ---- flatpak parsing ----
def test_keyfile_and_token_edges():
    assert sandbox.parse_keyfile("") == {} and sandbox.parse_keyfile("garbage without sections") == {}
    assert sandbox.parse_keyfile("[Context]\nsockets=\n")["Context"]["sockets"] == ""
    assert sandbox.tokens(None) == [] and sandbox.tokens(";;") == [] and sandbox.tokens("a;;!b;if:x:y") == ["a", "!b"]
    assert sandbox.findings(sandbox.merge([{}])) == []                          # no permissions at all
    assert sandbox.findings(sandbox.merge([sandbox.parse_keyfile("[Context]\nfilesystems=!host;!home;\n")])) == []
    # case: the same path twice with different modes keeps the last, a negation of an absent entry is harmless
    p = sandbox.merge([sandbox.parse_keyfile("[Context]\nfilesystems=home:ro;home:rw;!nothing\n")])
    assert p["filesystems"] == ["home:rw"]


def test_filesystem_forms():
    def f(fs):
        return {k: s for k, s, _ in sandbox.findings(sandbox.merge([sandbox.parse_keyfile(f"[Context]\nfilesystems={fs}\n")]))}
    assert f("host:ro")["fs:host"] == "warn" and f("host:create")["fs:host"] == "fail"
    assert f("/")["fs:/"] == "fail" and f("~")["fs:home"] == "fail" and f("~/")["fs:home"] == "fail"
    assert f("xdg-config")["fs:xdg-config"] == "warn" and f("xdg-config/gtk-3.0:ro") == {}
    assert f("~/.ssh:ro")["fs:.ssh"] == "fail" and f("/home/user/.gnupg")["fs:.gnupg"] == "fail"
    assert f("~/.sshfoo") == {} and f("xdg-download") == {} and f("/data/dev:ro") == {}


def test_flatpak_list_edge_cases():
    META = "[Context]\nsockets=wayland;\n"
    run = fake({("flatpak", "list"): "\n\norg.a.App\n  \nignored.App\tuser\n", ("flatpak", "info"): META,
                ("flatpak", "remotes"): "", ("flatpak", "remote-ls"): ""})
    r = {x.id: x for x in sandbox.flatpak_check(ignore=["ignored.App"], run=run)}
    assert "flatpak.org.a.App" in r and "flatpak.ignored.App" not in r         # blank lines, missing column, ignore list
    assert r["flatpak.updates"].status == "pass" and r["flatpak.remotes"].status == "pass"
    empty = {x.id: x for x in sandbox.flatpak_check(run=fake({("flatpak", "list"): ""}))}
    assert not any(k.startswith("flatpak.org") for k in empty)                  # no apps installed: no per-app results, no crash


# ---- files ----
def test_dockerfile_edges():
    L = containers.lint_dockerfile
    assert L("") == [] and L("# only a comment\n") == []
    multi = "FROM golang:1.22 AS build\nRUN go build\nFROM debian:12-slim\nUSER 1000\n"
    assert not any("USER" in t for _, _, t in L(multi))                        # the final stage sets USER
    assert any("never sets USER" in t for _, _, t in L("FROM a:1\nUSER app\nFROM b:2\n"))   # a USER in an earlier stage does not count
    assert any("never sets USER" in t for _, _, t in L("FROM a:1\nUSER root\n"))
    assert not any("pinned" in t for _, _, t in L("ARG BASE=x\nFROM $BASE\nUSER 1\n"))      # variable: cannot judge, say nothing
    assert not any("pinned" in t for _, _, t in L("FROM --platform=linux/amd64 a:1 AS x\nUSER 1\n"))
    assert any("pinned" in t for _, _, t in L("FROM --platform=linux/amd64 a\nUSER 1\n"))
    assert any("pinned" in t for _, _, t in L("FROM a:latest\nUSER 1\n"))
    assert not any("pinned" in t for _, _, t in L("FROM a@sha256:" + "0" * 64 + "\nUSER 1\n"))
    assert not any("secret" in t for _, _, t in L("USER 1\nENV TOKEN=$TOKEN\nARG PASSWORD\n"))   # a reference or an empty ARG is not a secret
    assert any("secret" in t for _, _, t in L("FROM a:1\nUSER 1\nenv DB_PASSWORD hunter22x\n"))   # lower case, space form
    assert L("FROM a:1\r\nUSER 1\r\n") == []                                   # CRLF files


def test_compose_edges():
    L = containers.lint_compose
    assert L("") == [] and L("# privileged: true\n") == []                     # a comment is not a setting
    assert L("services:\n  a:\n    ports: []\n") == []
    inside = "services:\n  a:\n    ports:\n      - \"127.0.0.1:80:80\"\n      - \"[::1]:81:81\"\n      - 82\n    command: [\"1:2\"]\n    deploy:\n      resources:\n        limits:\n          cpus: '0.5'\n"
    msgs = [t for _, _, t in L(inside)]
    assert len(msgs) == 1 and "82" in msgs[0]                                  # only the bare port; loopback binds and other lists are fine
    assert any("privileged" in t for _, _, t in L("services:\n  a:\n    privileged: \"true\"\n"))
    assert not any("secret" in t for _, _, t in L("    environment:\n      DB_PASSWORD: ${DB_PASSWORD}\n"))
    assert any("secret" in t for _, _, t in L("    environment:\n      - DB_PASSWORD=hunter22x\n"))


def test_files_check_unreadable_and_empty(tmp_path):
    assert containers.files_check([str(tmp_path / "nope")]) == []              # a pattern that matches nothing
    (tmp_path / "Dockerfile").write_bytes(b"\xff\xfeFROM a:1\nUSER 1\n")       # not valid UTF-8
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "Dockerfile").write_text("FROM a\n")                  # inside .git: ignored
    res = containers.files_check([str(tmp_path)])
    assert len(res) == 1 and res[0].status in ("pass", "warn")


# ---- rare file kinds in a repo ----
def test_secrets_scan_survives_symlink_to_dev_zero_fifo_and_odd_names(tmp_path):
    import os
    import subprocess as sp
    from judged import secrets
    r = tmp_path / "r"
    r.mkdir()
    sp.run(["git", "-C", str(r), "init", "-q"], check=True)
    tok = "ghp_" + "Qx7Lm2Vb9KdR4sTz1WcN8yHj5PfG3uAe6oXi"   # random-looking: the scanner skips placeholder-like runs
    (r / "zażółć gęślą.txt").write_text(f"key={tok}\n")           # non-ASCII name, git quotes it in plain ls-files
    (r / "new\nline.txt").write_text(f"x\nkey={tok}\n")           # newline in the name: needs -z
    (r / "zero.txt").symlink_to("/dev/zero")                      # read_bytes() on this never returns
    (r / "loop.txt").symlink_to("loop.txt")
    os.mkfifo(r / "pipe.txt")                                     # open() on a FIFO blocks
    sp.run(["git", "-C", str(r), "add", "-A", "-f"], check=True, capture_output=True)
    res = {x.id: x for x in secrets.repo_check(str(r))}
    assert res["secrets.r.shapes"].status == "fail" and "2 in files" in res["secrets.r.shapes"].evidence
    assert tok not in "".join(x.evidence for x in res.values())  # the value is never printed


# ---- flatpak leftovers and the report ----
LIST_APPS = "org.a.App\torg.freedesktop.Platform/x86_64/25.08\norg.b.App\torg.kde.Platform/x86_64/6.11\n"
LIST_RT = ("org.freedesktop.Platform\t24.08\t691.3 MB\norg.freedesktop.Platform\t25.08\t668.9 MB\n"
           "org.kde.Platform\t6.11\t1.1 GB\norg.kde.Platform\t5.15-25.08\t974.3 MB\norg.freedesktop.Sdk\t25.08\t1.7 GB\n"
           "org.freedesktop.Platform.GL.default\t24.08\t464.6 MB\n")


def test_leftovers_find_removed_app_data_and_skip_install_dir_names(tmp_path):
    for n in ("org.a.App", "org.gone.Old", "app", "repo", "runtime", "db", ".removed", "no-dots-here"):
        (tmp_path / n).mkdir()
    run = fake({("flatpak", "list", "--app"): LIST_APPS, ("flatpak", "list", "--runtime"): LIST_RT, ("du",): "2048\tx"})
    r = {x.id: x for x in sandbox.flatpak_leftovers(tmp_path, run)}
    assert r["flatpak.leftover-data"].status == "warn" and "org.gone.Old (2 MB)" in r["flatpak.leftover-data"].evidence
    assert "org.a.App" not in r["flatpak.leftover-data"].evidence and "repo" not in r["flatpak.leftover-data"].evidence
    assert r["flatpak.runtimes"].status == "warn"
    ev = r["flatpak.runtimes"].evidence
    assert "org.freedesktop.Platform//24.08" in ev and "org.kde.Platform//5.15-25.08" in ev
    assert "//25.08," not in ev and "Sdk" not in ev and "GL.default" not in ev     # used, not a base Platform, an extension


def test_leftovers_clean_missing_dir_and_no_flatpak(tmp_path):
    run = fake({("flatpak", "list", "--app"): "org.a.App\torg.freedesktop.Platform/x86_64/25.08\n",
                ("flatpak", "list", "--runtime"): "org.freedesktop.Platform\t25.08\t1 GB\n"})
    r = {x.id: x for x in sandbox.flatpak_leftovers(tmp_path, run)}
    assert r["flatpak.leftover-data"].status == "pass" and r["flatpak.runtimes"].status == "pass"
    r = {x.id: x for x in sandbox.flatpak_leftovers(tmp_path / "nope", run)}
    assert r["flatpak.leftover-data"].status == "unknown"                          # unreadable is not a pass
    assert sandbox.flatpak_leftovers(tmp_path, fake({})) == []                     # flatpak absent: nothing to say
    r = {x.id: x for x in sandbox.flatpak_leftovers(tmp_path, fake({("flatpak", "list", "--app"): "org.a.App\tweird\n"}))}
    assert r["flatpak.runtimes"].status == "unknown"                               # runtime listing failed


def test_mb_parsing():
    assert sandbox._mb("1.1 GB") == 1100 and sandbox._mb("17.3 MB") == 17.3 and sandbox._mb("163.8 kB") == 0.1638
    assert sandbox._mb("") == 0 and sandbox._mb("many") == 0 and sandbox._mb("1 PB") == 0


def test_report_orders_by_urgency_and_never_hides_unknown():
    from judged import report
    from judged.controls import Result
    res = [Result("a", "Disk encryption", "pass", "on", {}), Result("b", "Open port 23", "fail", "telnet is listening", {}),
           Result("c", "Updates", "warn", "3 pending", {}), Result("d", "Flatpak updates", "unknown", "offline", {})]
    md = report.build(res)
    assert md.index("Fix first") < md.index("Look at these") < md.index("Could not be checked")
    assert "1 to fix, 1 to review, 1 could not be checked, 1 fine" in md and "telnet is listening" in md and "offline" in md
    assert "Fix first" not in report.build(res[:1]) and "0 to fix" in report.build([])


def test_report_save_keeps_dated_copies_and_newest_answers(tmp_path):
    from datetime import datetime
    from judged import report
    f = tmp_path / "state" / "reports"                                    # folder does not exist yet
    assert report.newest(f) is None and report.newest(tmp_path / "nope") is None
    a = report.save("one", f, datetime(2026, 11, 24, 10, 0, 0))
    b = report.save("two", f, datetime(2026, 11, 24, 10, 0, 1))
    assert a == b == f / "raport.md" and a.read_text() == "two"
    assert sorted(p.name for p in f.glob("raport-*.md")) == ["raport-20261124-100000.md", "raport-20261124-100001.md"]
    a.rename(f / "moved")                                                 # raport.md lost: fall back to the newest dated file
    assert report.newest(f).name == "raport-20261124-100001.md"
