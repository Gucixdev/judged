import subprocess

from judged import secrets

TOKEN = "gh" + "p_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"        # built at runtime: not a literal in the repo

PW = "pass" + "word = 'hunter2hunter2hunter2'"                      # built from pieces: no complete secret-shaped line sits in this file
KEY_HEAD = "-----BEGIN OPENSSH " + "PRIVATE KEY-----"
RSA_HEAD = "-----BEGIN RSA " + "PRIVATE KEY-----"
SK = "sk-" + "Zq7Lm2Xv9Rt4Bn8Hc3Ws6Yd1Kf5Pg0Jh"
HOME_FX = "/" + "home" + "/someuser1"



def git(repo, *a):
    subprocess.run(["git", "-C", str(repo), *a], check=True, capture_output=True)


def test_scan_text_never_returns_values():
    out = secrets.scan_text(f"a\nexport X={TOKEN}\n{PW}\n")
    assert out == [("github-token", 2), ("name=value", 3)]
    assert all(TOKEN not in str(x) for x in out)
    assert secrets.scan_text(PW, generic=False) == []


def test_name_class():
    assert secrets.name_class(".env") == "secret" and secrets.name_class("a/id_ed25519") == "secret"
    assert secrets.name_class(".env.example") is None and secrets.name_class("id_rsa.pub") is None
    assert secrets.name_class("data/app.sqlite") == "data" and secrets.name_class("README.md") is None


def test_repo_check(tmp_path):
    git(tmp_path, "init", "-q")
    (tmp_path / ".gitignore").write_text("*.key\n")
    (tmp_path / ".env").write_text("A=1\n")                  # secret-named, not ignored, would be added
    (tmp_path / "x.key").write_text("k")                      # ignored: must not be reported
    (tmp_path / "notes.md").write_text(f"token {TOKEN}\n")
    git(tmp_path, "add", "notes.md")
    git(tmp_path, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "x")
    res = {r.id.split(".", 2)[2]: r for r in secrets.repo_check(str(tmp_path), history=True)}
    assert res["names.untracked"].status == "fail" and ".env" in res["names.untracked"].evidence
    assert "x.key" not in res["names.untracked"].evidence
    assert res["shapes"].status == "fail" and TOKEN not in res["shapes"].evidence
    assert res["gitignore"].status == "warn" and ".env" in res["gitignore"].evidence      # .env uncovered
    assert res["history"].status == "fail"


def test_path_check(tmp_path):
    (tmp_path / "chat.jsonl").write_text('{"m": "my key ' + TOKEN + '"}\n{"m": "hello"}\n')
    r = secrets.path_check(str(tmp_path))[0]
    assert r.status == "fail" and "chat.jsonl:1" in r.evidence and TOKEN not in r.evidence
    assert secrets.path_check(str(tmp_path / "none"))[0].status == "unknown"


def test_identity_detected_not_printed(tmp_path, monkeypatch):
    monkeypatch.setattr(secrets.getpass, "getuser", lambda: "someuser1")
    monkeypatch.setattr(secrets.socket, "gethostname", lambda: "box")
    t = secrets.identity_terms()
    assert t["username"] == "someuser1" and "hostname" not in t                  # short hostname skipped
    monkeypatch.setattr(secrets.getpass, "getuser", lambda: "root")
    assert "username" not in secrets.identity_terms()                          # generic names skipped
    monkeypatch.setattr(secrets, "identity_terms", lambda **kw: {"home path": HOME_FX, "username": "someuser1"})
    git(tmp_path, "init", "-q")
    (tmp_path / "a.sh").write_text(f"cd {HOME_FX}/x\necho hi\nuser=someuser1\n")
    git(tmp_path, "add", "a.sh")
    r = {x.id.split(".", 2)[2]: x for x in secrets.repo_check(str(tmp_path))}["identity"]
    assert r.status == "warn" and "a.sh:1" in r.evidence and "home path" in r.evidence
    assert "someuser1" not in r.evidence                                        # never printed


def test_placeholder_is_not_a_secret():
    fake = "gh" + "p_" + "x" * 36
    aws_doc = "AKIA" + "IOSFODNN7" + "EXAMPLE"
    assert secrets.scan_text(f"GITHUB_TOKEN={fake}\nkey={aws_doc}", generic=False) == []
    assert secrets.scan_text(f"x={TOKEN}", generic=False) == [("github-token", 1)]
    assert secrets.strong(KEY_HEAD) is None                  # a quoted header is not a key
    body = "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW"
    assert secrets.scan_text(KEY_HEAD + "\n" + body, generic=False) == [("private-key", 1)]
    assert secrets.strong('"' + RSA_HEAD + '\\n' + body + '"') == "private-key"   # one jsonl line


def test_generic_ignores_function_calls():
    assert secrets.scan_text('password = os.environ.get("RCON_PASSWORD")') == []
    assert secrets.scan_text(PW) == [("name=value", 1)]


def test_not_a_git_repo_is_reported(tmp_path):
    r = secrets.repo_check(str(tmp_path))
    assert r[0].status == "unknown" and "not a git repository" in r[0].evidence


def test_history_ignores_placeholder_commits(tmp_path):
    git(tmp_path, "init", "-q")
    (tmp_path / "t.txt").write_text("T=" + "gh" + "p_" + "x" * 36 + "\n")
    git(tmp_path, "add", "t.txt")
    git(tmp_path, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "fixture")
    h = {r.id.split(".", 2)[2]: r for r in secrets.repo_check(str(tmp_path), history=True)}["history"]
    assert h.status == "pass"


def test_slugs_and_prose_are_not_keys():
    assert secrets.scan_text("see ris" + "k-assessment-and-cleanup-of-old-sessions-for-the-team", generic=False) == []
    assert secrets.scan_text("file tas" + "k-force-weekly-report-final-version-two-copy", generic=False) == []
    assert secrets.scan_text("k=" + SK, generic=False) == [("api-key-sk", 1)]
