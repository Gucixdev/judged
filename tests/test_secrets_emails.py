import subprocess

from judged import secrets


def test_addresses_are_found_masked_and_numbered():
    t = "contact: anna.kowalska@gmail.com\nno address here\nB: bob@Firma.co.uk and c@d.io\n"
    assert secrets.scan_emails(t) == [("a***@gmail.com", 1), ("b***@Firma.co.uk", 3), ("c***@d.io", 3)]


def test_what_is_not_personal_is_skipped():
    t = ("git@github.com:Org/repo.git\n12345+user@users.noreply.github.com\nnoreply@anthropic.com\nno-reply@corp.com\nme@example.com\nx@sub.example.org\n"
         "root@localhost\na@b.invalid\na@b.test\nicon@2x.png\npkg@18.0.0.tgz\nname@1.2.3\n")
    assert secrets.scan_emails(t) == []


def test_look_alikes_that_are_personal_still_count():
    assert secrets.scan_emails("mail me: user.name+tag@mail.company-x.de.") == [("u***@mail.company-x.de", 1)]
    assert secrets.scan_emails("x@notexample.com\ny@myexample.com") == [("x***@notexample.com", 1), ("y***@myexample.com", 2)]
    assert secrets.scan_emails("a@localhost.com") == [("a***@localhost.com", 1)]


def test_accepted_addresses_and_domains_are_skipped_case_insensitively():
    t = "Security@Corp.com\nsales@corp.com\nanna@other.com\n"
    assert secrets.scan_emails(t, ["security@corp.com"]) == [("s***@corp.com", 2), ("a***@other.com", 3)]
    assert secrets.scan_emails(t, ["CORP.COM"]) == [("a***@other.com", 3)]


def test_very_long_lines_are_not_scanned():
    assert secrets.scan_emails("x" * 2001 + " a@b.com") == [] and secrets.scan_emails("x" * 1990 + " a@b.com") == [("a***@b.com", 1)]


def repo(tmp_path, files):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    for n, c in files.items():
        (tmp_path / n).write_text(c)
    subprocess.run(["git", "-C", str(tmp_path), "add", "-A"], check=True)
    return str(tmp_path)


def test_repo_check_warns_once_with_masked_addresses_and_never_shows_the_full_one(tmp_path):
    r = repo(tmp_path, {"a.md": "Questions: anna.kowalska@gmail.com\n", "b.txt": "also anna.kowalska@gmail.com and bob@firma.pl\n", "package-lock.json": '{"x": "zed@evil.org"}'})
    res = {x.id.rsplit(".", 1)[1]: x for x in secrets.repo_check(r)}
    e = res["emails"]
    assert e.status == "warn" and e.evidence.startswith("3 lines hold 2 address(es) (a***@gmail.com, b***@firma.pl), first at a.md:1, b.txt:1, b.txt:1")
    assert "anna.kowalska" not in e.evidence and "bob@" not in e.evidence and "zed" not in e.evidence          # a lock file is not looked at for addresses
    assert "email_accept" in e.evidence


def test_repo_check_switches_and_accepts(tmp_path):
    r = repo(tmp_path, {"a.md": "security@corp.com\n"})
    ids = lambda **kw: [x.id.rsplit(".", 1)[1] for x in secrets.repo_check(r, **kw)]
    assert "emails" in ids() and "emails" not in ids(emails=False) and "emails" not in ids(email_accept=["corp.com"])


def test_area_passes_the_options_through(tmp_path, monkeypatch):
    from judged.areas import secrets_area, Ctx
    from datetime import date
    seen = {}
    monkeypatch.setattr(secrets, "repo_check", lambda r, h, **kw: seen.update(kw) or [])
    monkeypatch.setattr(secrets, "identity_terms", lambda *a, **k: {})
    (tmp_path / "r").mkdir()
    secrets_area.run({"secrets": {"repos": [str(tmp_path / "r")], "emails": False, "email_accept": ["a@b.c"]}}, Ctx(today=date(2026, 1, 1), state=tmp_path))
    assert seen["emails"] is False and seen["email_accept"] == ["a@b.c"]


def test_service_mailbox_names_are_skipped_in_any_case():
    assert secrets.scan_emails("Git@Github.com NoReply@corp.com NO-REPLY@corp.com") == []
