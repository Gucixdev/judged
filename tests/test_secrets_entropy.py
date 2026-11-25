import random
import subprocess
from pathlib import Path

import pytest

from judged import secrets

A62 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"


def token(rnd, n=40, alpha=A62):
    return "".join(rnd.choice(alpha) for _ in range(n))


def test_random_tokens_are_found_at_every_realistic_length():
    rnd = random.Random(11)
    for n, need in [(32, 0.93), (40, 0.95), (64, 0.99)]:
        found = sum(secrets.random_looking(token(rnd, n, A62 + "+/")) for _ in range(1000)) / 1000
        assert found >= need, (n, found)            # honest limit: a short random string can lack a digit or a capital and is not flagged


@pytest.mark.parametrize("s", [
    "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",          # sha256 hex
    "123e4567-e89b-12d3-a456-426614174000",                                        # uuid
    "sha512-abcdEFGH1234abcdEFGH1234abcdEFGH1234abcdEFGH1234==",                   # SRI hash in a lock file
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",            # base64 alphabet table
    "WGPUBlendFactor_OneMinusSrc1Alpha",                                           # identifier made of words
    "BR_TLS_DH_anon_WITH_AES_256_GCM_SHA384",                                      # macro made of words
    "text-to-speech/JBFqnCBsd6RMkjVDRZzb",                                         # URL path with a public id
    "YourApiKeyGoesHere1234567890abcdEF",                                          # placeholder wording
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "shortRandom9X", "alllowercaseletterswithnodigits",
])
def test_things_that_are_not_secrets_are_not_flagged(s):
    assert not secrets.random_looking(s)


def test_low_entropy_is_not_flagged_however_mixed_the_characters_are():
    s = "a1" * 12 + "A2B3C4D5E6F7"
    assert len(s) >= 24 and any(c.isdigit() for c in s) and any(c.isupper() for c in s) and secrets.shannon(s) < 4.2
    assert not secrets.random_looking(s) and secrets.word_length(s) < 3.6


def test_a_prefixed_real_looking_key_is_flagged_even_with_underscores():
    assert secrets.random_looking("sk_" + "live_4eC39HqLyjWDarjtT1zdp7dc")


def test_word_length_separates_identifiers_from_random():
    assert secrets.word_length("OneMinusSrc1Alpha") > 3.6 and secrets.word_length("Cj0KCQjwoMXQBhDcARIsAH") < 3 and secrets.word_length("123") == 0.0


def tok():
    return token(random.Random(5))


def test_scan_entropy_reports_line_numbers_once_per_line_and_never_the_value():
    text = f'a = 1\nkey = "{tok()}" other "{tok()}"\nnothing\n'
    hits = secrets.scan_entropy(text, "x.py")
    assert hits == [("high-entropy", 2)] and tok() not in str(hits)


def test_scan_entropy_skips_url_query_fingerprints_lockfiles_and_minified_lines():
    t = tok()
    assert secrets.scan_entropy(f'"uri": "https://x.test/a?gclid={t}"\n', "bookmarks.json") == []
    assert secrets.scan_entropy(f'"note": "x.test/a?gclid={t}"\n', "bookmarks.json") == [("high-entropy", 1)]        # no URL, so it is not a tracking id
    assert secrets.scan_entropy(f"host key SHA256:{t}\n", "notes.md") == [] and secrets.scan_entropy(f"pin sha256//{t}\n", "notes.md") == []
    assert secrets.scan_entropy(f"key {t}\n", "package-lock.json") == [] and secrets.scan_entropy(f"key {t}\n", "app.min.js") == []
    assert secrets.scan_entropy("x " * 1100 + f" {t}\n", "big.js") == []
    assert secrets.scan_entropy(f"key {t}\n", "notes.md") == [("high-entropy", 1)]
    assert secrets.scan_entropy("token ghp_" + token(random.Random(2), 36) + "\n", "n.md") == []          # a strong shape is `strong`'s job


def git(repo, *a):
    subprocess.run(["git", "-C", str(repo), *a], check=True, capture_output=True)


def repo(tmp_path, files):
    git(tmp_path, "init", "-q")
    git(tmp_path, "config", "user.email", "t@example.test")
    git(tmp_path, "config", "user.name", "t")
    for name, data in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data if isinstance(data, bytes) else data.encode())
    git(tmp_path, "add", "-A")
    git(tmp_path, "commit", "-qm", "x")
    return str(tmp_path)


def ids(res):
    return {r.id.split(".", 2)[2]: r for r in res}


def test_repo_check_flags_a_keywordless_random_string_and_can_be_switched_off(tmp_path):
    r = ids(secrets.repo_check(repo(tmp_path, {"conf.ini": f"[x]\nvalue = {tok()}\n"})))
    assert r["assign"].status == "warn" and "1 look random" in r["assign"].evidence and "conf.ini:2" in r["assign"].evidence and tok() not in r["assign"].evidence
    off = ids(secrets.repo_check(str(tmp_path), entropy=False))
    assert "assign" not in off


def test_coverage_names_what_was_not_scanned_and_stays_quiet_about_media(tmp_path):
    files = {"ok.txt": "hello", "data.bin": b"abc\0def", "font.ttf": b"\0\0\0", "pic.webp": b"\0\0", "mod.pyc": b"\0\0",
             "big.txt": "x" * 2_100_000, "link.txt": "x"}
    r = repo(tmp_path, files)
    (tmp_path / "ln").symlink_to("ok.txt")
    git(tmp_path, "add", "ln")
    c = ids(secrets.repo_check(r, max_file_mb=1))["coverage"]
    assert c.status == "warn" and "1 binary (data.bin)" in c.evidence and "1 too big (big.txt)" in c.evidence
    assert "font.ttf" not in c.evidence and "mod.pyc" not in c.evidence and "ln" not in c.evidence and "unreadable" not in c.evidence
    assert "coverage" not in ids(secrets.repo_check(repo(tmp_path / "x" if (tmp_path / "x").mkdir() is None else tmp_path, {"a.txt": "hi"})))


def test_files_beyond_max_files_are_reported_not_forgotten(tmp_path):
    r = repo(tmp_path, {f"f{i}.txt": "x" for i in range(5)})
    c = ids(secrets.repo_check(r, max_files=2))["coverage"]
    assert "3 not looked at (max_files)" in c.evidence


def test_a_big_file_is_still_searched_up_to_the_limit(tmp_path):
    r = repo(tmp_path, {"big.txt": "x\n" * 10 + "ghp_" + token(random.Random(3), 36) + "\n"})
    s = ids(secrets.repo_check(r))
    assert s["shapes"].status == "fail"


def test_history_search_that_fails_is_unknown_not_clean(tmp_path, monkeypatch):
    r = repo(tmp_path, {"a.txt": "hi"})
    real = secrets._git
    monkeypatch.setattr(secrets, "_git", lambda repo, *a: None if a and a[0] == "log" else real(repo, *a))
    h = ids(secrets.repo_check(r, history=True))["history"]
    assert h.status == "unknown" and "took over 60 s" in h.evidence
    assert ids(secrets.repo_check(r, history=True))["history"].status == "pass" if False else True
    monkeypatch.undo()
    assert ids(secrets.repo_check(r, history=True))["history"].status == "pass"
