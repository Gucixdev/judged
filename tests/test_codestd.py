import json

from judged import codestd
from judged.areas import Ctx, codestd_area
from judged.codestd import cert_c, misra_c, shell

CFG = {"skip": [], "max_files": 300, "timeout": 60, "misra_rules": ""}


class Fake:
    def __init__(self, files, tools=("cppcheck", "clang-tidy", "shellcheck"), ans=(1, "", "")):
        self.tree, self.tools, self.ans, self.ran = files, set(tools), ans, []

    def which(self, tool):
        return tool if tool in self.tools else None

    def files(self, root, exts, limit):
        return [f for f in self.tree if f.endswith(exts)][:limit + 1]

    def run(self, cmd, timeout):
        self.ran.append((cmd, timeout))
        return self.ans


def one(env, std):
    return codestd.check_repo("/r/app", CFG, env, [std])


def test_misra_parse_keeps_only_misra_rules():
    err = "/r/app/a.c:10:5:misra-c2012-10.1:Operands shall not be of an inappropriate type\n/r/app/a.c:11:1:error:syntax\nb.c:3:misra-c2012-8.4:x\n"
    assert misra_c.parse(0, "", err) == [("misra-c2012-10.1", "/r/app/a.c", 10), ("misra-c2012-8.4", "b.c", 3)]


def test_misra_command_with_and_without_rule_texts():
    plain = misra_c.command(["a.c"], {})
    assert json.loads(plain[3][len("--addon="):]) == {"script": "misra.py", "args": []} and plain[-1] == "a.c"
    texts = misra_c.command(["a.c"], {"misra_rules": "/me/rules.txt"})
    assert json.loads(texts[3][len("--addon="):])["args"] == ["--rule-texts=/me/rules.txt"]


def test_findings_are_a_warning_with_counts_and_places():
    out = "/r/app/a.c:10:5:misra-c2012-10.1:m\n/r/app/a.c:12:5:misra-c2012-10.1:m\n/r/app/b.c:3:1:misra-c2012-8.4:m\n"
    [r] = one(Fake(["/r/app/a.c", "/r/app/b.c", "/r/app/c.c"], ans=(0, "", out)), misra_c)
    assert r.id == "codestd.app.misra-c" and r.status == "warn"
    assert r.evidence == "3 findings in 2 of 3 files; most frequent: misra-c2012-10.1 x2, misra-c2012-8.4 x1; first: a.c:10, a.c:12, b.c:3"
    assert r.maps == {"iso27001": ["A.8.28"]}


def test_clean_is_pass_and_never_fail():
    [r] = one(Fake(["/r/app/a.c"], ans=(0, "", "")), misra_c)
    assert (r.status, r.evidence) == ("pass", "no findings in 1 files")


def test_missing_tool_is_unknown_and_not_run():
    env = Fake(["/r/app/a.c"], tools=())
    [r] = one(env, misra_c)
    assert r.status == "unknown" and "cppcheck is not installed" in r.evidence and env.ran == []


def test_tool_that_did_not_start_or_failed_is_unknown():
    [r] = one(Fake(["/r/app/a.c"], ans=(None, "", "timed out after 60 s")), misra_c)
    assert r.status == "unknown" and "timed out" in r.evidence
    [r] = one(Fake(["/r/app/a.c"], ans=(2, "", "cppcheck: error: bad option")), misra_c)
    assert r.status == "unknown" and "bad option" in r.evidence


def test_no_files_of_the_kind_gives_no_result():
    assert one(Fake(["/r/app/a.py"]), misra_c) == []


def test_skip_and_file_cap():
    assert codestd.check_repo("/r/app", {**CFG, "skip": ["misra-c"]}, Fake(["/r/app/a.c"]), [misra_c]) == []
    env = Fake(["/r/app/a.c", "/r/app/b.c", "/r/app/c.c"], ans=(0, "", ""))
    [r] = codestd.check_repo("/r/app", {**CFG, "max_files": 2}, env, [misra_c])
    assert r.evidence == "no findings in 2 files; only the first 2 files were checked" and env.ran[0][0][-2:] == ["/r/app/a.c", "/r/app/b.c"]
    assert env.ran[0][1] == 60


def test_a_crashing_standard_is_one_unknown_and_the_next_still_runs():
    class Bad:
        NAME, DOC, TOOL, EXTS = "bad", "bad", "x", (".c",)
        command = staticmethod(lambda f, c: 1 / 0)
        parse = staticmethod(lambda *a: [])
    res = codestd.check_repo("/r/app", CFG, Fake(["/r/app/a.c"], tools=("x", "cppcheck"), ans=(0, "", "")), [Bad, misra_c])
    assert [(r.id, r.status) for r in res] == [("codestd.app.bad", "unknown"), ("codestd.app.misra-c", "pass")]


def test_cert_and_shell_parse():
    out = "/r/m.c:3:20: warning: 'atoi' used to convert a string to an integer value [cert-err34-c]\n/r/m.c:3:30: warning: x [clang-diagnostic-foo]\n"
    assert cert_c.parse(0, out, "") == [("cert-err34-c", "/r/m.c", 3)]
    sc = "a.sh:2:6: note: Double quote to prevent globbing [SC2086]\na.sh:3:1: warning: Use rm -- [SC2115]\n"
    assert shell.parse(1, sc, "") == [("SC2086", "a.sh", 2), ("SC2115", "a.sh", 3)]
    assert shell.parse(0, "", "") == [] and shell.parse(2, "", "usage") is None


def test_area_off_by_default_and_runs_on_repos(tmp_path):
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "a.sh").write_text("echo hi\n")
    assert codestd_area.run({"codestd": {"enabled": False}}, Ctx(None, tmp_path)) == []
    assert codestd_area.run({}, Ctx(None, tmp_path)) == []
    res = codestd_area.run({"codestd": {**CFG, "enabled": True, "repos": [str(tmp_path / "*")], "skip": ["misra-c", "cert-c"]}}, Ctx(None, tmp_path))
    assert [r.id for r in res] == ["codestd.app.shell"]
