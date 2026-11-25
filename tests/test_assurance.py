import json
from datetime import date

import pytest

from judged import areas, conf, controls, statement
from judged.areas import assurance_area as a

T = date(2026, 11, 25)


def run(text):
    return a.run(conf.parse(text), areas.Ctx(T, None))


def one(text):
    [r] = run(text)
    return r


GOOD = 'review "Risk assessment" last=2026-03-01 owner=anna proof=https://x/r.pdf maps=iso27001:A.5.15\n'


def test_a_pass_that_rests_only_on_statements_says_so():
    r = one(GOOD)
    assert (r.status, r.attested, r.id) == ("pass", True, "review.risk-assessment")
    assert r.evidence == "next due 2027-03-01 (96 days); owner anna; proof https://x/r.pdf"
    assert statement.control_status([r]) == "pass" and statement.shown("pass", [r]) == "pass (statements only)"
    measured = controls.Result("x", "x", "pass", "", r.maps)
    assert statement.shown("pass", [r, measured]) == "pass" and statement.shown("warn", [r]) == "warn"
    assert statement.control_status([r, controls.Result("y", "y", "fail", "", r.maps)]) == "fail"


@pytest.mark.parametrize("edit, status, text", [
    (("last=2026-03-01", ""), "fail", "never done"),
    (("last=2026-03-01", "last=2026-11-26"), "fail", "in the future"),
    (("last=2026-03-01", "last=2025-11-24"), "fail", "overdue since 2026-11-24"),
    (("last=2026-03-01", "last=2025-11-25"), "warn", "(0 days)"),
    (("last=2026-03-01", "last=2025-12-25"), "warn", "(30 days)"),
    (("last=2026-03-01", "last=2025-12-26"), "pass", "(31 days)"),
    (("last=2026-03-01", "last=2026-03-01 months=6"), "fail", "overdue since 2026-09-01"),
    (("owner=anna", ""), "warn", "no owner="),
    (("proof=https://x/r.pdf", ""), "warn", "no proof="),
    (("proof=https://x/r.pdf", "proof=/no/such/file.pdf"), "warn", "is not there"),
    (("A.5.15", "A.99"), "warn", "no known control: iso27001:A.99"),
])
def test_what_stops_a_statement_from_counting(edit, status, text):
    r = one(GOOD.replace(*edit))
    assert r.status == status and text in r.evidence


def test_a_proof_file_that_exists_and_a_ticket_id_are_accepted(tmp_path):
    f = tmp_path / "r.pdf"
    f.write_text("x")
    assert one(GOOD.replace("https://x/r.pdf", str(f))).status == "pass"
    assert one(GOOD.replace("https://x/r.pdf", "TICKET-12")).status == "pass"


def test_certification_expiry_facts_and_controls_of_your_own_framework():
    r = one('framework acme "Acme rules"\ncontrol acme 1 "Doors"\n'
            'certification "Cyber Essentials" 2027-04-30 number=N1 issuer="Body Ltd" scope=all owner=anna proof=URL maps=acme:1\n')
    assert r.status == "pass" and r.evidence == "valid until 2027-04-30 (156 days); number N1; issuer Body Ltd; scope all; owner anna; proof URL"
    assert one("certification ISO 2026-11-24 owner=anna proof=URL\n").evidence.startswith("expired 2026-11-24")


def test_not_applicable_needs_a_person_and_a_reason_and_never_hides_a_finding():
    ok = one('notapplicable iso27001 A.8.28 owner=anna reason="no code"\n')
    assert (ok.status, statement.control_status([ok])) == ("na", "n/a")
    bad = one("notapplicable iso27001 A.8.28 owner=anna\n")
    assert bad.status == "warn" and "ignored" in bad.evidence and statement.control_status([bad]) == "warn"
    assert statement.control_status([ok, controls.Result("m", "m", "fail", "", ok.maps)]) == "fail"
    assert statement.control_status([controls.Result("m", "m", "na", "", ok.maps)]) == "manual"


def test_review_and_certification_dates_alert_and_a_never_done_review_has_no_date():
    cfg = conf.parse("review a last=2026-01-31 months=1 owner=bo\nreview b\ncertification c 2027-01-01\ncontract d 2027-01-01\n")
    got = {(i.kind, i.name): i for i in areas.items(cfg, T)}
    assert sorted(got) == [("certification", "c"), ("contract", "d"), ("review", "a")]
    assert got[("review", "a")].expires.date() == date(2026, 2, 28) and got[("review", "a")].meta == {"owner": "bo"}


def test_statement_of_applicability_lists_proof_and_what_is_open():
    fw = {"f": {"name": "F", "controls": {"1": "One", "2": "Two", "3": "Three", "4": "Four", "5": "Five"}}}
    res = [controls.Result("a", "firewall", "pass", "up", {"f": ["1"]}),
           controls.Result("b", "review Risk", "pass", "x", {"f": ["2"]}, attested=True),
           controls.Result("c", "scope", "na", "does not apply: no code (decided by anna)", {"f": ["3"]}, attested=True),
           controls.Result("d", "updates", "fail", "old", {"f": ["4"]})]
    text = controls.soa(fw, res, today=T)
    assert "| 1 One | yes | pass | firewall (measured, pass) |" in text
    assert "| 2 Two | yes | pass (statements only) | review Risk (statement, pass) |" in text
    assert "| 3 Three | no | n/a | does not apply: no code (decided by anna) |" in text
    assert "| 5 Five | yes | manual | nothing yet |" in text
    assert "Open before an audit: failing: 4; needs a person: 5." in text and "certification body" in text
    assert "2 pass, 1 fail, 1 manual, 1 n/a" in text
    assert "nothing that judged knows of" in controls.soa({"f": {"name": "F", "controls": {"1": "One"}}}, res, today=T)


def test_the_report_and_its_json_keep_a_statement_apart_from_a_measurement():
    from judged import report
    rs = [statement.Result("a", "Said", "pass", "e", attested=True), statement.Result("b", "Measured", "pass", "e")]
    assert "## Fine (2)\n\nMeasured, Said (statement)\n" in report.build(rs, today=date(2026, 1, 1))
    assert [x.get("attested") for x in json.loads(report.dump(rs))] == [True, None]


def test_the_printed_review_list_has_one_line_per_requirement_and_passes_only_when_filled_in():
    ce = conf.catalog()["frameworks"]["ce"]["controls"]
    text = conf.reviews(conf.catalog()["frameworks"])
    cfg = conf.parse(text)
    assert [e["maps"] for e in cfg["item"]] == [{"ce": [cid]} for cid in ce]            # only frameworks that need statements
    assert {r.status for r in run(text)} == {"fail"}                                     # nothing was done yet
    results = run(text.replace("months=12 owner= proof=", f"months=12 last={T} owner=anna proof=TICKET-1"))
    assert {r.status for r in results} == {"pass"}
    rows = controls.assemble("ce", conf.catalog()["frameworks"]["ce"], results)
    assert {st for _, _, st, _ in rows} == {"pass"}
    assert "maps=iso27001:A.5.15" in conf.reviews(conf.catalog()["frameworks"], "iso27001")
    assert "maps=ce:" not in conf.reviews(conf.catalog()["frameworks"], "iso27001")
