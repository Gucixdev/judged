from datetime import date, datetime, timezone

from judged import contracts as c

T = date(2026, 11, 25)


def e(**kw):
    return {"kind": "contract", "name": "Hosting", "expires": date(2027, 3, 31), "owner": "anna", "cost": 24000.0, "currency": "EUR", **kw}


def one(entry, today=T, warn=30):
    return c._one(entry, today, warn)


def test_add_months_clamps_to_the_end_of_the_month_and_crosses_years():
    assert c.add_months(date(2026, 1, 31), 1) == date(2026, 2, 28) and c.add_months(date(2024, 1, 31), 1) == date(2024, 2, 29)
    assert c.add_months(date(2026, 11, 30), 3) == date(2027, 2, 28) and c.add_months(date(2026, 12, 15), 12) == date(2027, 12, 15)
    assert c.add_months(date(2026, 5, 31), 0) == date(2026, 5, 31)


def test_terms_roll_only_auto_renewals_and_from_the_original_date_without_drift():
    assert c.terms(e(expires=date(2025, 1, 31), auto_renews=True, term_months=1), date(2025, 3, 1)) == {"end": date(2025, 3, 31), "notice_by": date(2025, 3, 31), "rolled": 2}
    assert c.terms(e(expires=date(2025, 1, 31), term_months=1), date(2025, 3, 1))["rolled"] == 0                      # not auto: stays in the past
    assert c.terms(e(expires=date(2026, 11, 25), auto_renews=True), T)["rolled"] == 0                              # today is still inside the term
    assert c.terms(e(expires=date(2024, 3, 31), auto_renews=True), T) == {"end": date(2027, 3, 31), "notice_by": date(2027, 3, 31), "rolled": 3}
    assert c.terms(e(notice_days=90), T)["notice_by"] == date(2026, 12, 31)


def test_the_alert_item_sits_on_the_notice_deadline_with_the_money_in_meta():
    it = c.items({"item": [e(notice_days=90, auto_renews=True), {"kind": "tls", "host": "x"}]}, T)
    assert len(it) == 1 and it[0].kind == "contract" and it[0].name == "Hosting notice deadline"
    assert it[0].expires == datetime(2026, 12, 31, tzinfo=timezone.utc) and it[0].meta["cost"] == 24000.0 and "expires" not in it[0].meta
    assert c.items({"item": [e()]}, T)[0].name == "Hosting"                                                          # no notice period: the end date itself


def test_far_from_the_deadline_is_a_pass():
    r = one(e(notice_days=30, auto_renews=True))
    assert r.status == "pass" and r.evidence == "next deadline 2027-03-01 in 96 days, ends 2027-03-31" and r.id == "paperwork.hosting"
    assert r.maps["gdpr"] == ["art28"] and r.maps["iso27001"] == ["A.5.19", "A.5.20"]


def test_inside_the_warning_window_says_what_doing_nothing_costs():
    r = one(e(notice_days=30, auto_renews=True, expires=date(2026, 12, 25)))                 # notice by 2026-11-25 = today
    assert r.status == "warn" and r.evidence == "0 days to decide (2026-11-25), ends 2026-12-25; if you do nothing it renews for 24000 EUR"
    r = one(e(notice_days=30, expires=date(2027, 1, 24)))                                    # not auto-renewing: no cost sentence
    assert r.status == "warn" and r.evidence == "30 days to decide (2026-12-25), ends 2027-01-24"                # 30 days: still inside the window
    assert one(e(notice_days=30, expires=date(2027, 1, 25))).status == "pass"                  # 31 days: outside it


def test_a_passed_notice_deadline_on_an_auto_renewing_contract_is_a_failure_with_the_cost():
    r = one(e(notice_days=90, auto_renews=True, expires=date(2027, 1, 20), term_months=24))
    assert r.status == "fail" and r.evidence == "notice deadline passed 34 days ago (2026-10-22): it renews on 2027-01-20 for another 24 months, cost 24000 EUR"


def test_a_passed_notice_date_without_auto_renewal_is_a_warning_and_an_ended_contract_a_failure():
    assert one(e(notice_days=90, expires=date(2027, 1, 20))).status == "warn"
    r = one(e(expires=date(2026, 11, 1)))
    assert r.status == "fail" and r.evidence == "ended 24 days ago (2026-11-01) and does not auto-renew: renew it or remove it from the list"


def test_a_rolled_date_a_missing_owner_and_a_cost_without_currency_are_said():
    r = one(e(expires=date(2024, 3, 31), auto_renews=True, notice_days=30))
    assert r.status == "warn" and "rolled forward 3 term(s) because it auto-renews" in r.evidence
    r = one(e(owner="", currency=""))
    assert r.status == "warn" and "no owner" in r.evidence and "cost has no currency" in r.evidence
    assert one(e(), warn=0).status == "pass" and "no owner" not in one(e()).evidence


def test_type_and_maps():
    assert one(e(type="widget")).status == "unknown" and "not one of" in one(e(type="widget")).evidence
    assert one(e(type="insurance")).maps == {} and one(e(type="trademark")).maps == {} and one(e(type="dpa")).maps["gdpr"] == ["art28"]
    assert one(e(type="insurance")).title == "insurance Hosting" and one(e()).title == "contract Hosting"


def test_exposure_sums_only_auto_renewing_money_that_is_locked_or_near_and_never_mixes_currencies():
    rows = [e(name="A", notice_days=10, auto_renews=True, expires=date(2026, 12, 1)),             # notice passed (fail), 24000 EUR
            e(name="B", notice_days=10, auto_renews=True, expires=date(2026, 12, 30), cost=1000.0, currency="USD"),   # notice in 4 days (warn), USD
            e(name="C", notice_days=10, expires=date(2026, 12, 1)),                                # passed but not auto-renewing: no exposure
            e(name="D", notice_days=10, auto_renews=True, expires=date(2028, 1, 1)),                # far: pass
            e(name="E", notice_days=10, auto_renews=True, expires=date(2026, 12, 1), cost=500.0, currency="EUR")]
    out = c.audit({"item": rows}, T)
    assert out[-1].id == "paperwork.exposure" and out[-1].status == "warn"
    assert out[-1].evidence == "auto-renewing contracts past or near their notice deadline: 24500 EUR, 1000 USD"
    assert len(out) == 6 and c.audit({"item": [rows[3], rows[2]]}, T)[-1].id != "paperwork.exposure"
    nocur = c.audit({"item": [e(notice_days=10, auto_renews=True, expires=date(2026, 12, 1), currency="")]}, T)
    assert nocur[-1].evidence.endswith("24000 (no currency)")


def test_the_area_is_found_and_reads_the_warning_window_from_notify(tmp_path):
    from judged import areas
    from judged.areas import paperwork_area as pa
    assert pa in areas.discover() and "contract" in areas.specs()
    cfg = {"item": [e(notice_days=30, expires=date(2027, 1, 20))], "notify": {"lead_days": [90, 30]}}
    assert pa.run(cfg, areas.Ctx(today=T, state=tmp_path))[0].status == "warn"
    cfg["notify"]["lead_days"] = [7]
    assert pa.run(cfg, areas.Ctx(today=T, state=tmp_path))[0].status == "pass"


def test_a_config_line_loads_and_a_typo_is_an_error(tmp_path):
    from judged import conf
    p = tmp_path / "x.conf"
    p.write_text('contract "Hosting" 2027-03-31 type=supplier notice_days=90 auto_renews=1 cost=24000 currency=EUR owner=anna\n')
    got = conf.load(p)["item"][0]
    assert got["kind"] == "contract" and got["notice_days"] == 90 and got["auto_renews"] is True and got["type"] == "supplier"
    p.write_text('contract "Hosting" 2027-03-31 notice_dayz=90\n')
    try:
        conf.load(p)
        raise AssertionError("typo accepted")
    except ValueError:
        pass
