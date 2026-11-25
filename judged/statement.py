"""The words judged speaks: every check states pass, warn or fail (unknown when it could not look, na when it does not apply), a
control sums up the statements about it, and what cannot wait goes out as an alert, said once."""
import sys
from dataclasses import dataclass, field
from enum import StrEnum


class Status(StrEnum):
    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"
    UNKNOWN = "unknown"
    NA = "na"


SEVERITY = {Status.FAIL: 3, Status.WARN: 2, Status.UNKNOWN: 1, Status.PASS: 0, Status.NA: 0}


@dataclass
class Result:
    id: str
    title: str
    status: str            # a Status value
    evidence: str
    maps: dict = field(default_factory=dict)
    attested: bool = False  # a person's statement, not something judged measured


def control_status(results: list, confirm: bool = False) -> str:
    """The worst statement about a control; 'manual' when there is none (never a pass), 'n/a' when a person took it out of scope.
    `confirm`: measurements alone cannot pass this control, a person's passing statement has to be among them, else 'manual'."""
    counted = [r for r in results if r.status != Status.NA]
    if not counted:
        return "n/a" if any(r.attested for r in results) else "manual"
    worst = max((r.status for r in counted), key=SEVERITY.__getitem__)
    if confirm and worst == Status.PASS and not any(r.attested for r in counted):
        return "manual"
    return worst


def shown(status: str, results: list) -> str:
    """The status as printed: a pass that rests on nothing measured says so."""
    measured = any(r.status != Status.NA and not r.attested for r in results)
    return "pass (statements only)" if status == Status.PASS and not measured else status


@dataclass(frozen=True)
class Alert:
    key: str
    value: object          # remembered once the alert is out, so the same thing is said only once
    title: str = ""        # empty: nothing to say, only remember the value
    body: str = ""


def deliver(alerts: list, state: dict, last: dict, send, dry: bool) -> dict:
    """Send what has a title and record each value in `state`. One that did not get out keeps what `last` held, so the next pass
    tries again."""
    for a in alerts:
        if a.title and dry:
            print(f"[dry-run] would send: {a.title}")
        elif a.title and not send(a.title, a.body):
            print(f"warn: not delivered: {a.title}", file=sys.stderr)
            if a.key in last:
                state[a.key] = last[a.key]
            else:
                state.pop(a.key, None)
            continue
        state[a.key] = a.value
    return state
