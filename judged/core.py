"""Pure logic: when is an item close enough to expiry to say something, and only once per band."""
from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass(frozen=True)
class Item:
    kind: str          # tls | gpg | date | licence
    name: str
    expires: datetime  # timezone-aware
    meta: dict = field(default_factory=dict, compare=False, hash=False)   # licence: vendor, cost, currency, owner, auto_renews


def days_left(item: Item, now: datetime) -> float:
    return (item.expires - now).total_seconds() / 86400


def band(days: float, lead_days: list[int]) -> int | None:
    """Smallest lead threshold that still covers `days`; -1 once expired; None while far from expiry.
    lead [30,14,7,1]: 40 -> None, 20 -> 30, 10 -> 14, 0.5 -> 1, -2 -> -1."""
    if days < 0:
        return -1
    covering = [t for t in lead_days if days <= t]
    return min(covering) if covering else None


def due(items: list[Item], state: dict[str, int], lead_days: list[int], now: datetime):
    """Return (alerts, new_state). An item alerts when its band is more urgent than the one already
    reported; a renewal (band back to None or a larger one) resets it so the next cycle alerts again."""
    alerts, new = [], {}
    for it in items:
        key = f"{it.kind}:{it.name}"
        b = band(days_left(it, now), lead_days)
        if b is None:
            continue
        new[key] = b
        prev = state.get(key)
        if prev is None or b < prev:
            alerts.append((it, b))
        else:
            new[key] = prev
    return alerts, new
