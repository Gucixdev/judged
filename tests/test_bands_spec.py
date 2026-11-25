"""judged.core.band held to the specification proved in lean4/Bands.lean, on a grid of days and random lead sets."""
import random

from judged.core import band
from judged.renew import min_when_days, window_warning


def test_band_meets_spec():
    rnd = random.Random(3)
    for _ in range(300):
        ls = sorted(rnd.sample(range(1, 90), rnd.randint(1, 5)), reverse=True)
        prev = None
        for d in [x / 2 for x in range(-6, 200)]:           # half-day steps, expired first
            b = band(d, ls)
            if d < 0:
                assert b == -1
            elif b is not None:
                assert b in ls and d <= b and all(b <= t for t in ls if d <= t)
            else:
                assert all(d > t for t in ls)
        bands = [band(d / 2, ls) for d in range(0, 200)]      # moving away from expiry, bands only grow
        seen = [x for x in bands if x is not None]
        assert seen == sorted(seen)


def test_window():
    assert min_when_days(6, 3, 3) == 4           # 3 days reserve + 3 failures * 6 h = 3.75 days
    assert min_when_days(24, 3, 3) == 6
    assert min_when_days(6, 0, 0) == 0
    assert window_warning({"when_days": 21}, 6) is None
    assert "use at least" in window_warning({"when_days": 3}, 24)
