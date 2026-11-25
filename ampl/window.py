"""Hold judged.renew.min_when_days to the AMPL optimum on random instances. usage: window.py [N]"""
import random
import sys
from pathlib import Path

from amplpy import AMPL, modules

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from judged.renew import min_when_days  # noqa: E402


def optimum(ampl, retries, step, safety):
    ampl.param["retries"] = retries
    ampl.param["step"] = step
    ampl.param["safety"] = safety
    ampl.solve()
    assert ampl.get_value("solve_result") == "solved"
    return round(ampl.get_objective("window").value())


def main(n):
    modules.load()
    ampl = AMPL()
    ampl.option["solver"] = "highs"
    ampl.read(str(Path(__file__).with_name("window.mod")))
    rnd, bad = random.Random(7), 0
    for _ in range(n):
        k, step, s = rnd.randint(0, 8), rnd.choice([1, 3, 6, 12, 24, 36, 48, 7.5]), rnd.choice([0, 1, 2, 3, 5, 7, 2.5])
        want, got = optimum(ampl, k, step, s), min_when_days(step, k, s)
        if want != got:
            bad += 1
            print(f"MISMATCH retries={k} step={step} safety={s}: ampl {want} code {got}")
    print(f"window: {n} instances, {bad} mismatches against the AMPL optimum")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(int(sys.argv[1]) if len(sys.argv) > 1 else 200))
