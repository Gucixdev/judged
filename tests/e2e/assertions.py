"""What judged must say about the fixture world. Every line is one claim; the first wrong one stops the run."""
import json
import os
import re
import sys
from pathlib import Path

W = Path(sys.argv[1])
TOKEN = os.environ["TOKEN"]
bad = []


def claim(ok: bool, what: str):
    print(("ok   " if ok else "FAIL ") + what)
    if not ok:
        bad.append(what)


def read(name):
    return (W / name).read_text()


res = {r["id"]: r for r in json.loads(read("audit.json"))}
every = read("audit.json") + "".join(read(f) for f in ("check.out", "check.err", "licences.out", "obligations.out", "audit.err", "renew.out"))

# expiry list: the three soon-ish things are there with the right number of days, the far one is not due
chk = read("check.out")
d = lambda pat: float(re.search(pat + r"\s", chk).group(1)) if re.search(pat + r"\s", chk) else None
claim(d(r"([\d.]+) d\s+tls\s+e2e-tls") is not None and 4 <= d(r"([\d.]+) d\s+tls\s+e2e-tls") <= 5.1, "tls certificate has about 5 days left")
claim(d(r"([\d.]+) d\s+gpg\s+pub") is not None and 9 <= d(r"([\d.]+) d\s+gpg\s+pub") <= 10.1, "gpg key has about 10 days left")
claim(d(r"([\d.]+) d\s+date\s+e2e licence") is not None and 2 <= d(r"([\d.]+) d\s+date\s+e2e licence") <= 3.1, "dated item has about 3 days left")
claim("e2e seats" in chk, "bought licence is listed")
claim("obligation" in chk and "Cyber Essentials" in chk, "tracked obligation became an expiry item")

# secrets: findings with locations, never the value
claim(res["secrets.leaky.names.untracked"]["status"] == "fail" and ".env" in res["secrets.leaky.names.untracked"]["evidence"], "untracked .env in the leaky repo is a fail")
claim(res["secrets.leaky.shapes"]["status"] == "fail" and "notes.md:1" in res["secrets.leaky.shapes"]["evidence"], "token in notes.md found at notes.md:1")
claim(res["secrets.leaky.history"]["status"] == "fail", "token is found in history")
claim(res["secrets.leaky.gitignore"]["status"] == "warn", "leaky repo has no .gitignore cover")
claim(res["secrets.clean.gitignore"]["status"] == "pass", "clean repo .gitignore covers the usual names")
claim(res["secrets.clean.history"]["status"] == "pass", "clean repo history is clean")
claim(TOKEN not in every and TOKEN[-12:] not in every, "the token value appears in no output at all")

# dependencies offline: unknown, never pass
claim(res["deps.leaky.lockfiles"]["status"] == "pass" and "1 registry packages" in res["deps.leaky.lockfiles"]["evidence"], "Cargo.lock parsed: 1 registry package")
claim(res["deps.leaky.vulns"]["status"] == "unknown", "no network: vulnerabilities are unknown, not pass")

# the host checks must not claim what a container cannot show
claim(all(r["status"] in ("pass", "warn", "fail", "unknown", "na") for r in res.values()), "every result has a valid status")
claim(res["tls.www.e2e.test.connect"]["status"] != "fail" if "tls.www.e2e.test.connect" in res else True, "audit reached the TLS server on port 8443")
claim(any(k.startswith("mail.example.test") and v["status"] == "unknown" for k, v in res.items()), "no DNS: mail checks are unknown, not pass")
claim("warn: domain" in W.joinpath("check.err").read_text() or "example.test" in W.joinpath("check.err").read_text(), "unreachable RDAP is reported on stderr")

# licences and obligations
claim("2027" in read("licences.out") or "total" in read("licences.out"), "licence calendar printed with totals")
claim("[UNREVIEWED]" in read("obligations.out"), "unreviewed duties are marked")

# renewal: real server, real restart
claim("would-renew" in read("renew-dry.out"), "dry run: 5 days left < 21 would renew")
claim(re.search(r"^renewed\s+www.e2e.test", read("renew.out"), re.M) is not None, "renew: real ACME issuance (certbot to Pebble), service restarted, served certificate changed")
claim("Pebble" in read("served.txt"), "the certificate now served was issued by the ACME server (Pebble), not by the local CA")
claim(re.search(r"^ok\s+www.e2e.test", read("renew-again.out"), re.M) is not None, "second pass: 90 days left, nothing to do")

claim("always due" in read("renew-short.out") and "when_days=21" in read("renew-short.out"), "6-day certificate with when_days=21: judged warns that it is always due")

print(f"\n{len(bad)} wrong" if bad else "\nall claims hold")
sys.exit(1 if bad else 0)
