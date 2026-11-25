"""SSH keys of one account: type and size, age, a private key without passphrase, file permissions, and authorized_keys.
Key material is never read into a result and comments (they often hold an e-mail address) are never printed; a key is named by its file."""
import os
import re
import time

from ..controls import M_ACCESS, Result

NAME, ORDER = "ssh_keys", 25

LINE = re.compile(r"^(\d+) (\S+) (.*) \(([A-Z0-9-]+)\)$")           # ssh-keygen -l: BITS FINGERPRINT COMMENT (TYPE)


def parse(out: str) -> list:
    """[(bits, fingerprint, type)] from `ssh-keygen -l`; the comment is dropped here, on purpose."""
    return [(int(m[1]), m[2], m[4]) for m in map(LINE.match, out.splitlines()) if m]


def weak(bits: int, typ: str, min_rsa: int) -> str:
    if typ == "DSA":
        return "DSA is obsolete"
    if typ == "RSA" and bits < min_rsa:
        return f"RSA {bits} bits (want {min_rsa} or more)"
    return ""


def check(cfg, env):
    d = os.path.expanduser(cfg.get("ssh_dir", "~/.ssh"))
    try:
        names = env.listdir(d)
    except FileNotFoundError:
        return [Result("hardening.ssh_keys", "SSH keys", "na", f"no {d}: this account has no SSH keys", M_ACCESS)]
    except OSError as e:
        return [Result("hardening.ssh_keys", "SSH keys", "unknown", f"cannot read {d}: {e}", M_ACCESS)]
    min_rsa, max_age, accept = cfg.get("ssh_min_rsa_bits", 3072), cfg.get("ssh_key_max_age_days", 730), set(cfg.get("ssh_keys_accept", []))
    now, private, notes, fails, unknown = time.time(), [], [], [], []
    for n in names:
        p = f"{d}/{n}"
        try:
            if "PRIVATE KEY-----" not in env.head(p, 64):
                continue
        except OSError:
            continue
        private.append(n)
        rc, out = env.run(["ssh-keygen", "-l", "-f", p])
        keys = parse(out) if rc == 0 else []
        if not keys:
            unknown.append(f"{n}: ssh-keygen could not describe it")
            continue
        bits, _, typ = keys[0]
        w = weak(bits, typ, min_rsa)
        if w:
            notes.append(f"{n}: {w}")
        rc, _ = env.run(["ssh-keygen", "-y", "-P", "", "-f", p])                  # succeeds with an empty passphrase only if the key has none
        if rc == 0 and n not in accept:
            notes.append(f"{n}: no passphrase ({typ}); anyone who copies the file can use it")
        mode, mtime = env.stat(p)
        if mode & 0o077:
            fails.append(f"{n}: permissions {mode:o}, other users can read it")
        age = (now - mtime) / 86400
        if age > max_age:
            notes.append(f"{n}: file is {age / 365:.1f} years old (limit {max_age / 365:.1f}); rotate")
    ak = f"{d}/authorized_keys"
    try:
        text = env.read(ak)
    except FileNotFoundError:
        text = None
    except OSError as e:
        unknown.append(f"authorized_keys: {e}")
        text = None
    count = 0
    if text is not None:
        rc, out = env.run(["ssh-keygen", "-l", "-f", ak])
        keys = parse(out) if rc == 0 else []
        count = len(keys)
        if rc != 0 and any(l.strip() and not l.startswith("#") for l in text.splitlines()):
            unknown.append("authorized_keys: ssh-keygen could not read it")
        fps = [k[1] for k in keys]
        for fp in sorted({f for f in fps if fps.count(f) > 1}):
            notes.append(f"authorized_keys: the same key twice ({fp[:19]}...)")
        for bits, fp, typ in keys:
            w = weak(bits, typ, min_rsa)
            if w:
                notes.append(f"authorized_keys: {fp[:19]}... {w}")
        mode, _ = env.stat(ak)
        if mode & 0o022:
            fails.append(f"authorized_keys: permissions {mode:o}, other users can add keys")
    bad = fails + notes
    summary = f"{len(private)} private keys" + (f", {count} authorized keys" if text is not None else ", no authorized_keys")
    res = []
    if bad:
        res.append(Result("hardening.ssh_keys", "SSH keys", "fail" if fails else "warn", summary + ": " + "; ".join(bad), M_ACCESS))
    elif not unknown:
        res.append(Result("hardening.ssh_keys", "SSH keys", "pass" if private or text is not None else "na",
                          summary + ", all strong enough, protected and not old" if private or text is not None else f"no keys in {d}", M_ACCESS))
    if unknown:
        res.append(Result("hardening.ssh_keys_read", "SSH keys: could not check", "unknown", "; ".join(unknown), M_ACCESS))
    return res
