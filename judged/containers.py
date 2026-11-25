"""Container audit: running and stopped containers, images, and the Containerfile/Dockerfile/compose files in your
projects. Reads `podman` (or `docker`) JSON; only what the runtime reports is judged. The file linters are line based,
not a YAML or Dockerfile parser, and say so. Image vulnerabilities need a scanner (trivy, grype); without one the
result is unknown, never pass."""
import glob
import json
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from .controls import M_CONFIG, M_UPDATES, Result

SOCKETS = ("docker.sock", "podman.sock", "containerd.sock")
HOST_DIRS = {"/", "/etc", "/root", "/boot", "/proc", "/sys", "/var/run", "/run", "/dev", "/home", "/usr", "/var/lib"}
RISKY_CAPS = {"ALL", "SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "NET_ADMIN", "DAC_READ_SEARCH"}


def runtime(which=shutil.which) -> str | None:
    return next((r for r in ("podman", "docker") if which(r)), None)


def _json(cmd: list, run=subprocess.run):
    try:
        r = run(cmd, capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if r.returncode != 0:
        return None
    try:
        return json.loads(r.stdout or "null")
    except ValueError:
        return None


def judge_container(c: dict, rootless: bool) -> list:
    """[(key, severity, text)] for one `inspect` document (podman and docker share these keys).
    The key is what `accept=NAME=KEY` matches: privileged, cap:SYS_ADMIN, net:host, pid:host, ipc:host,
    socket:/path, mount:/path, secopt:seccomp=unconfined, root, port:80/tcp, unpinned."""
    h, cfg = c.get("HostConfig") or {}, c.get("Config") or {}
    out = []
    if h.get("Privileged"):
        out.append(("privileged", "fail", "privileged: no isolation from the host"))
    for cap in h.get("CapAdd") or []:
        cap = cap.replace("CAP_", "")
        if cap in RISKY_CAPS:
            out.append((f"cap:{cap}", "fail" if cap in ("ALL", "SYS_ADMIN", "SYS_MODULE") else "warn", f"added capability {cap}"))
    if (h.get("NetworkMode") or "") == "host":
        out.append(("net:host", "warn", "host network namespace"))
    for k, key, name in (("PidMode", "pid:host", "host PID namespace"), ("IpcMode", "ipc:host", "host IPC namespace")):
        if (h.get(k) or "") == "host":
            out.append((key, "warn", name))
    for b in h.get("Binds") or []:
        src = b.split(":")[0]
        if any(src.endswith(s) for s in SOCKETS):
            out.append((f"socket:{src}", "fail", f"mounts the container runtime socket {src} (root on the host)"))
        elif src.rstrip("/") in HOST_DIRS or src == "/":
            out.append((f"mount:{src}", "fail", f"mounts the host directory {src}"))
    for so in h.get("SecurityOpt") or []:
        flat = so.replace(" ", "")
        if flat in ("seccomp=unconfined", "label=disable", "apparmor=unconfined"):
            out.append((f"secopt:{flat}", "warn", f"security option {so}"))
    user = cfg.get("User") or ""
    if user in ("", "0", "root") and not rootless:
        out.append(("root", "warn", "runs as root inside a rootful runtime"))
    for port, binds in (h.get("PortBindings") or {}).items():
        for b in binds or []:
            if b.get("HostIp") in ("", "0.0.0.0", None):
                out.append((f"port:{port}", "warn", f"port {port} published on every interface"))
    image = cfg.get("Image") or c.get("ImageName") or ""
    if image and not image.startswith("localhost/") and (":" not in image.rsplit("/", 1)[-1] or image.endswith(":latest")) and "@sha256:" not in image:
        out.append(("unpinned", "warn", f"image {image} is not pinned to a version or digest"))
    return out


def containers_check(accept=None, max_image_age_days=180, scan=True, max_scan_mb=1000, max_images=10,
                     run=subprocess.run, which=shutil.which, now=None) -> list:
    rt = runtime(which)
    if rt is None:
        return [Result("containers", "Containers", "na", "neither podman nor docker is installed", M_CONFIG)]
    accepted = set(accept or [])
    info = _json([rt, "info", "--format", "json"], run)
    if info is None:
        return [Result("containers", "Containers", "unknown", f"{rt} did not answer", M_CONFIG)]
    rootless = bool((info.get("host") or {}).get("security", {}).get("rootless")) or \
        any("rootless" in s for s in (info.get("SecurityOptions") or []))
    out = [Result("containers.runtime", "Container runtime runs rootless", "pass" if rootless else "warn",
                  f"{rt} rootless" if rootless else f"{rt} runs as root: a container escape is root on the host", M_CONFIG)]
    ids = _json([rt, "ps", "-a", "--format", "json"], run)
    if ids is None:
        out.append(Result("containers.list", "Containers", "unknown", f"{rt} ps failed", M_CONFIG))
        ids = []
    for c in ids:
        cid = c.get("Id") or c.get("ID") or ""
        doc = _json([rt, "inspect", cid], run)
        name = (c.get("Names") or [cid[:12]])[0] if isinstance(c.get("Names"), list) else c.get("Names") or cid[:12]
        if not doc:
            out.append(Result(f"containers.{name}", f"Container {name}", "unknown", "inspect failed", M_CONFIG))
            continue
        live, shown = [], []
        for key, sev, text in judge_container(doc[0], rootless):
            if any(f"{who}={k}" in accepted for who in (name, "*") for k in (key, "*")):
                shown.append(f"accepted: {text}")
            else:
                live.append(sev)
                shown.append(f"{sev}: {text}")
        status = "fail" if "fail" in live else "warn" if live else "pass"
        out.append(Result(f"containers.{name}", f"Container {name}", status, "; ".join(shown) or "no wide permissions", M_CONFIG))
    imgs = _json([rt, "images", "--format", "json"], run)
    if imgs is not None:
        now = now or time.time()
        old, undated = [], 0
        for i in imgs:
            created = i.get("Created")
            if not isinstance(created, (int, float)) or created <= 0:
                undated += 1       # an answer we cannot read is not a pass (docker's JSON differs)
            elif (now - created) / 86400 > max_image_age_days:
                old.append((i.get("Names") or i.get("RepoTags") or [i.get("Id", "")[:12]])[0])
        gap = f"; {undated} image(s) have no readable creation time" if undated else ""
        status = "warn" if old else "unknown" if undated else "pass"
        out.append(Result("containers.images.age", "Container images are fresh", status,
                          (f"{len(old)} image(s) older than {max_image_age_days} days: " + ", ".join(old[:5]) if old else f"none older than {max_image_age_days} days") + gap, M_UPDATES))
    if not scan:
        out.append(Result("containers.images.vulns", "Container image vulnerabilities", "unknown", "scanning is switched off (scan=no)", M_UPDATES))
    elif not which("trivy"):
        out.append(Result("containers.images.vulns", "Container image vulnerabilities", "unknown",
                          "trivy is not installed (pacman -S trivy); images are not checked for known vulnerabilities", M_UPDATES))
    elif imgs is not None:
        out += scan_images(rt, imgs, max_scan_mb, max_images, accept, run)
    return out


def trivy_summary(doc: dict) -> tuple:
    """(status, evidence) from one `trivy image --format json` document. An image trivy cannot read is unknown."""
    results = doc.get("Results") or []
    meta = doc.get("Metadata") or {}
    if not results and not meta.get("OS"):
        return "unknown", "trivy found no operating system or packages to check (scratch, distroless or unreadable)"
    counts, fixable, ids = {"CRITICAL": 0, "HIGH": 0}, 0, []
    for r in results:
        for v in r.get("Vulnerabilities") or []:
            sev = v.get("Severity")
            if sev in counts:
                counts[sev] += 1
                if v.get("FixedVersion"):
                    fixable += 1
                if sev == "CRITICAL" and len(ids) < 3:
                    ids.append(v.get("VulnerabilityID", "?"))
    n = counts["CRITICAL"] + counts["HIGH"]
    if n == 0:
        return "pass", "no HIGH or CRITICAL vulnerabilities known to trivy's database"
    ev = f"{counts['CRITICAL']} critical, {counts['HIGH']} high ({fixable} have a fixed version available)"
    if ids:
        ev += "; critical: " + ", ".join(ids)
    return ("fail" if counts["CRITICAL"] else "warn"), ev


def scan_images(rt: str, imgs: list, max_scan_mb=1000, max_images=10, accept=None, run=subprocess.run) -> list:
    """Scan named images with trivy: `podman|docker save` to a temp tar, `trivy image --input`. Only the image
    content is read; nothing is sent anywhere except trivy's own database download. Images over `max_scan_mb`
    or beyond `max_images` are listed as not scanned (unknown), never silently dropped."""
    out, skipped_big, skipped_n, seen = [], [], 0, set()
    accepted = set(accept or [])
    for i in imgs:
        names = i.get("Names") or i.get("RepoTags") or []
        iid = i.get("Id") or ""
        if not names or iid in seen:
            continue          # dangling (<none>) or already scanned under another tag
        seen.add(iid)
        name = names[0]
        size = i.get("Size") or i.get("VirtualSize") or 0
        if size and size > max_scan_mb * 1048576:
            skipped_big.append(f"{name} ({size / 1048576:.0f} MB)")
            continue
        if len(seen) > max_images:
            skipped_n += 1
            continue
        rid = f"containers.vuln.{name}"
        with tempfile.TemporaryDirectory(prefix="judged-scan-") as d:
            tar = f"{d}/image.tar"
            try:
                s = run([rt, "save", "-o", tar, name], capture_output=True, text=True, timeout=600)
                if s.returncode != 0:
                    out.append(Result(rid, f"Vulnerabilities in {name}", "unknown", f"{rt} save failed: {(s.stderr or '')[-150:].strip()}", M_UPDATES))
                    continue
                r = run(["trivy", "image", "--quiet", "--format", "json", "--severity", "HIGH,CRITICAL", "--input", tar],
                        capture_output=True, text=True, timeout=900)
            except (OSError, subprocess.TimeoutExpired) as ex:
                out.append(Result(rid, f"Vulnerabilities in {name}", "unknown", f"scan did not finish: {ex}", M_UPDATES))
                continue
        if r.returncode != 0:
            out.append(Result(rid, f"Vulnerabilities in {name}", "unknown", f"trivy exit {r.returncode}: {(r.stderr or '')[-200:].strip()}", M_UPDATES))
            continue
        try:
            status, ev = trivy_summary(json.loads(r.stdout))
        except ValueError:
            status, ev = "unknown", "trivy printed something that is not JSON"
        if status in ("fail", "warn") and (f"{name}=vulns" in accepted or f"*=vulns" in accepted):
            status, ev = "pass", f"accepted: {ev}"
        out.append(Result(rid, f"Vulnerabilities in {name}", status, ev, M_UPDATES))
    if skipped_big or skipped_n:
        why = []
        if skipped_big:
            why.append(f"over max_scan_mb: {', '.join(skipped_big[:5])}")
        if skipped_n:
            why.append(f"{skipped_n} more beyond max_images")
        out.append(Result("containers.vuln.skipped", "Images not scanned for vulnerabilities", "unknown", "; ".join(why), M_UPDATES))
    return out


# ---- files in projects: line based, on purpose ----
SECRETY = re.compile(r"(?i)\b(?:ENV|ARG)\s+\w*(?:PASSWORD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY)\w*\s*[= ]\s*[^\s$]{6,}")


def lint_dockerfile(text: str) -> list:
    out = []
    stages, user_set, last_from = 0, False, ""
    for n, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        up = s.upper()
        if up.startswith("FROM "):
            stages += 1
            user_set = False
            parts = s.split()
            img = next((p for p in parts[1:] if not p.startswith("--")), "")
            last_from = img
            if img.lower() != "scratch" and "@sha256:" not in img and (":" not in img.rsplit("/", 1)[-1] or img.endswith(":latest")) and "$" not in img:
                out.append((n, "warn", f"FROM {img} is not pinned to a version or digest"))
        elif up.startswith("USER ") and s.split()[1].lower() not in ("root", "0"):
            user_set = True
        elif re.match(r"(?i)ADD\s+https?://", s):
            out.append((n, "warn", "ADD of a remote URL (no checksum); use COPY plus a verified download"))
        if re.search(r"(curl|wget)[^|;&]*\|\s*(sudo\s+)?(ba|z)?sh\b", s):
            out.append((n, "warn", "downloads and pipes to a shell"))
        if SECRETY.search(s):
            out.append((n, "fail", "a secret-looking ENV/ARG has a literal value (value not shown); it stays in the image history"))
        if re.search(r"chmod\s+(-R\s+)?0?777", s):
            out.append((n, "warn", "chmod 777"))
    if stages and not user_set:
        out.append((0, "warn", f"the last stage ({last_from or '?'}) never sets USER: it runs as root"))
    return out


def lint_compose(text: str) -> list:
    """Line based. `ports:` and `cap_add:` items are only read inside their own block (by indentation)."""
    out, block, block_indent = [], "", -1
    for n, line in enumerate(text.splitlines(), 1):
        body = line.split("#", 1)[0].rstrip()
        s = body.strip()
        if not s:
            continue
        indent = len(body) - len(body.lstrip())
        if block and indent <= block_indent and not s.startswith("-"):
            block = ""
        if re.match(r"(ports|cap_add):\s*$", s):
            block, block_indent = s.rstrip(":").strip(), indent
            continue
        item = s[1:].strip().strip("\"'") if s.startswith("-") else ""
        if re.match(r"privileged:\s*[\"']?(true|yes|1)\b", s):
            out.append((n, "fail", "privileged: true"))
        elif re.match(r"network_mode:\s*[\"']?host", s):
            out.append((n, "warn", "network_mode: host"))
        elif any(x in s for x in SOCKETS):
            out.append((n, "fail", "mounts the container runtime socket (root on the host)"))
        elif block == "ports" and item and not item.startswith(("127.", "[::1]", "localhost")):
            if re.match(r"(0\.0\.0\.0:)?(\d{1,5}(-\d{1,5})?:)?\d{1,5}(-\d{1,5})?(/\w+)?$", item):
                out.append((n, "warn", f"port {item} is published on every interface (prefix 127.0.0.1: to keep it local)"))
        elif block == "cap_add" and item.replace("CAP_", "") in RISKY_CAPS:
            out.append((n, "fail" if item in ("ALL", "SYS_ADMIN", "SYS_MODULE") else "warn", f"capability {item} added"))
        elif re.search(r"(?i)(PASSWORD|SECRET|TOKEN|API_?KEY)\w*\s*[:=]\s*[\"']?[^\s$\"'{][^\s\"']{5,}", s) and not s.startswith(("- /", "image")):
            out.append((n, "fail", "a secret-looking environment value is written in the file (value not shown)"))
    return out


NAMES = ("Dockerfile", "Containerfile", "Dockerfile.*", "Containerfile.*", "*.dockerfile", "docker-compose*.y*ml", "compose*.y*ml")


def files_check(projects: list, max_files=2000) -> list:
    out, seen = [], 0
    for pat in projects:
        for root in sorted(glob.glob(str(Path(pat).expanduser()))):
            if not Path(root).is_dir():
                continue
            found = set()
            for nm in NAMES:
                found |= {p for p in Path(root).rglob(nm) if p.is_file() and not any(x in p.parts for x in (".git", "node_modules", "target", ".venv"))}
            for p in sorted(found):
                seen += 1
                if seen > max_files:
                    out.append(Result("containers.files", "Container files", "unknown", f"stopped after {max_files} files", M_CONFIG))
                    return out
                try:
                    text = p.read_text(errors="replace")
                except OSError as e:
                    out.append(Result(f"containers.file.{p}", f"Container file {p}", "unknown", str(e), M_CONFIG))
                    continue
                fs = lint_compose(text) if "compose" in p.name.lower() else lint_dockerfile(text)
                status = "fail" if any(f[1] == "fail" for f in fs) else "warn" if fs else "pass"
                ev = "; ".join(f"{'line %d: ' % n if n else ''}{t}" for n, _, t in fs[:6]) or "nothing found by the line-based lint"
                out.append(Result(f"containers.file.{p}", f"Container file {p}", status, ev, M_CONFIG))
    return out
