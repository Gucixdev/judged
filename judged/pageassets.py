"""Images and animations on the front page of an own site, as warnings: a raster image that is not WebP (PNG, JPEG, GIF, BMP, TIFF) and an animation
that is a GIF or an APNG. WebP, AVIF and SVG pass, an animated WebP and a <video> pass as animations. Only assets on the same host are fetched, the
rest are counted. Nothing is downloaded beyond the first 200 KB of each file (the fetcher's limit), and the saving is NOT promised: it depends on the picture."""
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit
import re

from .controls import M_CONFIG, Result

RASTER = {"image/png": "PNG", "image/jpeg": "JPEG", "image/jpg": "JPEG", "image/gif": "GIF", "image/bmp": "BMP", "image/tiff": "TIFF", "image/apng": "APNG"}
FINE = {"image/webp", "image/avif", "image/svg+xml", "image/x-icon", "image/vnd.microsoft.icon"}
BY_EXT = {".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".gif": "image/gif", ".bmp": "image/bmp", ".tif": "image/tiff", ".tiff": "image/tiff",
          ".webp": "image/webp", ".avif": "image/avif", ".svg": "image/svg+xml", ".apng": "image/apng"}


class Pick(HTMLParser):
    """Collects image URLs: <img src srcset>, <source srcset> inside <picture>, <video poster>, url(...) in style attributes."""
    def __init__(self):
        super().__init__()
        self.urls, self._video = [], 0

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "video":
            self._video += 1
        if tag in ("img", "source") and not (tag == "source" and self._video):
            for u in [a.get("src", "")] + [s.strip().split()[0] for s in (a.get("srcset") or "").split(",") if s.strip()]:
                if u and not u.startswith("data:"):
                    self.urls.append(u)
        if tag == "video" and a.get("poster"):
            self.urls.append(a["poster"])
        self.urls += [m for m in re.findall(r"url\(\s*['\"]?([^'\")\s]+)", a.get("style") or "") if not m.startswith("data:")]

    def handle_endtag(self, tag):
        if tag == "video" and self._video:
            self._video -= 1


def asset_urls(html: str, host: str, base: str = "/") -> tuple:
    """(same-host paths in page order without duplicates, count of other-host assets)."""
    p = Pick()
    p.feed(html)
    mine, other = [], set()
    for u in p.urls:
        full = urljoin(f"https://{host}{base}", u)
        s = urlsplit(full)
        if s.hostname == host:
            path = s.path + (f"?{s.query}" if s.query else "")
            if path not in mine:
                mine.append(path)
        else:
            other.add(full)
    return mine, len(other)


def is_animated(kind: str, body: bytes) -> bool | None:
    """True / False, None when the first bytes cannot tell (a large GIF with one frame seen so far)."""
    if kind == "image/gif":
        n = body.count(b"\x21\xf9\x04")                           # one Graphic Control Extension per frame
        return True if n > 1 else (None if len(body) >= 200_000 else False)
    if kind in ("image/png", "image/apng"):
        a, d = body.find(b"acTL"), body.find(b"IDAT")
        return a != -1 and (d == -1 or a < d)
    return False


def kind_of(path: str, headers: dict) -> str:
    ct = headers.get("content-type", "").split(";")[0].strip().lower()
    if ct in RASTER or ct in FINE:
        return ct
    ext = "." + path.split("?")[0].rsplit(".", 1)[-1].lower() if "." in path.split("?")[0].rsplit("/", 1)[-1] else ""
    return BY_EXT.get(ext, ct or "unknown")


def _kb(n: int) -> str:
    return f"{n / 1024:.0f} KB" if n >= 1024 else f"{n} B"


def check(host: str, get, max_assets: int = 40) -> list:
    rid = f"web.{host}"
    try:
        st, h, _, body = get(host, "https", "/", "GET")
    except OSError as e:
        return [Result(f"{rid}.images", f"{host} images", "unknown", f"cannot fetch the page: {e}", M_CONFIG)]
    if "html" not in h.get("content-type", "html").lower():
        return []
    mine, other = asset_urls(body.decode("utf-8", "replace"), host)
    old, anim, errs, fine = [], [], [], 0
    for path in mine[:max_assets]:
        try:
            st, ah, _, data = get(host, "https", path, "GET")
        except OSError as e:
            errs.append(f"{path} ({e})")
            continue
        if st != 200:
            errs.append(f"{path} (HTTP {st})")
            continue
        kind = kind_of(path, ah)
        size = int(ah.get("content-length", len(data)) or len(data))
        if kind in RASTER:
            old.append(f"{path.split('?')[0]} ({RASTER[kind]}, {_kb(size)})")
            moving = is_animated(kind, data)
            if moving is not False:
                anim.append(f"{path.split('?')[0]} ({RASTER[kind]}{', maybe' if moving is None else ''}, {_kb(size)})")
        elif kind in FINE:
            fine += 1
    notes = ([f"{len(mine) - max_assets} more not looked at (limit {max_assets})"] if len(mine) > max_assets else []) + \
            ([f"{other} images on other hosts not checked"] if other else []) + ([f"could not be read: {', '.join(errs[:3])}"] if errs else [])
    tail = ("; " + "; ".join(notes)) if notes else ""
    res = [Result(f"{rid}.images", f"{host} image formats", "warn" if old else ("unknown" if errs and not fine else "pass"),
                  (f"{len(old)} not WebP: {', '.join(old[:6])}{' (+%d more)' % (len(old) - 6) if len(old) > 6 else ''}. WebP files are usually smaller; how much depends on the picture" if old
                   else f"{fine} images, all WebP, AVIF or SVG" if fine else "no same-host images on the front page") + tail, M_CONFIG)]
    if anim:
        res.append(Result(f"{rid}.animations", f"{host} animations", "warn",
                          f"{len(anim)} animated images are not WebP or video: {', '.join(anim[:6])}. The same animation as animated WebP or a muted looping video is usually smaller; how much depends on the picture", M_CONFIG))
    return res
