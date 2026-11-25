from judged import pageassets as pa

PAGE = b"""<html><body style="background:url('/bg.jpg')">
<img src="/a.png" alt=""><img src="logo.webp"><img src="data:image/png;base64,AAAA"><img src="https://cdn.other.test/x.png">
<picture><source srcset="/hero.webp 1x, /hero@2x.webp 2x"><img src="/hero.jpg"></picture>
<video poster="/poster.jpg"><source src="/clip.mp4" type="video/mp4"></video>
<img src="/anim.gif"><img src="/same.png"><img src="/same.png"><div style='background-image: url("/d.svg")'></div>
</body></html>"""


def GIF(frames, pad=0):
    return b"GIF89a" + b"\x00" * 10 + b"\x21\xf9\x04\x00\x00\x00\x00\x00" * frames + b"\x00" * pad


STATIC_PNG = b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\rIHDR" + b"\x00" * 17 + b"\x00\x00\x00\x04IDAT" + b"\x00" * 8
APNG = b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\rIHDR" + b"\x00" * 17 + b"\x00\x00\x00\x08acTL" + b"\x00" * 12 + b"\x00\x00\x00\x04IDAT" + b"\x00" * 8


def site(files, page=PAGE):
    """files: path -> (status, content-type, body); the front page is served at /."""
    calls = []
    def get(host, scheme, path, method="GET"):
        calls.append(path)
        if path == "/":
            return 200, {"content-type": "text/html; charset=utf-8"}, None, page
        st, ct, body = files.get(path, (404, "", b""))
        return st, ({"content-type": ct} if ct else {}), None, body
    get.calls = calls
    return get


def ids(res):
    return {r.id.rsplit(".", 1)[1]: r for r in res}


def test_asset_urls_collects_every_kind_once_and_counts_other_hosts():
    mine, other = pa.asset_urls(PAGE.decode(), "example.test")
    assert mine == ["/bg.jpg", "/a.png", "/logo.webp", "/hero.webp", "/hero@2x.webp", "/hero.jpg", "/poster.jpg", "/anim.gif", "/same.png", "/d.svg"]
    assert other == 1                                                  # data: URIs are skipped, <source> inside <video> is not an image


def test_gif_animation_png_and_webp_are_judged_by_what_they_are():
    files = {"/a.png": (200, "image/png", STATIC_PNG), "/logo.webp": (200, "image/webp", b"RIFF"), "/hero.webp": (200, "image/webp", b"x"), "/hero@2x.webp": (200, "image/webp", b"x"),
             "/hero.jpg": (200, "image/jpeg", b"\xff\xd8" + b"\x00" * 3000), "/poster.jpg": (200, "image/jpeg", b"\xff\xd8"), "/bg.jpg": (200, "image/jpeg", b"\xff\xd8"),
             "/anim.gif": (200, "image/gif", GIF(3)), "/same.png": (200, "image/png", APNG), "/d.svg": (200, "image/svg+xml", b"<svg/>")}
    r = ids(pa.check("example.test", site(files)))
    assert r["images"].status == "warn" and r["images"].evidence.startswith("6 not WebP: /bg.jpg (JPEG, 2 B), /a.png (PNG, ")
    assert "/hero.jpg (JPEG, 3 KB)" in r["images"].evidence and "/anim.gif (GIF" in r["images"].evidence and "1 images on other hosts not checked" in r["images"].evidence
    assert r["animations"].status == "warn" and "/anim.gif (GIF" in r["animations"].evidence and "/same.png (PNG" in r["animations"].evidence and "/a.png" not in r["animations"].evidence
    assert "2 animated images" in r["animations"].evidence


def test_a_site_with_only_webp_avif_and_svg_passes_and_has_no_animation_result():
    page = b'<img src="/a.webp"><img src="/b.avif"><img src="/c.svg"><img src="/d.dat">'
    r = ids(pa.check("example.test", site({"/a.webp": (200, "image/webp", b"x"), "/b.avif": (200, "image/avif", b"x"), "/c.svg": (200, "image/svg+xml", b"x"),
                                          "/d.dat": (200, "application/octet-stream", b"x")}, page)))
    assert r["images"].status == "pass" and r["images"].evidence == "3 images, all WebP, AVIF or SVG" and "animations" not in r


def test_content_type_wins_and_the_extension_is_the_fallback():
    assert pa.kind_of("/x.png", {"content-type": "image/webp"}) == "image/webp" and pa.kind_of("/x.PNG?v=2", {}) == "image/png"
    assert pa.kind_of("/x.png", {"content-type": "application/octet-stream"}) == "image/png" and pa.kind_of("/noext", {"content-type": "text/plain"}) == "text/plain"
    assert pa.kind_of("/dir.v2/noext", {}) == "unknown"


def test_gif_frame_counting_and_the_unknown_case():
    assert pa.is_animated("image/gif", GIF(1)) is False and pa.is_animated("image/gif", GIF(2)) is True
    assert pa.is_animated("image/gif", GIF(1, pad=200_000)) is None            # a big single frame in the first 200 KB: cannot tell
    assert pa.is_animated("image/png", STATIC_PNG) is False and pa.is_animated("image/png", APNG) is True and pa.is_animated("image/jpeg", b"x") is False
    assert pa.is_animated("image/png", b"\x89PNG....acTL....") is True


def test_failures_are_said_never_hidden():
    r = ids(pa.check("example.test", site({"/a.png": (404, "", b"")}, b'<img src="/a.png"><img src="/b.webp">')))
    assert r["images"].status == "unknown" and "could not be read: /a.png (HTTP 404), /b.webp (HTTP 404)" in r["images"].evidence
    def down(host, scheme, path, method="GET"):
        raise OSError("refused")
    assert pa.check("example.test", down)[0].status == "unknown" and "cannot fetch the page: refused" in pa.check("example.test", down)[0].evidence
    def error_on_asset(host, scheme, path, method="GET"):
        if path == "/":
            return 200, {"content-type": "text/html"}, None, b'<img src="/a.png">'
        raise OSError("reset")
    assert ids(pa.check("example.test", error_on_asset))["images"].evidence == "no same-host images on the front page; could not be read: /a.png (reset)"


def test_limit_and_non_html_pages():
    page = "".join(f'<img src="/i{n}.png">' for n in range(5)).encode()
    g = site({f"/i{n}.png": (200, "image/png", STATIC_PNG) for n in range(5)}, page)
    r = ids(pa.check("example.test", g, max_assets=2))
    assert "2 not WebP" in r["images"].evidence and "3 more not looked at (limit 2)" in r["images"].evidence and len(g.calls) == 3
    assert pa.check("example.test", lambda *a: (200, {"content-type": "application/json"}, None, b"{}")) == []


def test_more_than_six_are_counted_not_listed():
    page = "".join(f'<img src="/i{n}.png">' for n in range(8)).encode()
    r = ids(pa.check("example.test", site({f"/i{n}.png": (200, "image/png", STATIC_PNG) for n in range(8)}, page)))
    assert "8 not WebP" in r["images"].evidence and "(+2 more)" in r["images"].evidence and "/i6.png" not in r["images"].evidence


def test_endpoints_area_runs_it_unless_switched_off(monkeypatch):
    from judged.areas import endpoints
    from judged import web
    monkeypatch.setattr(web, "site", lambda h: [])
    monkeypatch.setattr(web, "dnssec", lambda h: pa.Result("d", "d", "pass", "", {}))
    seen = []
    monkeypatch.setattr(pa, "check", lambda h, g: seen.append(h) or [])
    endpoints.run({"item": [{"kind": "site", "host": "a.test"}, {"kind": "site", "host": "b.test", "images": False}]}, None)
    assert seen == ["a.test"]


def test_data_uris_in_styles_are_not_fetched():
    assert pa.asset_urls('<div style="background:url(data:image/png;base64,AAA)"></div><i style="x:url(/ok.png)">', "example.test") == (["/ok.png"], 0)


def test_gif_size_boundary_for_the_cannot_tell_case():
    assert pa.is_animated("image/gif", GIF(1, pad=5000)) is False
    assert pa.is_animated("image/gif", GIF(1, pad=200_000 - 24 - 1)) is False and pa.is_animated("image/gif", GIF(1, pad=200_000 - 24)) is None


def test_png_with_actl_after_the_image_data_is_not_animated():
    late = b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\x04IDAT" + b"\x00" * 8 + b"\x00\x00\x00\x08acTL"
    assert pa.is_animated("image/png", late) is False


def test_a_big_single_frame_gif_is_reported_as_maybe_animated():
    r = ids(pa.check("example.test", site({"/g.gif": (200, "image/gif", GIF(1, pad=200_000))}, b'<img src="/g.gif">')))
    assert "/g.gif (GIF, maybe, " in r["animations"].evidence


def test_a_small_single_frame_gif_is_only_an_old_format_not_an_animation():
    r = ids(pa.check("example.test", site({"/g.gif": (200, "image/gif", GIF(1))}, b'<img src="/g.gif">')))
    assert r["images"].status == "warn" and "animations" not in r


def test_exact_limit_and_exact_list_length_and_exact_kb_boundary():
    page = "".join(f'<img src="/i{n}.png">' for n in range(6)).encode()
    files = {f"/i{n}.png": (200, "image/png", STATIC_PNG) for n in range(6)}
    r = ids(pa.check("example.test", site(files, page), max_assets=6))
    assert "6 not WebP" in r["images"].evidence and "more" not in r["images"].evidence and "/i5.png" in r["images"].evidence
    page7 = "".join(f'<img src="/i{n}.png">' for n in range(7)).encode()
    r = ids(pa.check("example.test", site({f"/i{n}.png": (200, "image/png", STATIC_PNG) for n in range(7)}, page7)))
    assert "/i5.png" in r["images"].evidence and "/i6.png" not in r["images"].evidence and "(+1 more)" in r["images"].evidence
    assert pa._kb(1023) == "1023 B" and pa._kb(1024) == "1 KB"


def test_the_size_comes_from_content_length_when_the_body_was_cut():
    def get(host, scheme, path, method="GET"):
        if path == "/":
            return 200, {"content-type": "text/html"}, None, b'<img src="/big.jpg">'
        return 200, {"content-type": "image/jpeg", "content-length": "3145728"}, None, b"\xff\xd8"
    assert "/big.jpg (JPEG, 3072 KB)" in ids(pa.check("example.test", get))["images"].evidence
