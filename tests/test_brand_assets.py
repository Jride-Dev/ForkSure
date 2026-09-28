from __future__ import annotations

import struct
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _png_dimensions(path: Path) -> tuple[int, int]:
    data = path.read_bytes()[:24]
    assert data[:8] == b"\x89PNG\r\n\x1a\n"
    return struct.unpack(">II", data[16:24])


def test_social_preview_and_icons_have_expected_dimensions() -> None:
    assets = ROOT / "site" / "assets"

    assert _png_dimensions(assets / "forksure-social-preview.png") == (1200, 630)
    for size in (32, 180, 512):
        assert _png_dimensions(assets / f"forksure-icon-{size}.png") == (size, size)


def test_product_screenshot_set_exists() -> None:
    screenshots = ROOT / "docs" / "assets" / "screenshots"
    expected = {
        "forksure-review-console.png",
        "forksure-comparison-results.png",
        "forksure-close-matches.png",
        "forksure-mobile.png",
    }

    assert expected == {path.name for path in screenshots.glob("*.png")}
    assert all(_png_dimensions(screenshots / name)[0] >= 780 for name in expected)


def test_public_pages_reference_brand_metadata() -> None:
    for relative_path in ("site/index.html", "forksure/web/index.html"):
        html = (ROOT / relative_path).read_text(encoding="utf-8")
        assert "Trace the source. Compare the evidence." in html
        assert "forksure-social-preview.png" in html
        assert "forksure-icon-180.png" in html
