from __future__ import annotations

from functools import lru_cache
from pathlib import Path


ASSET_DIR = Path(__file__).resolve().parent / "demo"


def _read_asset(filename: str) -> str:
    return (ASSET_DIR / filename).read_text(encoding="utf-8")


def _render_page(template_name: str, css_name: str, js_name: str) -> str:
    template = _read_asset(template_name)
    return (
        template
        .replace("__PAGE_CSS__", _read_asset(css_name))
        .replace("__PAGE_JS__", _read_asset(js_name))
    )


@lru_cache(maxsize=1)
def render_dashboard_html() -> str:
    return _render_page("dashboard.html", "dashboard.css", "dashboard.js")


@lru_cache(maxsize=1)
def render_present_html() -> str:
    return _render_page("present.html", "present.css", "present.js")
