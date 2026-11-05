"""RT-21: real browser checks. axe-core (WCAG 2.1 A/AA tags), keyboard reachability, screenshots."""
import json
from datetime import datetime
from pathlib import Path

import pyotp
from axe_playwright_python.sync_playwright import Axe
from playwright.sync_api import sync_playwright

BASE = "https://10.60.0.20:8443"
USERS = json.load(open("/lab/demo_users.json"))
OUT = Path("/results")
SHOTS = OUT / "screenshots"
SHOTS.mkdir(parents=True, exist_ok=True)
TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]
PAGES = {"dashboard": "/", "alerts": "/alerts", "commands": "/commands", "history": "/history?q=escola", "audit": "/audit", "users": "/users"}


def audit(page, name: str, report: dict) -> None:
    results = Axe().run(page, options={"runOnly": {"type": "tag", "values": TAGS}})
    report[name] = {"violations": [{"id": v["id"], "impact": v["impact"], "nodes": len(v["nodes"]), "help": v["help"]}
                                   for v in results.response["violations"]],
                    "passes": len(results.response["passes"])}
    page.screenshot(path=SHOTS / f"{name}.png", full_page=True)


with sync_playwright() as p:
    browser = p.chromium.launch(args=["--no-sandbox"])
    context = browser.new_context(ignore_https_errors=True, viewport={"width": 1280, "height": 800}, locale="pt-BR")
    page = context.new_page()
    report: dict = {}
    page.goto(f"{BASE}/login")
    audit(page, "login", report)

    # Keyboard only: the whole login must be operable with Tab and typing, starting at the skip link.
    page.keyboard.press("Tab")
    first_focus = page.evaluate("document.activeElement.className")
    order = []
    for _ in range(4):
        page.keyboard.press("Tab")
        order.append(page.evaluate("document.activeElement.id || document.activeElement.tagName"))
    keyboard = {"first_tab_reaches_skip_link": first_focus == "skip", "tab_order": order,
                "focus_outline": page.evaluate("getComputedStyle(document.activeElement).outlineStyle")}

    user = USERS["coordenacao.demo"]
    page.fill("#username", "coordenacao.demo")
    page.fill("#password", user["password"])
    page.fill("#totp", pyotp.TOTP(user["totp_secret"]).now())
    page.keyboard.press("Enter")
    page.wait_for_url(f"{BASE}/")
    for name, path in PAGES.items():
        page.goto(f"{BASE}{path}")
        audit(page, name, report)

    mobile = browser.new_context(ignore_https_errors=True, viewport={"width": 390, "height": 800}, locale="pt-BR")
    small = mobile.new_page()
    small.goto(f"{BASE}/login")
    overflow = small.evaluate("document.documentElement.scrollWidth > window.innerWidth")
    small.screenshot(path=SHOTS / "login_mobile.png")
    font = page.evaluate("parseFloat(getComputedStyle(document.body).fontSize)")
    browser.close()

total = sum(len(v["violations"]) for v in report.values())
output = {"generated_at": datetime.now().isoformat(), "tool": "axe-core via axe-playwright-python", "tags": TAGS,
          "pages": report, "total_violations": total, "keyboard": keyboard,
          "mobile_390px_horizontal_overflow": overflow, "base_font_px": font,
          "note": "Automated tools catch only part of WCAG; a manual review with volunteers is still required."}
(OUT / "accessibility_results.json").write_text(json.dumps(output, indent=2, ensure_ascii=False))
print(json.dumps(output, indent=2, ensure_ascii=False))
