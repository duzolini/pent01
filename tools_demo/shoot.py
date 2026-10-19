import sys
from pathlib import Path
from playwright.sync_api import sync_playwright

CHROME = "/opt/pw-browsers/chromium-1194/chrome-linux/chrome"
OUT = Path("/tmp/claude-0/-home-user/f81c5cf9-0e8c-506e-968b-c18fbab9130f/scratchpad")
OUT.mkdir(parents=True, exist_ok=True)
scan_id = sys.argv[1]
report_file = sys.argv[2]

shots = [
    ("http://127.0.0.1:8000/", "shot_dashboard.png", 1120),
    (f"http://127.0.0.1:8000/scan/{scan_id}", "shot_scan.png", 1120),
    (f"file://{report_file}", "shot_report.png", 1000),
]

with sync_playwright() as p:
    browser = p.chromium.launch(executable_path=CHROME,
                                args=["--no-sandbox", "--disable-dev-shm-usage"])
    for url, name, width in shots:
        page = browser.new_page(viewport={"width": width, "height": 900},
                                device_scale_factor=2,
                                color_scheme="light")
        page.goto(url, wait_until="networkidle", timeout=30000)
        page.wait_for_timeout(400)
        page.screenshot(path=str(OUT / name), full_page=True)
        print(f"wrote {OUT / name}")
    browser.close()
