#!/usr/bin/env python3
"""
browser-crawl.py — Browser-driven site crawler for JS and traffic collection.

Uses Playwright to drive a real browser, capturing all network traffic,
clicking interactive elements, and collecting JavaScript files.
Avoids detection by anti-bot systems through real browser behavior.

Usage:
    python tools/browser-crawl.py --target "https://example.com" \
        --output-dir "targets/example.com/output/js/raw/" \
        --capture-traffic \
        --click-all-interactive \
        --follow-all-links \
        --max-depth 10
"""

import argparse
import asyncio
import hashlib
import json
import logging
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlparse

try:
    from playwright.async_api import async_playwright
except ImportError:
    print("ERROR: playwright not installed. Run: pip install playwright && playwright install chromium")
    sys.exit(1)

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S"
)
logger = logging.getLogger("browser-crawl")


class BrowserCrawler:
    def __init__(self, target: str, output_dir: str, max_depth: int = 10,
                 user_agent: str = None, capture_traffic: bool = True,
                 click_interactive: bool = True, follow_links: bool = True,
                 timeout_ms: int = 30000):
        self.target = target
        self.target_domain = urlparse(target).netloc
        self.output_dir = Path(output_dir)
        self.max_depth = max_depth
        self.user_agent = user_agent or (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        )
        self.capture_traffic = capture_traffic
        self.click_interactive = click_interactive
        self.follow_links = follow_links
        self.timeout_ms = timeout_ms

        self.visited_urls: set = set()
        self.discovered_js: dict = {}     # url -> {path, size, hash, source}
        self.inline_scripts: list = []
        self.traffic_log: list = []
        self.errors: list = []

        # Create output directories
        for subdir in ["external", "inline", "lazy-loaded"]:
            (self.output_dir / subdir).mkdir(parents=True, exist_ok=True)

    async def crawl(self):
        """Main crawl entry point."""
        logger.info(f"Starting browser crawl of {self.target}")
        logger.info(f"Output directory: {self.output_dir}")
        logger.info(f"Max depth: {self.max_depth}")

        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=[
                    "--disable-blink-features=AutomationControlled",
                    "--no-sandbox",
                ]
            )

            context = await browser.new_context(
                user_agent=self.user_agent,
                viewport={"width": 1920, "height": 1080},
                java_script_enabled=True,
                ignore_https_errors=True,
            )

            # Set up traffic capture
            if self.capture_traffic:
                await context.route("**/*", self._handle_route)

            page = await context.new_page()

            # Set up response listener for JS collection
            page.on("response", lambda response: asyncio.ensure_future(
                self._on_response(response)
            ))

            # Start crawling
            await self._crawl_page(page, self.target, depth=0)

            await browser.close()

        # Write collection summary
        self._write_summary()
        logger.info(f"Crawl complete. Collected {len(self.discovered_js)} JS files, "
                     f"{len(self.inline_scripts)} inline scripts")

    async def _handle_route(self, route):
        """Intercept and log all network traffic."""
        request = route.request
        self.traffic_log.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "method": request.method,
            "url": request.url,
            "resource_type": request.resource_type,
            "headers": dict(request.headers),
        })
        await route.continue_()

    async def _on_response(self, response):
        """Capture JavaScript responses."""
        try:
            url = response.url
            content_type = response.headers.get("content-type", "")

            if ("javascript" in content_type or
                url.endswith(".js") or
                "application/x-javascript" in content_type):

                body = await response.body()
                if body:
                    file_hash = hashlib.sha256(body).hexdigest()
                    filename = self._url_to_filename(url)
                    filepath = self.output_dir / "external" / filename

                    filepath.write_bytes(body)

                    self.discovered_js[url] = {
                        "path": str(filepath),
                        "size": len(body),
                        "hash": file_hash,
                        "source": "external",
                        "url": url,
                        "status": response.status,
                        "content_type": content_type,
                    }
                    logger.info(f"Captured JS: {url} ({len(body)} bytes)")

        except Exception as e:
            self.errors.append({"url": response.url, "error": str(e)})

    async def _crawl_page(self, page, url: str, depth: int):
        """Crawl a single page and extract scripts."""
        if depth > self.max_depth:
            return
        if url in self.visited_urls:
            return

        # Only crawl same-domain URLs
        parsed = urlparse(url)
        if parsed.netloc and parsed.netloc != self.target_domain:
            return

        self.visited_urls.add(url)
        logger.info(f"Crawling [{depth}]: {url}")

        try:
            response = await page.goto(url, wait_until="networkidle",
                                        timeout=self.timeout_ms)
            if not response:
                return

            # Wait for dynamic content
            await page.wait_for_timeout(2000)

            # Extract inline scripts
            await self._extract_inline_scripts(page, url)

            # Click interactive elements to trigger lazy-loaded JS
            if self.click_interactive:
                await self._click_interactive_elements(page)

            # Follow links
            if self.follow_links and depth < self.max_depth:
                links = await self._extract_links(page)
                for link in links:
                    absolute_url = urljoin(url, link)
                    if absolute_url not in self.visited_urls:
                        try:
                            await self._crawl_page(page, absolute_url, depth + 1)
                        except Exception as e:
                            self.errors.append({
                                "url": absolute_url,
                                "error": str(e),
                                "phase": "link-follow"
                            })

        except Exception as e:
            self.errors.append({"url": url, "error": str(e), "phase": "page-load"})
            logger.warning(f"Error crawling {url}: {e}")

    async def _extract_inline_scripts(self, page, page_url: str):
        """Extract all inline <script> blocks from the page."""
        try:
            scripts = await page.evaluate("""
                () => {
                    const scripts = [];
                    document.querySelectorAll('script:not([src])').forEach((s, i) => {
                        if (s.textContent.trim()) {
                            scripts.push({
                                index: i,
                                content: s.textContent,
                                type: s.type || 'text/javascript',
                            });
                        }
                    });
                    return scripts;
                }
            """)

            for script in scripts:
                content = script["content"]
                block_index = script["index"]
                safe_url = re.sub(r'[^\w\-.]', '_', urlparse(page_url).path or "index")
                filename = f"{safe_url}_block_{block_index}.js"
                filepath = self.output_dir / "inline" / filename

                filepath.write_text(content, encoding="utf-8")

                self.inline_scripts.append({
                    "page_url": page_url,
                    "block_index": block_index,
                    "path": str(filepath),
                    "size": len(content),
                    "hash": hashlib.sha256(content.encode()).hexdigest(),
                    "type": script["type"],
                })
                logger.info(f"Extracted inline script from {page_url} block #{block_index} "
                           f"({len(content)} bytes)")

        except Exception as e:
            self.errors.append({
                "url": page_url,
                "error": str(e),
                "phase": "inline-extraction"
            })

    async def _click_interactive_elements(self, page):
        """Click buttons, tabs, dropdowns, etc. to trigger lazy-loaded JS."""
        try:
            # Count JS files before clicking
            js_before = len(self.discovered_js)

            selectors = [
                "button:visible",
                "[role='tab']:visible",
                "[role='button']:visible",
                ".dropdown-toggle:visible",
                "[data-toggle]:visible",
                "a[href='#']:visible",
                "a[href='javascript:void(0)']:visible",
                "details > summary:visible",
            ]

            for selector in selectors:
                try:
                    elements = await page.query_selector_all(selector)
                    for el in elements[:10]:  # Limit to 10 per selector
                        try:
                            await el.click(timeout=3000)
                            await page.wait_for_timeout(1000)
                        except Exception:
                            pass  # Element may not be clickable
                except Exception:
                    pass

            js_after = len(self.discovered_js)
            if js_after > js_before:
                lazy_count = js_after - js_before
                logger.info(f"Discovered {lazy_count} lazy-loaded JS files via interaction")

        except Exception as e:
            self.errors.append({"error": str(e), "phase": "click-interactive"})

    async def _extract_links(self, page) -> list:
        """Extract all links from the current page."""
        try:
            links = await page.evaluate("""
                () => {
                    const links = new Set();
                    document.querySelectorAll('a[href]').forEach(a => {
                        const href = a.getAttribute('href');
                        if (href && !href.startsWith('#') && !href.startsWith('mailto:') 
                            && !href.startsWith('tel:') && !href.startsWith('javascript:')) {
                            links.add(href);
                        }
                    });
                    return Array.from(links);
                }
            """)
            return links
        except Exception:
            return []

    def _url_to_filename(self, url: str) -> str:
        """Convert a URL to a safe filename."""
        parsed = urlparse(url)
        path = parsed.path.strip("/").replace("/", "_") or "index"
        if not path.endswith(".js"):
            path += ".js"
        # Truncate overly long names
        if len(path) > 200:
            path = path[:180] + "_" + hashlib.md5(path.encode()).hexdigest()[:8] + ".js"
        return path

    def _write_summary(self):
        """Write crawl summary files."""
        summary = {
            "target": self.target,
            "crawl_time": datetime.now(timezone.utc).isoformat(),
            "pages_visited": len(self.visited_urls),
            "external_js_collected": len(self.discovered_js),
            "inline_scripts_collected": len(self.inline_scripts),
            "traffic_requests_logged": len(self.traffic_log),
            "errors": len(self.errors),
            "visited_urls": sorted(self.visited_urls),
        }

        (self.output_dir.parent / "crawl-summary.json").write_text(
            json.dumps(summary, indent=2), encoding="utf-8"
        )

        if self.traffic_log:
            traffic_path = self.output_dir.parent / "traffic-log.json"
            traffic_path.write_text(
                json.dumps(self.traffic_log, indent=2), encoding="utf-8"
            )

        if self.errors:
            errors_path = self.output_dir.parent / "crawl-errors.json"
            errors_path.write_text(
                json.dumps(self.errors, indent=2), encoding="utf-8"
            )


def main():
    parser = argparse.ArgumentParser(
        description="Browser-driven site crawler for JS and traffic collection"
    )
    parser.add_argument("--target", required=True, help="Target URL (e.g., https://example.com)")
    parser.add_argument("--output-dir", required=True, help="Output directory for collected JS")
    parser.add_argument("--capture-traffic", action="store_true", default=True,
                        help="Capture all network traffic")
    parser.add_argument("--click-all-interactive", action="store_true", default=True,
                        help="Click interactive elements to trigger lazy JS")
    parser.add_argument("--follow-all-links", action="store_true", default=True,
                        help="Follow all links on pages")
    parser.add_argument("--max-depth", type=int, default=10,
                        help="Maximum crawl depth (default: 10)")
    parser.add_argument("--user-agent", default=None,
                        help="Custom User-Agent string")
    parser.add_argument("--timeout", type=int, default=30000,
                        help="Page load timeout in ms (default: 30000)")

    args = parser.parse_args()

    crawler = BrowserCrawler(
        target=args.target,
        output_dir=args.output_dir,
        max_depth=args.max_depth,
        user_agent=args.user_agent,
        capture_traffic=args.capture_traffic,
        click_interactive=args.click_all_interactive,
        follow_links=args.follow_all_links,
        timeout_ms=args.timeout,
    )

    asyncio.run(crawler.crawl())


if __name__ == "__main__":
    main()
