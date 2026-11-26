#!/usr/bin/env python3
"""
sourcemap-hunter.py — Source map discovery tool.

For every collected .js file, checks for corresponding .map files
using multiple discovery methods: appending .map, common directories,
sourceMappingURL comments, and known framework patterns.

Usage:
    python tools/sourcemap-hunter.py \
        --js-dir "targets/example.com/output/js/raw/" \
        --output-dir "targets/example.com/output/js/source-maps/" \
        --check-common-paths \
        --check-mobile-bundles
"""

import argparse
import hashlib
import json
import logging
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlparse
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S"
)
logger = logging.getLogger("sourcemap-hunter")

REQUEST_DELAY_SECONDS = 0.5

# Common source map directory patterns
COMMON_MAP_PATHS = [
    "{base}.map",
    "{base}.js.map",
    "/sourcemaps/{filename}.map",
    "/__source/{filename}.map",
    "/maps/{filename}.map",
    "/source-maps/{filename}.map",
    "/.map/{filename}.map",
]

# sourceMappingURL pattern in JS content
SOURCEMAP_URL_PATTERN = re.compile(
    r'//[#@]\s*sourceMappingURL\s*=\s*(\S+)',
    re.MULTILINE
)


class SourceMapHunter:
    def __init__(self, js_dir: str, output_dir: str, base_url: str = None,
                 check_common_paths: bool = True, check_mobile: bool = False,
                 timeout: int = 15):
        self.js_dir = Path(js_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.base_url = base_url
        self.check_common = check_common_paths
        self.check_mobile = check_mobile
        self.timeout = timeout

        self.found_maps: list = []
        self.checked_urls: set = set()
        self.errors: list = []

    def run(self):
        """Main execution."""
        logger.info(f"Hunting source maps in {self.js_dir}")

        js_files = list(self.js_dir.rglob("*.js"))
        logger.info(f"Found {len(js_files)} JS files to check")

        for js_file in js_files:
            self._check_file(js_file)

        self._write_summary()
        logger.info(f"Source map hunt complete. Found {len(self.found_maps)} maps.")

    def _check_file(self, js_file: Path):
        """Check a single JS file for source maps."""
        logger.debug(f"Checking: {js_file}")

        try:
            content = js_file.read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            self.errors.append({"file": str(js_file), "error": str(e)})
            return

        # Method 1: Check for sourceMappingURL comment in the JS file
        matches = SOURCEMAP_URL_PATTERN.findall(content)
        for map_url in matches:
            logger.info(f"Found sourceMappingURL in {js_file.name}: {map_url}")

            # If it's a data: URI, extract inline source map
            if map_url.startswith("data:"):
                self._extract_inline_map(js_file, map_url)
                continue

            # If it's a relative URL, try to resolve and fetch
            if self.base_url and not map_url.startswith(("http://", "https://")):
                full_url = urljoin(self.base_url, map_url)
                self._try_fetch_map(full_url, js_file, "sourceMappingURL")
            else:
                # Check if file exists locally
                local_path = js_file.parent / map_url
                if local_path.exists():
                    self._save_local_map(local_path, js_file, "sourceMappingURL-local")

        # Method 2: Try common .map file locations (remote)
        if self.base_url and self.check_common:
            for pattern in COMMON_MAP_PATHS:
                filename = js_file.stem
                base = js_file.stem
                map_path = pattern.format(base=base, filename=filename)

                # Construct full URL
                parsed_base = urlparse(self.base_url)
                full_url = f"{parsed_base.scheme}://{parsed_base.netloc}/{map_path.lstrip('/')}"

                if full_url not in self.checked_urls:
                    self._try_fetch_map(full_url, js_file, f"common-path:{pattern}")

        # Method 3: Check for local .map file next to the JS file
        local_map = js_file.with_suffix(".js.map")
        if local_map.exists():
            self._save_local_map(local_map, js_file, "adjacent-file")

        local_map2 = js_file.with_suffix(".map")
        if local_map2.exists():
            self._save_local_map(local_map2, js_file, "adjacent-file")

    def _try_fetch_map(self, url: str, source_js: Path, method: str):
        """Try to fetch a source map from a URL."""
        if url in self.checked_urls:
            return
        self.checked_urls.add(url)

        try:
            req = Request(url, headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
                "Accept": "application/json,*/*",
            })
            with urlopen(req, timeout=self.timeout) as response:
                content = response.read()

                # Validate it looks like a source map
                if self._is_valid_sourcemap(content):
                    filename = f"{source_js.stem}.js.map"
                    filepath = self.output_dir / filename
                    filepath.write_bytes(content)

                    self.found_maps.append({
                        "source_js": str(source_js),
                        "map_url": url,
                        "local_path": str(filepath),
                        "size": len(content),
                        "sha256": hashlib.sha256(content).hexdigest(),
                        "discovery_method": method,
                    })
                    logger.info(f"FOUND source map: {url} ({len(content)} bytes)")

            time.sleep(REQUEST_DELAY_SECONDS)

        except (URLError, HTTPError):
            pass  # Expected — most URLs won't have maps
        except Exception as e:
            self.errors.append({"url": url, "error": str(e)})

    def _save_local_map(self, map_path: Path, source_js: Path, method: str):
        """Save a locally-found source map."""
        try:
            content = map_path.read_bytes()
            if self._is_valid_sourcemap(content):
                dest = self.output_dir / map_path.name
                dest.write_bytes(content)

                self.found_maps.append({
                    "source_js": str(source_js),
                    "map_path": str(map_path),
                    "local_path": str(dest),
                    "size": len(content),
                    "sha256": hashlib.sha256(content).hexdigest(),
                    "discovery_method": method,
                })
                logger.info(f"FOUND local source map: {map_path}")
        except Exception as e:
            self.errors.append({"file": str(map_path), "error": str(e)})

    def _extract_inline_map(self, source_js: Path, data_uri: str):
        """Extract an inline base64-encoded source map from a data: URI."""
        import base64
        try:
            # data:application/json;charset=utf-8;base64,XXXX
            if ";base64," in data_uri:
                encoded = data_uri.split(";base64,", 1)[1]
                content = base64.b64decode(encoded)

                if self._is_valid_sourcemap(content):
                    filename = f"{source_js.stem}_inline.js.map"
                    filepath = self.output_dir / filename
                    filepath.write_bytes(content)

                    self.found_maps.append({
                        "source_js": str(source_js),
                        "local_path": str(filepath),
                        "size": len(content),
                        "sha256": hashlib.sha256(content).hexdigest(),
                        "discovery_method": "inline-data-uri",
                    })
                    logger.info(f"Extracted inline source map from {source_js.name}")
        except Exception as e:
            self.errors.append({"file": str(source_js), "error": str(e), "phase": "inline-extract"})

    def _is_valid_sourcemap(self, content: bytes) -> bool:
        """Check if content looks like a valid source map."""
        try:
            text = content.decode("utf-8", errors="ignore")
            # Must contain "mappings" or "sources" keys
            if '"mappings"' in text or '"sources"' in text:
                data = json.loads(text)
                return "mappings" in data or "sources" in data
        except (json.JSONDecodeError, ValueError):
            pass
        return False

    def _write_summary(self):
        """Write hunt summary."""
        summary = {
            "js_directory": str(self.js_dir),
            "hunt_time": datetime.now(timezone.utc).isoformat(),
            "js_files_checked": len(list(self.js_dir.rglob("*.js"))),
            "urls_checked": len(self.checked_urls),
            "source_maps_found": len(self.found_maps),
            "errors": len(self.errors),
            "maps": self.found_maps,
        }

        summary_path = self.output_dir / "sourcemap-hunt-summary.json"
        summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

        if self.errors:
            errors_path = self.output_dir / "sourcemap-errors.json"
            errors_path.write_text(json.dumps(self.errors, indent=2), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description="Hunt for JavaScript source maps")
    parser.add_argument("--js-dir", required=True, help="Directory containing JS files")
    parser.add_argument("--output-dir", required=True, help="Output directory for source maps")
    parser.add_argument("--base-url", default=None, help="Base URL for remote source map checks")
    parser.add_argument("--check-common-paths", action="store_true", default=True,
                        help="Check common source map directory patterns")
    parser.add_argument("--check-mobile-bundles", action="store_true", default=False,
                        help="Check associated mobile app bundles")
    parser.add_argument("--timeout", type=int, default=15,
                        help="HTTP timeout in seconds")

    args = parser.parse_args()

    hunter = SourceMapHunter(
        js_dir=args.js_dir,
        output_dir=args.output_dir,
        base_url=args.base_url,
        check_common_paths=args.check_common_paths,
        check_mobile=args.check_mobile_bundles,
        timeout=args.timeout,
    )

    hunter.run()


if __name__ == "__main__":
    main()
