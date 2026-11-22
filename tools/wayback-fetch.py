#!/usr/bin/env python3
"""
wayback-fetch.py — Historical JavaScript fetcher via Wayback Machine CDX API.

Queries the Wayback Machine (and optionally other web archive APIs) for historical
versions of JavaScript files and HTML pages containing inline JS.

Usage:
    python tools/wayback-fetch.py --domain "example.com" \
        --filter "mimetype:application/javascript" \
        --output-dir "targets/example.com/output/js/raw/historical/" \
        --collapse "digest" \
        --limit 500
"""

import argparse
import hashlib
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlencode
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S"
)
logger = logging.getLogger("wayback-fetch")

CDX_API_URL = "https://web.archive.org/cdx/search/cdx"
WAYBACK_RAW_URL = "https://web.archive.org/web/{timestamp}id_/{url}"

# Rate limit: be respectful to the Wayback Machine
REQUEST_DELAY_SECONDS = 1.5


class WaybackFetcher:
    def __init__(self, domain: str, output_dir: str, mime_filter: str = None,
                 collapse: str = "digest", limit: int = 500, timeout: int = 30):
        self.domain = domain
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.mime_filter = mime_filter
        self.collapse = collapse
        self.limit = limit
        self.timeout = timeout

        self.fetched_files: list = []
        self.errors: list = []
        self.seen_hashes: set = set()  # deduplicate by content

    def query_cdx(self) -> list:
        """Query the CDX API for archived resources."""
        params = {
            "url": f"*.{self.domain}/*",
            "output": "json",
            "limit": str(self.limit),
            "fl": "timestamp,original,mimetype,statuscode,digest,length",
        }

        if self.mime_filter:
            params["filter"] = self.mime_filter

        if self.collapse:
            params["collapse"] = self.collapse

        query_url = f"{CDX_API_URL}?{urlencode(params)}"
        logger.info(f"Querying CDX API: {query_url}")

        try:
            req = Request(query_url, headers={
                "User-Agent": "Hackbot-WaybackFetcher/1.0 (authorized security research)"
            })
            with urlopen(req, timeout=self.timeout) as response:
                data = json.loads(response.read().decode("utf-8"))

            if not data or len(data) < 2:
                logger.info("No results from CDX API")
                return []

            # First row is headers
            headers = data[0]
            results = []
            for row in data[1:]:
                record = dict(zip(headers, row))
                results.append(record)

            logger.info(f"CDX API returned {len(results)} results")
            return results

        except (URLError, HTTPError) as e:
            logger.error(f"CDX API query failed: {e}")
            self.errors.append({"phase": "cdx-query", "error": str(e)})
            return []

    def fetch_archived_file(self, timestamp: str, original_url: str) -> bytes | None:
        """Fetch a specific archived file from the Wayback Machine."""
        fetch_url = WAYBACK_RAW_URL.format(timestamp=timestamp, url=original_url)

        try:
            req = Request(fetch_url, headers={
                "User-Agent": "Hackbot-WaybackFetcher/1.0 (authorized security research)"
            })
            with urlopen(req, timeout=self.timeout) as response:
                return response.read()
        except (URLError, HTTPError) as e:
            self.errors.append({
                "phase": "fetch",
                "url": original_url,
                "timestamp": timestamp,
                "error": str(e)
            })
            return None

    def run(self):
        """Main execution flow."""
        logger.info(f"Starting Wayback Machine fetch for {self.domain}")

        # Step 1: Query CDX
        records = self.query_cdx()
        if not records:
            self._write_summary()
            return

        # Step 2: Fetch each unique file
        for i, record in enumerate(records):
            timestamp = record.get("timestamp", "")
            original_url = record.get("original", "")
            digest = record.get("digest", "")
            status = record.get("statuscode", "")

            # Skip non-200 responses
            if status != "200":
                continue

            # Skip already-seen content (by digest)
            if digest in self.seen_hashes:
                logger.debug(f"Skipping duplicate: {original_url} ({timestamp})")
                continue
            self.seen_hashes.add(digest)

            logger.info(f"[{i+1}/{len(records)}] Fetching: {original_url} ({timestamp})")

            content = self.fetch_archived_file(timestamp, original_url)
            if content:
                # Save to disk
                filename = self._make_filename(original_url, timestamp)
                filepath = self.output_dir / filename
                filepath.write_bytes(content)

                content_hash = hashlib.sha256(content).hexdigest()
                self.fetched_files.append({
                    "original_url": original_url,
                    "timestamp": timestamp,
                    "path": str(filepath),
                    "size": len(content),
                    "sha256": content_hash,
                    "wayback_digest": digest,
                })

                logger.info(f"  Saved: {filepath} ({len(content)} bytes)")

            # Rate limiting
            time.sleep(REQUEST_DELAY_SECONDS)

        self._write_summary()

    def _make_filename(self, url: str, timestamp: str) -> str:
        """Generate a unique filename from URL and timestamp."""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        path = parsed.path.strip("/").replace("/", "_") or "index"
        if not path.endswith(".js"):
            path += ".js"
        # Prepend timestamp for uniqueness
        safe_name = f"{timestamp}_{path}"
        if len(safe_name) > 200:
            safe_name = safe_name[:180] + "_" + hashlib.md5(url.encode()).hexdigest()[:8] + ".js"
        return safe_name

    def _write_summary(self):
        """Write fetch summary."""
        summary = {
            "domain": self.domain,
            "fetch_time": datetime.now(timezone.utc).isoformat(),
            "total_cdx_results": len(self.seen_hashes),
            "files_fetched": len(self.fetched_files),
            "errors": len(self.errors),
            "files": self.fetched_files,
        }

        summary_path = self.output_dir / "wayback-fetch-summary.json"
        summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        logger.info(f"Summary written to {summary_path}")

        if self.errors:
            errors_path = self.output_dir / "wayback-errors.json"
            errors_path.write_text(json.dumps(self.errors, indent=2), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(
        description="Fetch historical JavaScript from the Wayback Machine"
    )
    parser.add_argument("--domain", required=True, help="Target domain")
    parser.add_argument("--output-dir", required=True, help="Output directory")
    parser.add_argument("--filter", default="mimetype:application/javascript",
                        help="CDX API filter (default: mimetype:application/javascript)")
    parser.add_argument("--collapse", default="digest",
                        help="CDX collapse parameter (default: digest)")
    parser.add_argument("--limit", type=int, default=500,
                        help="Max results from CDX API (default: 500)")
    parser.add_argument("--timeout", type=int, default=30,
                        help="HTTP timeout in seconds (default: 30)")

    args = parser.parse_args()

    fetcher = WaybackFetcher(
        domain=args.domain,
        output_dir=args.output_dir,
        mime_filter=args.filter,
        collapse=args.collapse,
        limit=args.limit,
        timeout=args.timeout,
    )

    fetcher.run()


if __name__ == "__main__":
    main()
