---
name: js-discover
description: >
  Collects all JavaScript from a target domain: external .js files, inline script blocks,
  lazy-loaded JS (browser-driven), historical JS from web archives, and leaked source maps.
  Outputs raw and beautified JS organized by source type. This is a collection-only skill;
  analysis is handled by js-analyze.
---

# JS Discover — JavaScript Collection Skill

## Purpose

Exhaustively collect every piece of JavaScript associated with a target domain. This includes code that only appears on user interaction (click/scroll/auth), historical versions from web archives, and source maps that may reveal original source.

## Prerequisites

- `targets/<domain>/scope-of-work.pdf` must exist (authorization check)
- Browser-driving tool available (see tools/ directory)
- Network access to target domain and web archive APIs

## Inputs

- `TARGET_DOMAIN` — the target domain (e.g., `example.com`)
- `TARGET_DIR` — full path: `targets/<domain>/`

## Outputs

All output goes to `targets/<domain>/output/js/`:

```
output/js/
  raw/
    external/          # downloaded .js files from <script src="...">
    inline/            # extracted <script>...</script> blocks (one file per page per block)
    lazy-loaded/       # JS loaded after click/scroll/auth/route-change events
    historical/        # old .js versions from Wayback Machine / web archives
  beautified/
    external/
    inline/
    lazy-loaded/
    historical/
  source-maps/
    external/          # .js.map files found for external scripts
    inline/            # source maps for inline scripts (rare but possible)
  collection-manifest.json   # inventory of everything collected
  collection-stats.json      # counts and metadata
```

## Methodology Checklist

- [ ] Step 1: Verify authorization — confirm `scope-of-work.pdf` exists in target directory
  - Expected artifact: N/A (gate check)
  - Log file: `targets/<domain>/output/logs/js-discover/step-01-auth-check.log`

- [ ] Step 2: Browser-driven site crawl — drive a real browser through the target site, visiting every discoverable page and clicking every interactive element. Capture all network traffic. Do NOT use a generic HTTP client with default user-agent (will be blocked by anti-bot).
  - Expected artifact: `targets/<domain>/output/js/raw/external/` (populated with .js files)
  - Log file: `targets/<domain>/output/logs/js-discover/step-02-browser-crawl.log`

- [ ] Step 3: Extract inline scripts — from every crawled page, extract all `<script>...</script>` blocks (not just external src references). Name files by page URL and block index.
  - Expected artifact: `targets/<domain>/output/js/raw/inline/` (populated)
  - Log file: `targets/<domain>/output/logs/js-discover/step-03-inline-extraction.log`

- [ ] Step 4: Capture lazy-loaded JS — trigger click events, scroll events, route changes, and auth-gated paths in the browser to discover JS that only loads on interaction. Record any new .js requests.
  - Expected artifact: `targets/<domain>/output/js/raw/lazy-loaded/` (populated, may be empty if none found — log must explain)
  - Log file: `targets/<domain>/output/logs/js-discover/step-04-lazy-loaded.log`

- [ ] Step 5: Historical JS collection — query Wayback Machine (web.archive.org) and other web archive snapshot APIs for old versions of discovered .js files and any .js URLs found in historical snapshots of the target's HTML.
  - Expected artifact: `targets/<domain>/output/js/raw/historical/` (populated or explained)
  - Log file: `targets/<domain>/output/logs/js-discover/step-05-historical.log`

- [ ] Step 6: Source map hunting — for every collected .js file, check for `<file>.js.map`, common source-map directory paths (`/sourcemaps/`, `/__source/`), sourceMappingURL comments in JS content, and associated mobile app bundles.
  - Expected artifact: `targets/<domain>/output/js/source-maps/` (populated or explained)
  - Log file: `targets/<domain>/output/logs/js-discover/step-06-source-maps.log`

- [ ] Step 7: Beautify all collected JS — run js-beautify (or equivalent) on every raw JS file. Maintain the same subdirectory structure under `beautified/`.
  - Expected artifact: `targets/<domain>/output/js/beautified/` (populated, same structure as raw/)
  - Log file: `targets/<domain>/output/logs/js-discover/step-07-beautify.log`

- [ ] Step 8: Generate collection manifest — create `collection-manifest.json` listing every file collected with: source URL, file path, size in bytes, SHA256 hash, collection method (crawl/inline/lazy/historical/sourcemap), and timestamp.
  - Expected artifact: `targets/<domain>/output/js/collection-manifest.json`
  - Log file: `targets/<domain>/output/logs/js-discover/step-08-manifest.log`

- [ ] Step 9: Generate collection stats — create `collection-stats.json` with summary counts: total files per category, total bytes, unique domains serving JS, number of source maps found, number of historical versions found.
  - Expected artifact: `targets/<domain>/output/js/collection-stats.json`
  - Log file: `targets/<domain>/output/logs/js-discover/step-09-stats.log`

## Tool Usage

### Browser Crawling (Step 2, 3, 4)
Use the browser-driving tool from `tools/` with explicit flags:
```bash
# Example: crawl with full traffic capture
tools/browser-crawl.py --target "https://<domain>" \
  --output-dir "targets/<domain>/output/js/raw/" \
  --capture-traffic \
  --click-all-interactive \
  --follow-all-links \
  --max-depth 10 \
  --user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
```

### Wayback Machine (Step 5)
```bash
# Query CDX API for all JS URLs
tools/wayback-fetch.py --domain "<domain>" \
  --filter "mimetype:application/javascript" \
  --output-dir "targets/<domain>/output/js/raw/historical/" \
  --collapse "digest" \
  --limit 500
```

### Source Maps (Step 6)
```bash
# Check each .js file for corresponding .map
tools/sourcemap-hunter.py --js-dir "targets/<domain>/output/js/raw/" \
  --output-dir "targets/<domain>/output/js/source-maps/" \
  --check-common-paths \
  --check-mobile-bundles
```

## Important Notes

- **Anti-bot bypass**: Many real targets block generic HTTP clients. Always use a real browser with realistic user-agent and behavior patterns. The browser tool handles this.
- **Inline JS is critical**: Do NOT skip inline `<script>` blocks. These often contain page-specific configuration, API keys, and routing information that external bundles don't have.
- **Lazy-loaded JS**: Single-page apps frequently load code chunks on demand. Triggering route changes and interactions is essential for complete coverage.
- **Historical JS**: Old API endpoints discovered in archived JS may still be live but unlinked from the current UI — these are high-value targets for further testing.
