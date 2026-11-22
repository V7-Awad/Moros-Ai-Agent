# JS Discover — Reference Output Examples

Concrete examples of what complete, successful `js-discover` output looks like.

---

## Example: Full collection from a React SPA

### Directory Structure (complete run)
```
targets/app.example.com/output/js/
├── raw/
│   ├── external/
│   │   ├── main.a1b2c3d4.js         (342,891 bytes)
│   │   ├── vendor.e5f6g7h8.js       (1,245,012 bytes)
│   │   ├── runtime-main.i9j0k1.js   (8,234 bytes)
│   │   ├── 2.chunk.l2m3n4.js        (45,678 bytes)
│   │   ├── 3.chunk.o5p6q7.js        (123,456 bytes)
│   │   └── polyfills.r8s9t0.js      (67,890 bytes)
│   ├── inline/
│   │   ├── _index_block_0.js         (2,345 bytes)  — window.__CONFIG__
│   │   ├── _index_block_1.js         (890 bytes)    — analytics init
│   │   ├── _login_block_0.js         (1,234 bytes)  — CAPTCHA config
│   │   └── _dashboard_block_0.js     (3,456 bytes)  — feature flags
│   ├── lazy-loaded/
│   │   ├── settings.chunk.js        (89,012 bytes)  — loaded on /settings nav
│   │   └── admin.chunk.js           (234,567 bytes) — loaded after admin role check
│   └── historical/
│       ├── 20230115_main.js          (298,765 bytes) — contained /api/v1 routes
│       ├── 20230601_vendor.js        (1,100,234 bytes)
│       └── 20231001_main.js          (315,432 bytes) — contained debug endpoints
├── beautified/
│   ├── external/
│   │   ├── main.a1b2c3d4.js         (512,345 bytes)
│   │   └── ... (same files, beautified)
│   ├── inline/
│   │   └── ... (same files, beautified)
│   ├── lazy-loaded/
│   │   └── ... (same files, beautified)
│   └── historical/
│       └── ... (same files, beautified)
├── source-maps/
│   └── external/
│       └── main.a1b2c3d4.js.map     (1,823,456 bytes)
├── collection-manifest.json
└── collection-stats.json
```

### collection-manifest.json (excerpt)
```json
{
  "target": "app.example.com",
  "collection_time": "2024-01-15T10:30:00Z",
  "files": [
    {
      "source_url": "https://app.example.com/static/js/main.a1b2c3d4.js",
      "local_path": "raw/external/main.a1b2c3d4.js",
      "size_bytes": 342891,
      "sha256": "a1b2c3d4e5f6...",
      "collection_method": "browser-crawl",
      "timestamp": "2024-01-15T10:30:12Z",
      "content_type": "application/javascript"
    },
    {
      "source_url": "https://app.example.com/ (inline block #0)",
      "local_path": "raw/inline/_index_block_0.js",
      "size_bytes": 2345,
      "sha256": "b2c3d4e5f6g7...",
      "collection_method": "inline-extraction",
      "timestamp": "2024-01-15T10:30:14Z",
      "content_type": "text/javascript"
    },
    {
      "source_url": "https://web.archive.org/web/20230115/https://app.example.com/static/js/main.js",
      "local_path": "raw/historical/20230115_main.js",
      "size_bytes": 298765,
      "sha256": "c3d4e5f6g7h8...",
      "collection_method": "wayback-machine",
      "timestamp": "2024-01-15T10:35:22Z",
      "original_archive_date": "2023-01-15"
    }
  ]
}
```

### collection-stats.json
```json
{
  "target": "app.example.com",
  "collection_time": "2024-01-15T10:30:00Z",
  "totals": {
    "files_collected": 16,
    "total_bytes": 4823456,
    "external_js_files": 6,
    "inline_script_blocks": 4,
    "lazy_loaded_files": 2,
    "historical_versions": 3,
    "source_maps_found": 1
  },
  "unique_domains_serving_js": [
    "app.example.com",
    "cdn.example.com",
    "www.googletagmanager.com"
  ],
  "pages_crawled": 23,
  "interactive_elements_clicked": 47,
  "wayback_snapshots_checked": 89
}
```

---

## Common Failure Modes (what to watch for)

1. **Empty `inline/` directory**: Model used `fetch` instead of browser-driving and missed all inline scripts.
2. **Missing `lazy-loaded/`**: Model didn't click interactive elements or navigate to auth-gated routes.
3. **Empty `historical/`**: Wayback query failed silently or returned 0 results but log says "success".
4. **Missing source maps**: Model only checked `<file>.js.map` and skipped common directory patterns.
5. **Generic user-agent blocked**: Output has suspiciously few files because anti-bot protection silently returned empty responses.
