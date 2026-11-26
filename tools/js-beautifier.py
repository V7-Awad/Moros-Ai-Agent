#!/usr/bin/env python3
"""
js-beautifier.py — JavaScript beautification wrapper.

Beautifies raw JavaScript files using jsbeautifier, maintaining directory structure.
Handles minified, obfuscated, and webpack-bundled code.

Usage:
    python tools/js-beautifier.py \
        --input-dir "targets/example.com/output/js/raw/" \
        --output-dir "targets/example.com/output/js/beautified/"
"""

import argparse
import hashlib
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S"
)
logger = logging.getLogger("js-beautifier")

try:
    import jsbeautifier
    HAS_JSBEAUTIFIER = True
except ImportError:
    HAS_JSBEAUTIFIER = False
    logger.warning("jsbeautifier not installed. Install with: pip install jsbeautifier")


def beautify_js(content: str) -> str:
    """Beautify JavaScript content."""
    if HAS_JSBEAUTIFIER:
        opts = jsbeautifier.default_options()
        opts.indent_size = 2
        opts.indent_char = " "
        opts.max_preserve_newlines = 2
        opts.preserve_newlines = True
        opts.jslint_happy = False
        opts.space_after_anon_function = True
        opts.brace_style = "collapse"
        opts.keep_array_indentation = False
        opts.keep_function_indentation = False
        opts.space_before_conditional = True
        opts.break_chained_methods = False
        opts.eval_code = False
        opts.unescape_strings = True
        opts.wrap_line_length = 0
        return jsbeautifier.beautify(content, opts)
    else:
        # Fallback: basic formatting via regex
        import re
        # Add newlines after semicolons and braces
        result = re.sub(r';(?!\s*\n)', ';\n', content)
        result = re.sub(r'\{(?!\s*\n)', '{\n', result)
        result = re.sub(r'\}(?!\s*\n)', '}\n', result)
        return result


def main():
    parser = argparse.ArgumentParser(description="Beautify JavaScript files")
    parser.add_argument("--input-dir", required=True, help="Directory with raw JS files")
    parser.add_argument("--output-dir", required=True, help="Directory for beautified output")

    args = parser.parse_args()

    input_dir = Path(args.input_dir)
    output_dir = Path(args.output_dir)

    if not input_dir.exists():
        logger.error(f"Input directory does not exist: {input_dir}")
        sys.exit(1)

    js_files = list(input_dir.rglob("*.js"))
    logger.info(f"Found {len(js_files)} JS files to beautify")

    results = []
    errors = []

    for js_file in js_files:
        try:
            # Maintain relative directory structure
            rel_path = js_file.relative_to(input_dir)
            out_file = output_dir / rel_path
            out_file.parent.mkdir(parents=True, exist_ok=True)

            content = js_file.read_text(encoding="utf-8", errors="ignore")
            beautified = beautify_js(content)
            out_file.write_text(beautified, encoding="utf-8")

            results.append({
                "input": str(js_file),
                "output": str(out_file),
                "input_size": len(content),
                "output_size": len(beautified),
                "sha256": hashlib.sha256(beautified.encode()).hexdigest(),
            })
            logger.info(f"Beautified: {rel_path} ({len(content)} → {len(beautified)} bytes)")

        except Exception as e:
            errors.append({"file": str(js_file), "error": str(e)})
            logger.error(f"Error beautifying {js_file}: {e}")

    # Write summary
    summary = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "files_processed": len(results),
        "errors": len(errors),
        "results": results,
    }

    summary_path = output_dir / "beautify-summary.json"
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    if errors:
        errors_path = output_dir / "beautify-errors.json"
        errors_path.write_text(json.dumps(errors, indent=2), encoding="utf-8")

    logger.info(f"Done. {len(results)} files beautified, {len(errors)} errors.")


if __name__ == "__main__":
    main()
