#!/usr/bin/env python3
"""
dashboard.py — Moros AI Web Dashboard Launcher
Inspired by Strix's `strix view` command.

Usage:
    python dashboard.py
    python dashboard.py --port 8080
    python dashboard.py --target example.com
    python dashboard.py --no-open
"""

import argparse
import sys
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.resolve()
sys.path.insert(0, str(PROJECT_ROOT / "dashboard"))

from server import run_dashboard


def main():
    parser = argparse.ArgumentParser(
        description="Moros AI Agent — Web Dashboard (Interactive Viewer)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python dashboard.py
  python dashboard.py --port 9000
  python dashboard.py --target example.com
  python dashboard.py --host 0.0.0.0 --port 8080 --no-open
        """
    )

    parser.add_argument("--host", default="127.0.0.1",
                        help="Host to bind server to (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8080,
                        help="Port to listen on (default: 8080)")
    parser.add_argument("--target", default=None,
                        help="Target domain to focus on initially")
    parser.add_argument("--no-open", action="store_true",
                        help="Do not automatically open browser")

    args = parser.parse_args()

    run_dashboard(
        host=args.host,
        port=args.port,
        open_browser=not args.no_open,
        default_target=args.target
    )


if __name__ == "__main__":
    main()
