#!/usr/bin/env python3
"""
setup.py — Setup and initialization for Moros AI Agent.

Usage:
    python setup.py init-target --domain example.com
    python setup.py check
    python setup.py install
"""

import argparse
import json
import os
import subprocess
import sys
import re
from pathlib import Path

# Keep setup commands usable in Windows terminals that default to CP1252.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

PROJECT_ROOT = Path(__file__).parent.resolve()


def validate_target_name(domain: str) -> str:
    """Accept DNS-like labels only; target names are also filesystem paths."""
    if not isinstance(domain, str) or not re.fullmatch(
        r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?", domain
    ) or ".." in domain:
        raise ValueError("Target must be a DNS-like name without path separators")
    return domain


def init_target(domain: str):
    """Initialize a target directory with the required structure."""
    domain = validate_target_name(domain)
    target_dir = PROJECT_ROOT / "targets" / domain
    output_dir = target_dir / "output"

    # Create directory structure
    dirs = [
        target_dir,
        output_dir / "recon",
        output_dir / "js" / "raw" / "external",
        output_dir / "js" / "raw" / "inline",
        output_dir / "js" / "raw" / "lazy-loaded",
        output_dir / "js" / "raw" / "historical",
        output_dir / "js" / "beautified" / "external",
        output_dir / "js" / "beautified" / "inline",
        output_dir / "js" / "beautified" / "lazy-loaded",
        output_dir / "js" / "beautified" / "historical",
        output_dir / "js" / "source-maps" / "external",
        output_dir / "js" / "source-maps" / "inline",
        output_dir / "content-discovery",
        output_dir / "api",
        output_dir / "logs" / "api-spec-discovery",
        output_dir / "findings" / "xss-reflected",
        output_dir / "findings" / "xss-stored",
        output_dir / "findings" / "xss-dom",
        output_dir / "findings" / "xss-blind",
        output_dir / "findings" / "ssrf",
        output_dir / "findings" / "idp-race",
        output_dir / "findings" / "auth-reset",
        output_dir / "logs" / "recon-subdomain",
        output_dir / "logs" / "js-discover",
        output_dir / "logs" / "js-analyze",
        output_dir / "logs" / "content-discovery",
        output_dir / "logs" / "xss-reflected",
        output_dir / "logs" / "xss-stored",
        output_dir / "logs" / "xss-dom",
        output_dir / "logs" / "xss-blind",
        output_dir / "logs" / "ssrf-identify",
        output_dir / "logs" / "ssrf-post-exploit",
        output_dir / "logs" / "idp-race-condition",
        output_dir / "logs" / "auth-password-reset",
        output_dir / "logs" / "review",
        output_dir / "logs" / "report-conglomeration",
        output_dir / "report",
    ]

    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)

    # Create a placeholder scope-of-work notice
    notice_path = target_dir / "PLACE_SCOPE_OF_WORK_HERE.txt"
    if not notice_path.exists():
        notice_path.write_text(
            f"# Authorization Required for {domain}\n\n"
            f"Before running any offensive skills against {domain}, you MUST:\n\n"
            f"1. Place your signed scope-of-work document in this directory:\n"
            f"   - File name: scope-of-work.md (also supported: .txt, .yaml, .yml, .json)\n"
            f"   - Must contain the target domain and signed authorization wording\n"
            f"     (bug bounty program rules or penetration testing agreement).\n\n"
            f"2. Without this file, only passive reconnaissance skills will execute.\n\n"
            f"⚠️  UNAUTHORIZED TESTING IS ILLEGAL. ⚠️\n",
            encoding="utf-8"
        )

    # Create .gitkeep files so empty dirs are tracked
    for d in dirs:
        gitkeep = d / ".gitkeep"
        if not gitkeep.exists() and not any(d.iterdir()):
            gitkeep.touch()

    # Create scope.json template
    scope_json = target_dir / "scope.json"
    if not scope_json.exists():
        scope_template = {
            "target": domain,
            "in_scope": [domain, f"*.{domain}"],
            "out_of_scope": [],
            "notes": "Edit this file to define precise scope boundaries"
        }
        scope_json.write_text(
            json.dumps(scope_template, indent=2) + "\n",
            encoding="utf-8"
        )

    # Create scope-of-work.md template
    scope_md = target_dir / "scope-of-work.md"
    if not scope_md.exists():
        scope_md.write_text(
            f"# Scope of Work — {domain}\n\n"
            f"## Authorization\n"
            f"This assessment of `{domain}` is authorized under:\n"
            f"- [ ] Bug Bounty Program\n"
            f"- [ ] Penetration Testing Agreement\n"
            f"- [ ] Written Authorization\n\n"
            f"## In Scope\n"
            f"- `{domain}`\n"
            f"- `*.{domain}`\n\n"
            f"## Out of Scope\n"
            f"- (add excluded hosts here)\n\n"
            f"## Rules of Engagement\n"
            f"- Non-destructive testing only\n"
            f"- No denial of service\n"
            f"- No data exfiltration\n",
            encoding="utf-8"
        )

    print(f"✅ Target initialized: {target_dir}")
    print(f"   📁 Output directories created")
    print(f"   ⚠️  Review/authorize scope-of-work.md (or .txt/.yaml/.yml/.json) in: {target_dir}/")
    print(f"\n   Next: python run.py --target {domain}")


def check_system():
    """Check all system prerequisites."""
    print("🔍 Checking Moros AI prerequisites...\n")
    all_ok = True

    # Python version
    py_ver = sys.version_info
    if py_ver >= (3, 10):
        print(f"  ✅ Python {py_ver.major}.{py_ver.minor}.{py_ver.micro}")
    else:
        print(f"  ❌ Python {py_ver.major}.{py_ver.minor}.{py_ver.micro} (need 3.10+)")
        all_ok = False

    # Required packages
    packages = {
        "playwright": "playwright",
        "jsbeautifier": "jsbeautifier",
        "yaml": "PyYAML",
    }

    for import_name, pip_name in packages.items():
        try:
            __import__(import_name)
            print(f"  ✅ {pip_name}")
        except ImportError:
            print(f"  ❌ {pip_name} (pip install {pip_name})")
            all_ok = False

    # Playwright browsers
    try:
        from playwright.sync_api import sync_playwright
        browsers_env = os.environ.get("PLAYWRIGHT_BROWSERS_PATH", "").strip()
        if browsers_env and not Path(browsers_env).exists():
            print(f"  ❌ PLAYWRIGHT_BROWSERS_PATH does not exist: {browsers_env} (run 'playwright install chromium')")
            all_ok = False
        else:
            with sync_playwright() as p:
                chromium_exe = Path(p.chromium.executable_path)
            if chromium_exe.is_file():
                print(f"  ✅ Playwright Chromium browser installed ({chromium_exe})")
            else:
                print("  ❌ Playwright Chromium browser missing (run 'playwright install chromium')")
                all_ok = False
    except ImportError:
        pass
    except Exception as exc:
        print(f"  ⚠️  Could not verify Playwright Chromium browser ({exc}); run 'playwright install chromium' if missing")

    print()
    if all_ok:
        print("✅ All prerequisites met!")
    else:
        print("❌ Some prerequisites missing. Run: pip install -r requirements.txt")

    return all_ok


def install_deps():
    """Install all Python dependencies."""
    print("📦 Installing dependencies...\n")
    req_file = PROJECT_ROOT / "requirements.txt"

    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", "-r", str(req_file)],
        capture_output=False
    )

    if result.returncode == 0:
        print("\n✅ Dependencies installed!")
        print("   Now install Playwright browsers: playwright install chromium")
    else:
        print("\n❌ Installation failed. Check errors above.")

    return result.returncode == 0


def main():
    parser = argparse.ArgumentParser(
        description="Moros AI Agent — Setup & Initialization"
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # init-target
    init_parser = subparsers.add_parser("init-target", help="Initialize a target directory")
    init_parser.add_argument("--domain", required=True, help="Target domain")

    # check
    subparsers.add_parser("check", help="Check system prerequisites")

    # install
    subparsers.add_parser("install", help="Install Python dependencies")

    args = parser.parse_args()

    if args.command == "init-target":
        init_target(args.domain)
    elif args.command == "check":
        sys.exit(0 if check_system() else 1)
    elif args.command == "install":
        sys.exit(0 if install_deps() else 1)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
