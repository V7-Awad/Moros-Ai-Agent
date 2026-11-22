#!/usr/bin/env python3
"""
run.py — Main entry point for Moros AI Agent (Hackbot).

Usage:
    python run.py --target example.com
    python run.py --target example.com --skills recon-subdomain,js-discover,js-analyze
    python run.py --target example.com --dry-run
    python run.py --target example.com --models claude-sonnet,gpt-4o-mini --runs-per-skill 2
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.resolve()
sys.path.insert(0, str(PROJECT_ROOT / "tools"))

from hackbot_orchestrator import HackbotOrchestrator, SKILL_ORDER


BANNER = r"""
  __  __                        _    ___ 
 |  \/  | ___  _ __ ___  ___   / \  |_ _|
 | |\/| |/ _ \| '__/ _ \/ __| / _ \  | | 
 | |  | | (_) | | | (_) \__ \/ ___ \ | | 
 |_|  |_|\___/|_|  \___/|___/_/   \_\___|
                                          
  Agentic Web Pentest Automation System
  ⚠️  AUTHORIZED TESTING ONLY
"""


def check_prerequisites():
    """Check that required tools are installed."""
    issues = []

    # Check Python version
    if sys.version_info < (3, 10):
        issues.append(f"Python 3.10+ required, found {sys.version}")

    # Check playwright
    try:
        import playwright
    except ImportError:
        issues.append("playwright not installed. Run: pip install playwright && playwright install chromium")

    # Check jsbeautifier
    try:
        import jsbeautifier
    except ImportError:
        issues.append("jsbeautifier not installed. Run: pip install jsbeautifier")

    return issues


def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="Moros AI Agent — Agentic Web Pentest Automation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run.py --target example.com
  python run.py --target example.com --skills js-discover,js-analyze
  python run.py --target example.com --dry-run
  python run.py --target example.com --models claude-sonnet,gpt-4o-mini
        """
    )

    parser.add_argument("--target", required=False, default=None,
                        help="Target domain (e.g., example.com)")
    parser.add_argument("--target-dir", default=None,
                        help="Custom target directory (default: targets/<domain>)")
    parser.add_argument("--skills", default="all",
                        help="Comma-separated skill names, or 'all' (default: all)")
    parser.add_argument("--models", default="default",
                        help="Comma-separated model names (default: default)")
    parser.add_argument("--runs-per-skill", type=int, default=1,
                        help="Number of runs per skill per model (default: 1)")
    parser.add_argument("--review-model", default=None,
                        help="Model to use for review-skill (default: same as skill model)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show execution plan without running anything")
    parser.add_argument("--check", action="store_true",
                        help="Check prerequisites only")
    parser.add_argument("--dashboard", action="store_true",
                        help="Launch local web dashboard viewer (like 'strix view')")
    parser.add_argument("--port", type=int, default=8080,
                        help="Dashboard server port (default: 8080)")

    args = parser.parse_args()

    # Check dashboard flag or subcommands
    if args.dashboard or (len(sys.argv) > 1 and sys.argv[1] == "view"):
        from dashboard.server import run_dashboard
        target_name = args.target if hasattr(args, "target") else None
        run_dashboard(port=args.port, default_target=target_name)
        sys.exit(0)

    # Check prerequisites
    issues = check_prerequisites()
    if args.check:
        if issues:
            print("\n❌ Issues found:")
            for issue in issues:
                print(f"   • {issue}")
            sys.exit(1)
        else:
            print("\n✅ All prerequisites met!")
            sys.exit(0)

    if issues:
        print("\n⚠️  Some prerequisites are missing (non-fatal):")
        for issue in issues:
            print(f"   • {issue}")
        print()

    if not args.target:
        print("\n❌ Error: --target is required to run a scan.")
        print("   Example: python run.py --target example.com")
        print("   To launch dashboard: python run.py --dashboard (or python dashboard.py)")
        sys.exit(1)

    # Resolve target directory
    target_dir = args.target_dir or str(PROJECT_ROOT / "targets" / args.target)
    target_path = Path(target_dir)

    # Check target directory exists
    if not target_path.exists():
        print(f"\n❌ Target directory not found: {target_dir}")
        print(f"   Run: python setup.py init-target --domain {args.target}")
        sys.exit(1)

    # Parse skills
    if args.skills == "all":
        skills = list(SKILL_ORDER)
    else:
        skills = [s.strip() for s in args.skills.split(",")]
        # Validate skill names
        for s in skills:
            if s not in SKILL_ORDER:
                print(f"\n❌ Unknown skill: {s}")
                print(f"   Available skills: {', '.join(SKILL_ORDER)}")
                sys.exit(1)

    # Parse models
    models = [m.strip() for m in args.models.split(",")]

    # Dry run
    if args.dry_run:
        print("\n📋 DRY RUN — Execution Plan:")
        print(f"   Target: {args.target}")
        print(f"   Directory: {target_dir}")
        print(f"   Skills ({len(skills)}): {' → '.join(skills)}")
        print(f"   Models: {', '.join(models)}")
        print(f"   Runs per skill: {args.runs_per_skill}")
        print(f"   Review model: {args.review_model or 'same as skill'}")

        # Check scope
        scope_files = list(target_path.glob("scope-of-work.*"))
        if scope_files:
            print(f"\n   ✅ Scope-of-work found: {scope_files[0].name}")
        else:
            print(f"\n   ⚠️  No scope-of-work found — will run in PASSIVE-ONLY mode")

        total_runs = len(skills) * len(models) * args.runs_per_skill
        print(f"\n   Total skill runs planned: {total_runs}")
        print(f"   Total review runs planned: {total_runs} (one per skill run)")
        sys.exit(0)

    # Run orchestrator
    print(f"\n🚀 Starting Moros AI scan of {args.target}")
    print(f"   Skills: {', '.join(skills)}")
    print(f"   Models: {', '.join(models)}")
    print()

    orchestrator = HackbotOrchestrator(
        target=args.target,
        target_dir=target_dir,
        skills=skills,
        models=models,
        runs_per_skill=args.runs_per_skill,
        review_model=args.review_model,
    )

    try:
        orchestrator.run()
    except KeyboardInterrupt:
        print("\n\n⚠️  Scan interrupted by user.")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        raise


if __name__ == "__main__":
    main()
