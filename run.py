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
import time
from datetime import datetime, timezone
from pathlib import Path

# Keep the CLI usable on Windows consoles that still default to CP1252.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.resolve()
sys.path.insert(0, str(PROJECT_ROOT / "tools"))

from hackbot_orchestrator import HackbotOrchestrator, SKILL_ORDER
from skill_registry import SkillRegistry
from llm_client import load_dotenv_if_present, KNOWN_PROVIDERS


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
    parser.add_argument("--scan-mode", choices=["quick", "deep", "full", "passive"], default="full",
                        help="Scan profile: quick (surface recon & discovery), deep/full (full exploit suite), passive (zero active probes)")
    parser.add_argument("--fail-on-candidate", action="store_true",
                        help="Return exit code 2 when the completed run contains unverified candidate findings (useful in CI)")
    parser.add_argument("--models", default="default",
                        help="Comma-separated model names (default: default)")
    parser.add_argument("--runs-per-skill", type=int, default=1,
                        help="Number of runs per skill per model (default: 1)")
    parser.add_argument("--review-model", default=None,
                        help="Model to use for review-skill (default: same as skill model)")
    parser.add_argument("--api-spec", default=None,
                        help="Local OpenAPI/Swagger JSON or YAML file for api-spec-discovery")
    parser.add_argument("--active-host-limit", type=int, default=100,
                        help="Maximum hosts for recon HEAD checks (default: 100)")
    parser.add_argument("--root-only-active", action="store_true",
                        help="Limit active recon checks to the exact target hostname")
    parser.add_argument("--https-only", action="store_true",
                        help="Do not fall back to plaintext HTTP during active recon")
    parser.add_argument("--max-http-requests", type=int, default=150,
                        help="Maximum same-host GET/HEAD requests per scan (default: 150)")
    parser.add_argument("--request-delay", type=float, default=0.3,
                        help="Minimum seconds between target requests (default: 0.3)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show execution plan without running anything")
    parser.add_argument("--check", action="store_true",
                        help="Check prerequisites only")
    parser.add_argument("--provider", choices=list(KNOWN_PROVIDERS.keys()), default=None,
                        help="LLM provider for agentic reasoning (e.g. deepseek, openai, anthropic, groq)")
    parser.add_argument("--api-key", default=None,
                        help="API key for the selected provider (e.g. sk-...)")
    parser.add_argument("--model", default=None,
                        help="Model name to use (e.g. deepseek-chat, deepseek-reasoner)")
    parser.add_argument("--list-skills", action="store_true",
                        help="List all dynamically installed skills in skills/ and exit")
    parser.add_argument("--max-subagents", type=int, default=10,
                        help="Maximum autonomous child subagents the agent can spawn (default: 10)")
    parser.add_argument("--cookie", default=None,
                        help="Session cookie string for authenticated testing (e.g. 'session=xyz; user_id=123')")
    parser.add_argument("--auth-header", default=None,
                        help="Custom authorization header (e.g. 'Authorization: Bearer eyJ...')")
    parser.add_argument("--auth-file", default=None,
                        help="Path to JSON file containing auth headers/cookies")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Enable verbose debug output")
    parser.add_argument("--quiet", "-q", action="store_true",
                        help="Suppress informational output, show only errors and results")
    parser.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                        default="INFO", help="Set logging verbosity")
    parser.add_argument("--in-scope", default=None,
                        help="Comma-separated list of allowed host patterns (e.g. '*.target.com,target.com')")
    parser.add_argument("--out-of-scope", default=None,
                        help="Comma-separated list of forbidden host patterns (e.g. 'blog.target.com,status.target.com')")
    parser.add_argument("--bug-bounty-id", default=None,
                        help="Bug bounty identifier to send in X-Bug-Bounty header (e.g. 'hackerone-handle')")
    parser.add_argument("--parallel", action="store_true",
                        help="Execute independent skills in parallel using ThreadPoolExecutor")
    parser.add_argument("--dashboard", action="store_true",
                        help="Launch local web dashboard viewer")
    parser.add_argument("--port", type=int, default=8080,
                        help="Dashboard server port (default: 8080)")
    parser.add_argument("--no-open", action="store_true",
                        help="Do not open a browser when launching the dashboard")
    parser.add_argument("command", nargs="?", choices=["view"],
                        help=argparse.SUPPRESS)

    args = parser.parse_args()
    load_dotenv_if_present()

    import logging
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG, force=True)
    elif args.quiet:
        logging.basicConfig(level=logging.ERROR, force=True)
    else:
        logging.basicConfig(level=getattr(logging, args.log_level, logging.INFO), force=True)

    # Configure provider overrides if specified on CLI
    if args.provider:
        os.environ["MOROS_LLM_PROVIDER"] = args.provider
        prov_info = KNOWN_PROVIDERS.get(args.provider, {})
        if args.api_key:
            env_key = prov_info.get("env_key", f"{args.provider.upper()}_API_KEY")
            os.environ[env_key] = args.api_key
        if args.model:
            env_model = prov_info.get("env_model", f"{args.provider.upper()}_MODEL")
            os.environ[env_model] = args.model

    # Configure Authenticated Scanning & Session Credentials
    if args.cookie:
        os.environ["MOROS_AUTH_COOKIE"] = args.cookie
    if args.auth_header:
        os.environ["MOROS_AUTH_HEADER"] = args.auth_header
    if args.bug_bounty_id:
        os.environ["MOROS_BUG_BOUNTY_ID"] = args.bug_bounty_id
    if args.auth_file:
        auth_p = Path(args.auth_file)
        if auth_p.is_file():
            try:
                auth_data = json.loads(auth_p.read_text(encoding="utf-8"))
                if "cookie" in auth_data:
                    os.environ["MOROS_AUTH_COOKIE"] = str(auth_data["cookie"])
                if "cookies" in auth_data:
                    c_str = "; ".join(f"{k}={v}" for k, v in auth_data["cookies"].items()) if isinstance(auth_data["cookies"], dict) else str(auth_data["cookies"])
                    os.environ["MOROS_AUTH_COOKIE"] = c_str
                if "authorization" in auth_data:
                    os.environ["MOROS_AUTH_HEADER"] = f"Authorization: {auth_data['authorization']}"
                if "headers" in auth_data and isinstance(auth_data["headers"], dict):
                    for hk, hv in auth_data["headers"].items():
                        if hk.lower() == "authorization":
                            os.environ["MOROS_AUTH_HEADER"] = f"{hk}: {hv}"
            except Exception as e:
                print(f"⚠️  Warning: Failed to parse --auth-file: {e}")

    # Configure Strict Scope Boundaries
    if args.in_scope:
        os.environ["MOROS_IN_SCOPE"] = args.in_scope
    if args.out_of_scope:
        os.environ["MOROS_OUT_OF_SCOPE"] = args.out_of_scope

    registry = SkillRegistry()
    installed_skills = registry.list_skills()
    all_skill_ids = [s["id"] for s in installed_skills]

    # Handle --list-skills
    if args.list_skills:
        print("\n📦 Installed Security Skills in Moros AI:")
        print(f"{'Skill ID':<32} {'Category':<22} {'Type'}")
        print("-" * 68)
        for s in installed_skills:
            stype = "Custom" if s.get("is_custom") else "Core"
            print(f"{s['id']:<32} {s.get('category', 'Offensive'):<22} {stype}")
        print(f"\nTotal: {len(installed_skills)} skills available.\n")
        sys.exit(0)

    # Check dashboard flag or subcommands
    if args.dashboard or args.command == "view":
        from dashboard.server import run_dashboard
        run_dashboard(
            port=args.port,
            open_browser=not args.no_open,
            default_target=args.target,
        )
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
        if args.scan_mode == "quick":
            skills = ["recon-subdomain", "api-spec-discovery", "js-discover", "js-analyze",
                      "content-discovery", "xss-reflected", "ssrf-identify", "report-conglomeration"]
        elif args.scan_mode == "passive":
            skills = ["recon-subdomain", "api-spec-discovery", "js-discover", "js-analyze", "report-conglomeration"]
        else:
            skills = registry.get_execution_order()
    else:
        skills = [s.strip() for s in args.skills.split(",")]
        # Validate skill names against all dynamically discovered skills
        for s in skills:
            if s not in all_skill_ids:
                print(f"\n❌ Unknown skill: '{s}'")
                print(f"   Available skills ({len(all_skill_ids)}): {', '.join(all_skill_ids)}")
                sys.exit(1)

    # Parse models
    models = [m.strip() for m in args.models.split(",")]

    # Dry run
    if args.dry_run:
        print("\n📋 DRY RUN — Execution Plan:")
        print(f"   Target: {args.target}")
        print(f"   Directory: {target_dir}")
        print(f"   Skills ({len(skills)}): {' → '.join(skills)}")
        print(f"   Scan mode: {args.scan_mode}")
        print(f"   Models: {', '.join(models)}")
        print(f"   Runs per skill: {args.runs_per_skill}")
        print(f"   Review model: {args.review_model or 'same as skill'}")
        if args.api_spec:
            print(f"   API spec: {args.api_spec}")

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
    print(f"   Scan mode: {args.scan_mode}")
    print(f"   Models: {', '.join(models)}")
    print()

    orchestrator = HackbotOrchestrator(
        target=args.target,
        target_dir=target_dir,
        skills=skills,
        models=models,
        runs_per_skill=args.runs_per_skill,
        review_model=args.review_model,
        api_spec=args.api_spec,
        active_host_limit=args.active_host_limit,
        root_only_active=args.root_only_active,
        https_only=args.https_only,
        max_http_requests=args.max_http_requests,
        request_delay=args.request_delay,
        parallel=args.parallel,
    )

    scan_started_at = time.time()
    try:
        result = orchestrator.run()
        if result and result.get("status") == "FAILED":
            sys.exit(1)
        if args.fail_on_candidate and result:
            findings_root = target_path / "output" / "findings"
            has_candidate = False
            if findings_root.exists():
                for artifact in findings_root.rglob("candidates-*.json"):
                    if artifact.stat().st_mtime < scan_started_at:
                        continue
                    try:
                        payload = json.loads(artifact.read_text(encoding="utf-8"))
                        if payload.get("findings"):
                            has_candidate = True
                            break
                    except (OSError, json.JSONDecodeError, AttributeError):
                        continue
            if has_candidate:
                sys.exit(2)
    except KeyboardInterrupt:
        print("\n\n⚠️  Scan interrupted by user.")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        raise


if __name__ == "__main__":
    main()
