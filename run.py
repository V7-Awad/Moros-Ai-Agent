#!/usr/bin/env python3
"""
run.py — Main entry point for Moros offensive security testing framework.

Usage:
    python run.py --target example.com
    python run.py --target example.com --skills recon-subdomain,js-discover,js-analyze
    python run.py --target example.com --dry-run
    python run.py --target example.com --models claude-sonnet,gpt-4o-mini --runs-per-skill 2
"""

import argparse
import inspect
import json
import os
import sys
import time
from pathlib import Path

# Keep the CLI usable on Windows consoles that still default to CP1252.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.resolve()
sys.path.insert(0, str(PROJECT_ROOT / "tools"))

from hackbot_orchestrator import HackbotOrchestrator
from skill_registry import SkillRegistry
from llm_client import load_dotenv_if_present, KNOWN_PROVIDERS
from model_router import ModelRouter


BANNER = r"""
  __  __                        _    ___ 
 |  \/  | ___  _ __ ___  ___   / \  |_ _|
 | |\/| |/ _ \| '__/ _ \/ __| / _ \  | | 
 | |  | | (_) | | | (_) \__ \/ ___ \ | | 
 |_|  |_|\___/|_|  \___/|___/_/   \_\___|
                                          
  Web Penetration Testing Automation Framework
  [!] AUTHORIZED SECURITY ASSESSMENTS ONLY
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

    # Check PyYAML
    try:
        import yaml
    except ImportError:
        issues.append("PyYAML not installed. Run: pip install PyYAML")

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
    parser.add_argument("--sandbox", choices=["none", "local", "docker"], default="local",
                        help="Execution sandbox mode for custom skills (default: local)")
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
    parser.add_argument("--budget", type=float, default=10.0,
                        help="Maximum LLM spend budget in USD (default: 10.0)")
    parser.add_argument("--mcp-server", action="append", default=[],
                        help="External MCP tool server URL or stdio command (repeatable)")
    parser.add_argument("--no-trace", action="store_true",
                        help="Disable OpenTelemetry trace export under output/traces/")
    parser.add_argument("--smart-route", action="store_true",
                        help="Enable complexity-based cost-aware model routing")
    parser.add_argument("--deep-recon", action="store_true",
                        help="Include parallel deep-recon fan-out skill in scan")
    parser.add_argument("--lang", choices=["en", "ar"], default="en",
                        help="Report output language: en (English) or ar (Arabic bilingual)")
    parser.add_argument("--dialect", choices=["msa", "egyptian"], default="msa",
                        help="Arabic report tone when --lang ar: msa or egyptian")
    parser.add_argument("--cookie-b", default=None,
                        help="Secondary session cookie for dual-auth IDOR/BOLA diffing")
    parser.add_argument("--auth-header-b", default=None,
                        help="Secondary authorization header for dual-auth IDOR/BOLA diffing")
    parser.add_argument("--oob-url", default=None,
                        help="External OOB/Interactsh callback URL for blind vulnerability checks")
    parser.add_argument("--oob-listen", action="store_true",
                        help="Start local OOB HTTP callback listener during scan")
    parser.add_argument("--schedule", default=None,
                        help="Register recurring scan schedule (e.g. 'interval:3600' or 'cron:0 2 * * *') and exit")
    parser.add_argument("--list-schedules", action="store_true",
                        help="List saved scan schedules for --target and exit")
    parser.add_argument("--proposals", choices=["list", "generate"], default=None,
                        help="List or generate learned SKILL.md proposals for --target and exit")
    parser.add_argument("--approve-proposal", default=None,
                        help="Approve and activate a pending skill proposal ID for --target and exit")
    parser.add_argument("--proxy", default=None,
                        help="HTTP/HTTPS/SOCKS5 proxy URL for scoped target requests (sets MOROS_PROXY)")
    parser.add_argument("--resume", nargs="?", const="latest", default=None,
                        help="Resume the latest (or specified) incomplete scan run ID")
    parser.add_argument("--no-failover", action="store_true",
                        help="Disable cross-provider LLM failover (sets MOROS_LLM_FAILOVER=0)")
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

    # Configure proxy and LLM failover flags
    if args.proxy:
        os.environ["MOROS_PROXY"] = args.proxy.strip()
    if args.no_failover:
        os.environ["MOROS_LLM_FAILOVER"] = "0"

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
    if args.cookie_b:
        os.environ["MOROS_AUTH_COOKIE_B"] = args.cookie_b
    if args.auth_header_b:
        os.environ["MOROS_AUTH_HEADER_B"] = args.auth_header_b
    if args.oob_url:
        os.environ["MOROS_OOB_URL"] = args.oob_url
        os.environ["MOROS_CALLBACK_URL"] = args.oob_url
    os.environ["MOROS_REPORT_LANG"] = args.lang
    os.environ["MOROS_REPORT_DIALECT"] = args.dialect
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

    # Configure Sandbox Isolation & Subagent Cap
    os.environ["MOROS_SANDBOX_MODE"] = args.sandbox
    os.environ["MOROS_MAX_SUBAGENTS"] = str(args.max_subagents)

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

    # Handle --list-schedules / --schedule
    if args.list_schedules or args.schedule:
        from scheduler import ScanScheduler
        sched = ScanScheduler(target=args.target, target_dir=target_path)
        if args.schedule:
            raw_spec = str(args.schedule).strip()
            if raw_spec.startswith("interval:"):
                interval_val = float(raw_spec.split(":", 1)[1].strip())
                created = sched.create_schedule(
                    name=f"cli-{args.scan_mode}",
                    interval_seconds=interval_val,
                    budget_usd=args.budget,
                    scan_mode=args.scan_mode,
                )
            elif raw_spec.startswith("cron:"):
                cron_expr = raw_spec.split(":", 1)[1].strip()
                created = sched.create_schedule(
                    name=f"cli-{args.scan_mode}",
                    cron=cron_expr,
                    budget_usd=args.budget,
                    scan_mode=args.scan_mode,
                )
            else:
                created = sched.create_schedule(
                    name=f"cli-{args.scan_mode}",
                    cron=raw_spec,
                    budget_usd=args.budget,
                    scan_mode=args.scan_mode,
                )
            print(json.dumps({"status": "scheduled", "schedule": created}, indent=2))
            sys.exit(0)
        print(json.dumps({"target": args.target, "schedules": sched.list_schedules()}, indent=2))
        sys.exit(0)

    # Handle --proposals / --approve-proposal
    if args.proposals or args.approve_proposal:
        from skill_learner import SkillLearner
        learner = SkillLearner(target_dir=target_path)
        if args.approve_proposal:
            approved = learner.approve_proposal(args.approve_proposal, approved_by="cli-operator")
            print(json.dumps({"status": "approved", "proposal": approved}, indent=2))
            sys.exit(0)
        if args.proposals == "generate":
            drafts = learner.propose_skills()
            print(json.dumps({"target": args.target, "generated": drafts}, indent=2))
            sys.exit(0)
        print(json.dumps({"target": args.target, "proposals": learner.list_proposals()}, indent=2))
        sys.exit(0)

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
    if args.resume and args.skills == "all" and (target_path / "output" / "runs").is_dir():
        try:
            from run_manager import RunManager
            resume_target = None if str(args.resume).strip().lower() == "latest" else str(args.resume).strip()
            resume_plan = RunManager(target_path).prepare_resume_plan(resume_target)
            if resume_plan and resume_plan.get("skills_requested"):
                valid_prior = [s for s in resume_plan["skills_requested"] if s in all_skill_ids]
                if valid_prior:
                    skills = valid_prior
        except Exception:
            pass

    if args.deep_recon and "deep-recon" not in skills:
        insert_at = 1 if skills and skills[0] == "recon-subdomain" else 0
        skills.insert(insert_at, "deep-recon")

    models = [m.strip() for m in args.models.split(",")]
    cost_est = ModelRouter(budget_usd=args.budget).estimate_scan_cost(len(skills))

    # Dry run
    if args.dry_run:
        print("\n📋 DRY RUN — Execution Plan:")
        print(f"   Target: {args.target}")
        print(f"   Directory: {target_dir}")
        print(f"   Skills ({len(skills)}): {' → '.join(skills)}")
        print(f"   Scan mode: {args.scan_mode}")
        print(f"   Models: {', '.join(models)} (smart-route: {args.smart_route})")
        print(f"   Sandbox: {args.sandbox} | Max subagents: {args.max_subagents}")
        if args.proxy:
            print(f"   Proxy: {args.proxy}")
        if args.resume:
            print(f"   Resume run: {args.resume}")
        print(f"   Budget Cap: ${args.budget:.2f} | Est. LLM Cost: ${cost_est['cost_low_usd']:.4f}–${cost_est['cost_high_usd']:.4f}")
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
    print(f"   Models: {', '.join(models)} | Budget Cap: ${args.budget:.2f}")
    print()

    orchestrator_kwargs = dict(
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
        budget_usd=args.budget,
        mcp_servers=args.mcp_server,
        enable_tracing=not args.no_trace,
        smart_routing=args.smart_route,
    )
    try:
        orch_params = inspect.signature(HackbotOrchestrator).parameters
        has_varkw = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in orch_params.values())
        if "max_subagents" in orch_params or has_varkw:
            orchestrator_kwargs["max_subagents"] = args.max_subagents
        if "resume_run_id" in orch_params or has_varkw:
            orchestrator_kwargs["resume_run_id"] = args.resume
        if "proxy" in orch_params or has_varkw:
            orchestrator_kwargs["proxy"] = args.proxy
    except (TypeError, ValueError):
        orchestrator_kwargs["max_subagents"] = args.max_subagents
        if args.resume is not None:
            orchestrator_kwargs["resume_run_id"] = args.resume
        if args.proxy is not None:
            orchestrator_kwargs["proxy"] = args.proxy

    orchestrator = HackbotOrchestrator(**orchestrator_kwargs)
    if getattr(orchestrator, "runner", None) is not None:
        orchestrator.runner.sandbox_mode = args.sandbox
        orchestrator.runner.max_subagents = args.max_subagents

    oob_server = None
    if args.oob_listen and not os.environ.get("MOROS_OOB_URL"):
        try:
            from oob_server import OOBServer
            oob_server = OOBServer(host="127.0.0.1", port=0, log_dir=target_path / "output" / "logs")
            listen_url = oob_server.start()
            os.environ["MOROS_OOB_URL"] = listen_url
            os.environ["MOROS_CALLBACK_URL"] = listen_url
            print(f"   📡 Local OOB Callback Listener active: {listen_url}")
        except Exception as exc:
            print(f"   ⚠️  Could not start local OOB listener: {exc}")

    scan_started_at = time.time()
    try:
        result = orchestrator.run()
        if oob_server is not None:
            hits = oob_server.list_callbacks()
            if hits:
                print(f"\n   📡 OOB Listener captured {len(hits)} callback(s) during scan.")
        if orchestrator.cost_tracker.get_running_total().get("total_calls", 0) > 0:
            print("\n" + orchestrator.cost_tracker.format_human_summary())
        if result and result.get("status") == "BLOCKED_SCOPE":
            print("\n🛑 Scan stopped because a request or redirect violated the saved scope policy.")
            sys.exit(3)
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
    finally:
        if oob_server is not None:
            try:
                oob_server.stop()
            except Exception:
                pass


if __name__ == "__main__":
    main()
