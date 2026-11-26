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
from llm_client import LLMClient, load_dotenv_if_present, KNOWN_PROVIDERS
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


def _iter_finding_containers(target_path: Path):
    """Yield (path, container, findings_list) from reports (newest first) and findings/*.json."""
    output_dir = target_path / "output"
    report_dir = output_dir / "report"
    if report_dir.is_dir():
        report_files = sorted(
            report_dir.glob("hackbot-report-*.json"),
            key=lambda p: (p.stat().st_mtime, p.name),
            reverse=True,
        )
        for rf in report_files:
            try:
                data = json.loads(rf.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if isinstance(data, dict) and isinstance(data.get("findings"), list):
                yield rf, data, data["findings"]

    findings_dir = output_dir / "findings"
    if findings_dir.is_dir():
        for ff in sorted(findings_dir.rglob("*.json")):
            try:
                data = json.loads(ff.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if isinstance(data, list):
                yield ff, data, data
            elif isinstance(data, dict) and isinstance(data.get("findings"), list):
                yield ff, data, data["findings"]
            elif isinstance(data, dict) and "title" in data:
                yield ff, data, [data]


def _matches_finding_id(item: dict, finding_id: str) -> bool:
    if not isinstance(item, dict):
        return False
    target_id = str(finding_id or "").strip()
    if not target_id:
        return False
    if str(item.get("finding_id") or "").strip() == target_id or str(item.get("id") or "").strip() == target_id:
        return True
    try:
        from remediation_assistant import _extract_finding_id
        if _extract_finding_id(item) == target_id:
            return True
    except Exception:
        pass
    return False


def _find_target_finding(target_path: Path, finding_id: str):
    """Locate the first matching finding dict by ID across target report/finding artifacts."""
    for _path, _container, rows in _iter_finding_containers(target_path):
        for row in rows:
            if _matches_finding_id(row, finding_id):
                return dict(row)
    return None


def _update_finding_in_artifacts(target_path: Path, finding_id: str, updated_finding: dict) -> None:
    """Persist lifecycle updates for a finding across target report and finding JSON artifacts."""
    for path, container, rows in _iter_finding_containers(target_path):
        modified = False
        for idx, row in enumerate(rows):
            if _matches_finding_id(row, finding_id):
                rows[idx] = dict(updated_finding)
                modified = True
        if not modified:
            continue
        try:
            if isinstance(container, dict) and isinstance(container.get("findings"), list):
                container["findings"] = rows
                summary = container.get("summary")
                if isinstance(summary, dict):
                    summary["confirmed_findings"] = sum(
                        1 for f in rows if isinstance(f, dict) and f.get("status") == "confirmed"
                    )
                    summary["human_validated_findings"] = sum(
                        1 for f in rows if isinstance(f, dict) and f.get("status") == "validated"
                    )
                    summary["validated_findings"] = (
                        summary["confirmed_findings"] + summary["human_validated_findings"]
                    )
                    summary["unverified_candidates"] = sum(
                        1 for f in rows
                        if isinstance(f, dict) and f.get("status", "candidate") in ("candidate", "validating", "inconclusive")
                    )
                payload = container
            elif isinstance(container, list):
                payload = rows
            else:
                payload = rows[0] if rows else container
            path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        except OSError:
            continue


def _run_ci_gate_cli(target: str, target_path: Path, args) -> int:
    """Evaluate CI/CD policy gate via tools/ci_gate.py and optionally write PR summary."""
    from ci_gate import (
        EXIT_INVALID_CONFIG,
        GateConfig,
        InvalidGateConfigError,
        evaluate_gate,
        generate_pr_summary,
    )

    fail_on_confirmed = True if args.fail_on_confirmed is None else args.fail_on_confirmed
    try:
        cfg = GateConfig(
            min_severity=args.min_severity,
            fail_on_candidate=bool(args.fail_on_candidate),
            fail_on_confirmed=fail_on_confirmed,
        ).validate()
    except InvalidGateConfigError as exc:
        err_payload = {
            "status": "invalid_config",
            "passed": False,
            "exit_code": EXIT_INVALID_CONFIG,
            "target": target,
            "errors": [str(exc)],
        }
        print(json.dumps(err_payload, indent=2))
        return EXIT_INVALID_CONFIG

    evaluation = evaluate_gate(
        output_dir=target_path / "output",
        config=cfg,
        target=target,
    )
    if args.pr_summary_out:
        summary_md = generate_pr_summary(evaluation)
        out_path = Path(args.pr_summary_out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(summary_md, encoding="utf-8")

    print(json.dumps(evaluation, indent=2))
    return int(evaluation.get("exit_code", EXIT_INVALID_CONFIG))


def _run_remediate_cli(target: str, target_path: Path, args) -> int:
    """Run Phase 3 RemediationAssistant in an isolated sandbox/worktree without modifying main repo."""
    import subprocess
    from remediation_assistant import RemediationAssistant, RemediationError

    finding = _find_target_finding(target_path, args.remediate)
    if finding is None:
        print(json.dumps({
            "status": "error",
            "error": f"Finding '{args.remediate}' not found in {target_path / 'output'}",
        }, indent=2), file=sys.stderr)
        return 1

    repo_dir = Path(args.repo_dir).resolve() if args.repo_dir else PROJECT_ROOT
    llm = LLMClient(provider="auto")
    assistant = RemediationAssistant(
        repo_root=repo_dir,
        llm_client=llm if llm.is_available() else None,
        target=target,
        target_dir=target_path,
    )
    if (repo_dir / ".git").exists():
        try:
            proc = subprocess.run(
                ["git", "-C", str(repo_dir), "status", "--porcelain"],
                capture_output=True, text=True, timeout=10,
            )
            if proc.returncode == 0 and not proc.stdout.strip():
                assistant.test_runner.use_git_worktree = True
        except Exception:
            pass

    try:
        report = assistant.remediate(finding, require_confirmed=True)
    except RemediationError as exc:
        print(json.dumps({
            "status": "rejected",
            "finding_id": args.remediate,
            "error": str(exc),
        }, indent=2), file=sys.stderr)
        return 1

    rem_dir = target_path / "output" / "remediation"
    rem_dir.mkdir(parents=True, exist_ok=True)
    rem_json_path = rem_dir / f"{report.finding_id}.json"
    rem_md_path = rem_dir / f"{report.finding_id}.md"
    rem_json_path.write_text(report.to_json() + "\n", encoding="utf-8")
    rem_md_path.write_text(report.to_markdown(), encoding="utf-8")

    try:
        from learning_engine.engine import LearningEngine
        test_passed = (report.test_results or {}).get("passed")
        rem_outcome = "tested_pass" if test_passed is True else ("tested_fail" if test_passed is False else "proposed")
        with LearningEngine(root=target_path) as le:
            le.record_remediation_outcome(
                target=target,
                finding_id=report.finding_id,
                vuln_class=str(finding.get("type") or finding.get("vuln_class") or "finding"),
                outcome=rem_outcome,
                confidence=0.9 if test_passed is True else 0.5,
                strategy="remediation_assistant",
                evidence_ids=list(finding.get("evidence_ids") or []),
                metadata={"affected_file": report.affected_file, "approval_status": report.approval_status},
            )
    except Exception:
        pass

    print(report.to_json())
    return 0


def _run_retest_cli(target: str, target_path: Path, args) -> int:
    """Run Phase 4 RetestEngine for a finding and preserve historical proof/ledger provenance."""
    from checkpoint_manager import CheckpointManager
    from retest_engine import RetestEngine
    from scope_validator import ScopeValidator

    finding = _find_target_finding(target_path, args.retest)
    if finding is None:
        print(json.dumps({
            "status": "error",
            "error": f"Finding '{args.retest}' not found in {target_path / 'output'}",
        }, indent=2), file=sys.stderr)
        return 1

    remediation_id = ""
    rem_file = target_path / "output" / "remediation" / f"{args.retest}.json"
    if rem_file.is_file():
        remediation_id = f"rem-{args.retest}"

    retest_target = target
    vr = finding.get("validation_result") if isinstance(finding.get("validation_result"), dict) else {}
    vr_env = vr.get("environment") if isinstance(vr.get("environment"), dict) else {}
    url_hints = (
        str(finding.get("url") or ""),
        str(finding.get("endpoint") or ""),
        str(vr.get("endpoint") or ""),
        str(vr_env.get("base_url") or ""),
    )
    if "://" not in retest_target and any(u.startswith("http://") for u in url_hints):
        retest_target = f"http://{retest_target}"

    sv = ScopeValidator(target, target_dir=target_path)
    cm = CheckpointManager(target, target_path)
    engine = RetestEngine(
        target=retest_target,
        target_dir=target_path,
        scope_validator=sv,
        checkpoint_manager=cm,
        max_requests=args.max_http_requests,
        delay_seconds=args.request_delay,
    )
    retest_result = engine.retest_finding(
        finding,
        remediation_id=remediation_id,
        mutate_finding=True,
    )
    _update_finding_in_artifacts(target_path, args.retest, finding)

    try:
        from learning_engine.engine import LearningEngine
        if retest_result.outcome in ("fixed", "still_vulnerable", "regression_detected", "inconclusive"):
            with LearningEngine(root=target_path) as le:
                le.record_retest_outcome(
                    target=target,
                    finding_id=retest_result.finding_id,
                    vuln_class=str(finding.get("type") or retest_result.strategy or "finding"),
                    outcome=retest_result.outcome,
                    confidence=retest_result.confidence,
                    strategy=retest_result.strategy,
                    run_id=retest_result.retest_id,
                    evidence_ids=list(retest_result.retest_evidence_ids or retest_result.original_evidence_ids),
                    metadata={
                        "remediation_id": remediation_id,
                        "retest_artifact": retest_result.retest_artifact,
                    },
                )
    except Exception:
        pass

    print(json.dumps(retest_result.to_dict(), indent=2))
    return 3 if retest_result.outcome == "blocked_scope" else 0


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
    parser.add_argument("--validate", action="store_true",
                        help="Enable deterministic Phase 1 candidate validation before report assembly")
    parser.add_argument("--remediate", default=None, metavar="FINDING_ID",
                        help="Generate and sandbox-test a minimal remediation patch for FINDING_ID (no auto-commit)")
    parser.add_argument("--repo-dir", default=None, metavar="PATH",
                        help="Authorized source repository root for --remediate (default: project root)")
    parser.add_argument("--retest", default=None, metavar="FINDING_ID",
                        help="Run deterministic Phase 4 retest verification for FINDING_ID")
    parser.add_argument("--ci-gate", action="store_true",
                        help="Evaluate CI/CD policy gate against target artifacts (tools/ci_gate.py)")
    parser.add_argument("--min-severity", choices=["info", "low", "medium", "high", "critical"],
                        default="high", help="Minimum severity threshold for --ci-gate (default: high)")
    parser.add_argument("--fail-on-confirmed", nargs="?", const="true", default=None,
                        help="Fail --ci-gate (exit 2) when confirmed/validated findings meet thresholds")
    parser.add_argument("--pr-summary-out", default=None, metavar="PATH",
                        help="Write secret-redacted Markdown PR summary from --ci-gate to PATH")
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

    # Handle --remediate / --retest / standalone --ci-gate (deterministic, no LLM required)
    if args.remediate:
        sys.exit(_run_remediate_cli(args.target, target_path, args))

    if args.retest:
        sys.exit(_run_retest_cli(args.target, target_path, args))

    explicit_skills = any(arg == "--skills" or arg.startswith("--skills=") for arg in sys.argv[1:])
    if (
        args.ci_gate
        and not args.validate
        and not args.deep_recon
        and not args.resume
        and not args.dry_run
        and not explicit_skills
    ):
        sys.exit(_run_ci_gate_cli(args.target, target_path, args))

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
        if args.validate:
            print("   Validation: enabled (Phase 1 ExploitValidator)")
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

    # Fail fast when there is no configured provider. The orchestrator performs
    # a live connection probe before it makes any request to the target.
    # Allow unit tests that monkeypatch HackbotOrchestrator with a DummyOrchestrator
    # (lacking _model_preflight) to exercise CLI wiring offline.
    llm_client = LLMClient(provider="auto")
    if hasattr(HackbotOrchestrator, "_model_preflight") and not llm_client.is_available():
        print("\n❌ Scan blocked: no LLM provider is configured. Configure a provider and API key, then test the connection.", file=sys.stderr)
        sys.exit(2)

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
        if "validate_candidates" in orch_params or has_varkw:
            orchestrator_kwargs["validate_candidates"] = args.validate
    except (TypeError, ValueError):
        orchestrator_kwargs["max_subagents"] = args.max_subagents
        if args.resume is not None:
            orchestrator_kwargs["resume_run_id"] = args.resume
        if args.proxy is not None:
            orchestrator_kwargs["proxy"] = args.proxy
        if args.validate:
            orchestrator_kwargs["validate_candidates"] = args.validate

    orchestrator = HackbotOrchestrator(**orchestrator_kwargs)
    if getattr(orchestrator, "runner", None) is not None:
        orchestrator.runner.sandbox_mode = args.sandbox
        orchestrator.runner.max_subagents = args.max_subagents

    oob_server = None
    if args.oob_listen and not os.environ.get("MOROS_OOB_URL"):
        try:
            from oob_server import OOBServer
            oob_server = OOBServer(host="127.0.0.1", port=0, log_dir=target_path / "output" / "logs")
            oob_server.start()
            listen_url = oob_server.base_url
            os.environ["MOROS_OOB_URL"] = listen_url
            os.environ["MOROS_CALLBACK_URL"] = listen_url
            print(f"   📡 Local OOB Callback Listener active: {listen_url}")
        except Exception as exc:
            print(f"   ⚠️  Could not start local OOB listener: {exc}")

    scan_started_at = time.time()
    try:
        result = orchestrator.run()
        if oob_server is not None:
            token_hits = []
            for tok in oob_server.list_tokens():
                token_hits.extend(oob_server.poll_callbacks(tok))
            unmatched_hits = oob_server.unmatched_callbacks()
            summaries = oob_server.summarize_findings()
            total_hits = len(token_hits) + len(unmatched_hits)
            if total_hits or summaries:
                print(
                    f"\n   📡 OOB Listener captured {total_hits} callback(s) "
                    f"({len(summaries)} correlated finding(s)) during scan."
                )
        if orchestrator.cost_tracker.get_running_total().get("total_calls", 0) > 0:
            print("\n" + orchestrator.cost_tracker.format_human_summary())
        if result and result.get("status") == "BLOCKED_SCOPE":
            print("\n🛑 Scan stopped because a request or redirect violated the saved scope policy.")
            sys.exit(3)
        if result and result.get("status") == "FAILED":
            sys.exit(1)
        if args.ci_gate:
            sys.exit(_run_ci_gate_cli(args.target, target_path, args))
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
