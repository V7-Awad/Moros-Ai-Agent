#!/usr/bin/env python3
"""
Moros AI Agent — Web Dashboard Server
Native Moros AI operations center and real-time security telemetry viewer.

Provides a local web server and REST API for:
- Managing assessment targets & scope compliance
- Monitoring multi-agent skill coordination in real-time
- Inspecting security findings, PoC curl commands, and evidence
- Handling human-in-the-loop (HITL) checkpoint approvals
- Streaming live tool logs & terminal output
- Viewing and exporting conglomerated penetration testing reports
"""

import hashlib
import json
import logging
import mimetypes
import os
import re
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from socketserver import ThreadingMixIn

PROJECT_ROOT = Path(__file__).parent.parent.resolve()
STATIC_DIR = Path(__file__).parent / "static"
TARGETS_DIR = PROJECT_ROOT / "targets"
SKILLS_DIR = PROJECT_ROOT / "skills"
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tools.conversation_store import ConversationStore, safe_agent_name
from tools.llm_client import LLMClient
from tools.checkpoint_manager import CheckpointManager
from tools.run_manager import RunManager
from tools.skill_registry import SkillRegistry, CORE_SKILLS

logger = logging.getLogger(__name__)

# List of all 14 skills in dependency order
ALL_SKILLS = [
    "recon-subdomain",
    "api-spec-discovery",
    "js-discover",
    "js-analyze",
    "content-discovery",
    "xss-reflected",
    "xss-stored",
    "xss-dom",
    "xss-blind",
    "ssrf-identify",
    "ssrf-post-exploit",
    "idp-race-condition",
    "auth-password-reset-bruteforce",
    "review-skill",
    "report-conglomeration",
]

# In-memory scan manager
active_scans = {}  # target -> {thread, status, logs, start_time, pid}


def is_valid_discord_webhook_url(value):
    try:
        parsed = urllib.parse.urlsplit(value)
        return (
            parsed.scheme == "https"
            and parsed.hostname in {"discord.com", "discordapp.com"}
            and parsed.port in (None, 443)
            and not parsed.username
            and not parsed.password
            and not parsed.query
            and not parsed.fragment
            and re.fullmatch(r"/api/webhooks/\d+/[A-Za-z0-9._-]+", parsed.path) is not None
        )
    except (TypeError, ValueError):
        return False


def send_discord_scan_summary(target, status):
    webhook_url = os.environ.get("DISCORD_WEBHOOK_URL", "").strip()
    if not webhook_url or not is_valid_discord_webhook_url(webhook_url):
        return "not configured"

    report_dir = TARGETS_DIR / target / "output" / "report"
    report_data = {}
    if report_dir.is_dir():
        report_files = sorted(report_dir.glob("hackbot-report-*.json"), key=lambda path: path.stat().st_mtime, reverse=True)
        if report_files:
            try:
                report_data = json.loads(report_files[0].read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                report_data = {}

    summary = report_data.get("summary", {}) if isinstance(report_data, dict) else {}
    findings = report_data.get("findings", []) if isinstance(report_data, dict) else []
    if not isinstance(findings, list):
        findings = []

    lines = [
        "**Moros AI scan finished**",
        f"Target: `{target}`",
        f"Status: `{status}`",
        f"Triage items: {summary.get('triage_items', len(findings))}",
        f"Validated: {summary.get('validated_findings', 0)} · Pending review: {summary.get('unverified_candidates', len(findings))}",
    ]
    if findings:
        lines.append("Top results (titles and severity only):")
        for finding in findings[:8]:
            if not isinstance(finding, dict):
                continue
            title = re.sub(r"[\r\n`*_~|<>]", " ", str(finding.get("title", finding.get("type", "Finding"))))
            severity = re.sub(r"[\r\n`*_~|<>]", " ", str(finding.get("severity", "Unassessed")))
            validation = str(finding.get("validation_status", "unverified"))
            lines.append(f"• {severity[:48]} — {title[:120]} ({validation[:32]})")

    content = "\n".join(lines)
    if len(content) > 1900:
        content = content[:1890] + "..."
    payload = json.dumps({"content": content, "allowed_mentions": {"parse": []}}).encode("utf-8")
    request = urllib.request.Request(
        webhook_url,
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "Moros-AI-Scan-Notifier"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            response.read(1)
        return "sent"
    except urllib.error.HTTPError as exc:
        return f"HTTP {exc.code}"
    except Exception:
        return "unavailable"


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class DashboardHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Mute standard noisy HTTP logging, keep terminal clean
        pass

    def send_json(self, data, status=200):
        body = json.dumps(data, indent=2, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_error_json(self, message, status=400):
        self.send_json({"error": message, "status": "error"}, status=status)

    def do_OPTIONS(self):
        self.send_error_json("Cross-origin requests are not supported", status=405)

    def _is_local_browser_request(self):
        local_names = {"127.0.0.1", "::1", "localhost"}
        host = self.headers.get("Host", "").rsplit(":", 1)[0].strip("[]").lower()
        origin = self.headers.get("Origin")
        if host not in local_names:
            return False
        if origin:
            origin_host = urllib.parse.urlparse(origin).hostname
            if (origin_host or "").lower() not in local_names:
                return False
        return True

    def do_GET(self):
        if not self._is_local_browser_request():
            self.send_error_json("Dashboard is restricted to local browser requests", status=403)
            return
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        # REST API Endpoints
        if path.startswith("/api/"):
            self.handle_api_get(path, query)
            return

        # Static file serving
        self.handle_static_get(path)

    def do_POST(self):
        if not self._is_local_browser_request():
            self.send_error_json("Dashboard is restricted to local browser requests", status=403)
            return
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        try:
            content_length = int(self.headers.get("Content-Length", 0))
        except (TypeError, ValueError):
            self.send_error_json("Invalid Content-Length", status=400)
            return
        if content_length < 0 or content_length > 1_000_000:
            self.send_error_json("Request body is too large", status=413)
            return
        body_bytes = self.rfile.read(content_length) if content_length > 0 else b"{}"

        try:
            body_json = json.loads(body_bytes.decode("utf-8")) if body_bytes else {}
        except Exception:
            body_json = {}

        if path.startswith("/api/"):
            self.handle_api_post(path, body_json)
            return

        self.send_error_json("Not Found", status=404)

    def handle_static_get(self, path):
        if path in ["", "/", "/index.html"]:
            file_path = STATIC_DIR / "index.html"
        else:
            rel = path.lstrip("/")
            file_path = (STATIC_DIR / rel).resolve()
            if not str(file_path).startswith(str(STATIC_DIR)):
                self.send_error_json("Forbidden", status=403)
                return

        if not file_path.exists() or not file_path.is_file():
            # Fallback to index.html for SPA client-side routing
            file_path = STATIC_DIR / "index.html"

        mime, _ = mimetypes.guess_type(str(file_path))
        mime = mime or "application/octet-stream"

        try:
            data = file_path.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except Exception as e:
            self.send_error_json(f"Error reading file: {e}", status=500)

    # ==================== API HANDLERS ====================

    def handle_api_get(self, path, query):
        # 1. System info / prereq
        if path == "/api/system":
            self.send_json(self.get_system_info())
            return

        # 2. List all targets
        if path == "/api/targets":
            self.send_json(self.get_targets_list())
            return

        # 3. Available skills list
        if path == "/api/skills":
            self.send_json(self.get_skills_meta())
            return

        # 4. Target specific endpoints: /api/targets/{target}/...
        target_match = re.match(r"^/api/targets/([^/]+)/?(.*)$", path)
        if target_match:
            target_name = urllib.parse.unquote(target_match.group(1))
            sub = target_match.group(2)

            try:
                from setup import validate_target_name
                validate_target_name(target_name)
            except ValueError:
                self.send_error_json("Invalid target name", status=400)
                return

            target_path = TARGETS_DIR / target_name
            if not target_path.exists():
                self.send_error_json(f"Target '{target_name}' not found", status=404)
                return

            if sub in ["", "summary"]:
                self.send_json(self.get_target_summary(target_name))
                return
            elif sub == "skills":
                self.send_json(self.get_target_skills_status(target_name))
                return
            elif sub == "findings":
                self.send_json(self.get_target_findings(target_name))
                return
            elif sub == "endpoints":
                self.send_json(self.get_target_endpoints(target_name))
                return
            elif sub == "tech":
                self.send_json(self.get_target_tech_fingerprint(target_name))
                return
            elif sub == "logs":
                self.send_json(self.get_target_logs(target_name, query.get("file", [None])[0]))
                return
            elif sub == "checkpoints":
                self.send_json(self.get_target_checkpoints(target_name))
                return
            elif sub == "runs":
                rm = RunManager(target_path)
                self.send_json({"target": target_name, "runs": rm.list_runs()})
                return
            elif sub.startswith("runs/"):
                rest = sub[5:]
                rm = RunManager(target_path)
                if "/agents" in rest:
                    run_id = rest.split("/agents")[0].strip("/")
                    self.send_json({"run_id": run_id, "agents": rm.list_agent_sessions(run_id)})
                    return
                run_id = rest
                run_data = rm.get_run(run_id)
                if not run_data:
                    self.send_error_json("Run not found", status=404)
                    return
                self.send_json(run_data)
                return
            elif sub == "conversations":
                agent = query.get("agent", ["coordinator"])[0]
                try:
                    limit = int(query.get("limit", [200])[0])
                except (TypeError, ValueError):
                    limit = 200
                store = ConversationStore(target_path)
                messages = store.read(agent, limit)
                agent_safe = safe_agent_name(agent)
                if not messages:
                    welcome_text = self.get_agent_greeting(target_name, agent_safe)
                    messages = [{
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "agent": agent_safe,
                        "role": "assistant",
                        "content": welcome_text,
                        "source": "greeting"
                    }]
                self.send_json({
                    "target": target_name,
                    "agent": agent_safe,
                    "agents": store.list_agents(),
                    "roster": self.get_subagent_roster(target_name),
                    "messages": messages,
                })
                return
            elif sub == "report":
                self.send_json(self.get_target_report(target_name))
                return
            elif sub == "sarif":
                self.send_json(self.get_target_sarif(target_name))
                return

        # 5. Scan status
        if path == "/api/scan/status":
            target = query.get("target", [None])[0]
            self.send_json(self.get_scan_status(target))
            return

        # 6. Active runs across targets
        if path == "/api/runs/active":
            active_runs = []
            if TARGETS_DIR.exists():
                for td in TARGETS_DIR.iterdir():
                    if td.is_dir():
                        rm = RunManager(td)
                        for r in rm.list_runs():
                            if r.get("status") == "running":
                                active_runs.append(r)
            self.send_json({"active_runs": active_runs})
            return

        # 7. Current LLM configuration
        if path == "/api/config/llm":
            self.send_json(self.get_llm_config())
            return
        if path == "/api/config/notifications":
            self.send_json(self.get_notification_config())
            return

        self.send_error_json("Unknown API endpoint", status=404)

    def handle_api_post(self, path, body):
        # 1. Create target
        if path == "/api/targets/create":
            domain = str(body.get("domain", "")).strip()
            if not domain:
                self.send_error_json("Domain name is required")
                return

            # Invoke setup script to create target folder
            from setup import init_target
            try:
                from setup import validate_target_name
                validate_target_name(domain)
                init_target(domain)
                self.send_json({"status": "success", "message": f"Target {domain} created", "target": domain})
            except ValueError as e:
                self.send_error_json(str(e), status=400)
            except Exception as e:
                self.send_error_json(f"Failed to create target: {e}")
            return

        # 2. Start Scan
        if path == "/api/scan/start":
            target = str(body.get("target", "")).strip()
            skills = body.get("skills", "all")
            models = body.get("models", "default")
            dry_run = body.get("dry_run", False)
            scan_mode = body.get("scan_mode", "quick")

            if not target:
                self.send_error_json("Target is required")
                return

            try:
                from setup import validate_target_name
                validate_target_name(target)
            except ValueError:
                self.send_error_json("Invalid target name", status=400)
                return

            try:
                res = self.start_scan_job(target, skills, models, dry_run, scan_mode=scan_mode)
                self.send_json(res)
            except Exception as exc:
                logger.exception("Failed to enqueue dashboard scan for %s", target)
                self.send_json({"status": "error", "message": f"Could not start scan ({type(exc).__name__})."}, status=500)
            return

        # 3. Stop Scan
        if path == "/api/scan/stop":
            target = str(body.get("target", "")).strip()
            try:
                from setup import validate_target_name
                validate_target_name(target)
            except ValueError:
                self.send_error_json("Invalid target name", status=400)
                return
            res = self.stop_scan_job(target)
            self.send_json(res)
            return

        # 4. Checkpoint approval/rejection
        if path == "/api/checkpoints/action":
            target = str(body.get("target", "")).strip()
            try:
                from setup import validate_target_name
                validate_target_name(target)
            except ValueError:
                self.send_error_json("Invalid target name", status=400)
                return
            checkpoint_id = body.get("checkpoint_id", "")
            action = body.get("action", "")  # "approve" or "reject"
            notes = body.get("notes", "")

            res = self.handle_checkpoint_decision(target, checkpoint_id, action, notes)
            self.send_json(res)
            return

        # 5. Coordinator / sub-agent conversation message
        if path == "/api/conversations/chat":
            target = str(body.get("target", "")).strip()
            agent = safe_agent_name(body.get("agent", "coordinator"))
            message = str(body.get("message", "")).strip()
            if not target or not message:
                self.send_error_json("Target and message are required")
                return
            try:
                from setup import validate_target_name
                validate_target_name(target)
            except ValueError:
                self.send_error_json("Invalid target name", status=400)
                return
            target_path = TARGETS_DIR / target
            if not target_path.is_dir():
                self.send_error_json(f"Target '{target}' not found", status=404)
                return
            if len(message) > 60000:
                self.send_error_json("Message is too long (max 60000 characters)")
                return

            res = self.execute_subagent_chat(target, agent, message)
            self.send_json(res)
            return

        # 6. Save LLM Configuration directly from Dashboard
        if path == "/api/config/llm":
            res = self.save_llm_config(body)
            self.send_json(res)
            return

        # 7. Test LLM Connection from Dashboard
        if path == "/api/config/llm/test":
            res = self.test_llm_config(body)
            self.send_json(res)
            return

        if path == "/api/config/notifications":
            res = self.save_notification_config(body)
            self.send_json(res, status=200 if res.get("status") == "success" else 400)
            return

        # 8. Custom Skills Engine: Create Custom Skill
        if path == "/api/skills/create":
            skill_id = str(body.get("id", "")).strip()
            title = str(body.get("title", "")).strip()
            description = str(body.get("description", "")).strip()
            category = str(body.get("category", "Custom Security")).strip()
            checklist = body.get("checklist", [])
            methodology = str(body.get("methodology", "")).strip()
            if not skill_id or not title:
                self.send_error_json("Skill ID and Title are required", status=400)
                return
            try:
                registry = SkillRegistry()
                created = registry.create_custom_skill(
                    skill_id=skill_id,
                    title=title,
                    description=description,
                    category=category,
                    checklist=checklist,
                    methodology=methodology
                )
                self.send_json({"status": "success", "message": f"Custom skill '{skill_id}' registered successfully", "skill": created})
            except Exception as e:
                self.send_error_json(str(e), status=400)
            return

        # 9. Custom Skills Engine: Delete Custom Skill
        if path == "/api/skills/delete":
            skill_id = str(body.get("id", "")).strip()
            if not skill_id:
                self.send_error_json("Skill ID is required", status=400)
                return
            try:
                registry = SkillRegistry()
                success = registry.delete_custom_skill(skill_id)
                if success:
                    self.send_json({"status": "success", "message": f"Skill '{skill_id}' deleted successfully"})
                else:
                    self.send_error_json(f"Skill '{skill_id}' not found", status=404)
            except Exception as e:
                self.send_error_json(str(e), status=400)
            return

        self.send_error_json("Unknown API endpoint", status=404)

    def get_llm_config(self):
        client = LLMClient(provider="auto")
        key = client.api_key or ""
        return {
            "provider": client.provider,
            "model": client.model,
            "base_url": client.base_url or "",
            "is_available": client.is_available(),
            "has_api_key": bool(key),
        }

    def get_notification_config(self):
        return {"has_discord_webhook": bool(os.environ.get("DISCORD_WEBHOOK_URL", "").strip())}

    def save_notification_config(self, body):
        webhook_url = str(body.get("discord_webhook_url", "")).strip()
        if not is_valid_discord_webhook_url(webhook_url):
            return {"status": "error", "message": "Enter a valid HTTPS Discord webhook URL."}

        env_file = PROJECT_ROOT / ".env"
        try:
            lines = env_file.read_text(encoding="utf-8").splitlines() if env_file.is_file() else []
            lines = [line for line in lines if not line.strip().startswith("DISCORD_WEBHOOK_URL=")]
            lines.append(f"DISCORD_WEBHOOK_URL={webhook_url}")
            env_file.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
        except OSError:
            logger.exception("Failed to save Discord notification settings")
            return {"status": "error", "message": "Could not save Discord settings locally."}

        os.environ["DISCORD_WEBHOOK_URL"] = webhook_url
        return {"status": "success", "message": "Discord scan notifications are configured."}

    def save_llm_config(self, body):
        provider = str(body.get("provider", "openai")).strip().lower()
        model = str(body.get("model", "")).strip()
        api_key = str(body.get("api_key", "")).strip()
        base_url = str(body.get("base_url", "")).strip()

        env_file = PROJECT_ROOT / ".env"
        env_lines = []
        if env_file.is_file():
            try:
                env_lines = env_file.read_text(encoding="utf-8").splitlines()
            except Exception:
                pass

        env_dict = {}
        for line in env_lines:
            line_str = line.strip()
            if line_str and not line_str.startswith("#") and "=" in line_str:
                k, v = line_str.split("=", 1)
                env_dict[k.strip()] = v.strip().strip('"').strip("'")

        # Map according to provider
        env_dict["MOROS_LLM_PROVIDER"] = provider
        if provider == "deepseek":
            if api_key:
                env_dict["DEEPSEEK_API_KEY"] = api_key
            env_dict["DEEPSEEK_MODEL"] = model or "deepseek-chat"
        elif provider == "groq":
            if api_key:
                env_dict["GROQ_API_KEY"] = api_key
            env_dict["GROQ_MODEL"] = model or "llama-3.3-70b-versatile"
        elif provider == "anthropic":
            if api_key:
                env_dict["ANTHROPIC_API_KEY"] = api_key
            env_dict["ANTHROPIC_MODEL"] = model or "claude-3-5-sonnet-20241022"
        elif provider == "gemini":
            if api_key:
                env_dict["GEMINI_API_KEY"] = api_key
            env_dict["GEMINI_MODEL"] = model or "gemini-3.8-flash"
        elif provider == "openrouter":
            if api_key:
                env_dict["OPENROUTER_API_KEY"] = api_key
            env_dict["OPENROUTER_MODEL"] = model or "meta-llama/llama-3.1-8b-instruct"
        elif provider in ["xai", "grok"]:
            if api_key:
                env_dict["XAI_API_KEY"] = api_key
            env_dict["XAI_MODEL"] = model or "grok-2-latest"
        elif provider == "mistral":
            if api_key:
                env_dict["MISTRAL_API_KEY"] = api_key
            env_dict["MISTRAL_MODEL"] = model or "mistral-large-latest"
        elif provider == "together":
            if api_key:
                env_dict["TOGETHER_API_KEY"] = api_key
            env_dict["TOGETHER_MODEL"] = model or "meta-llama/Llama-3.3-70B-Instruct-Turbo"
        elif provider == "cerebras":
            if api_key:
                env_dict["CEREBRAS_API_KEY"] = api_key
            env_dict["CEREBRAS_MODEL"] = model or "llama3.3-70b"
        elif provider == "sambanova":
            if api_key:
                env_dict["SAMBANOVA_API_KEY"] = api_key
            env_dict["SAMBANOVA_MODEL"] = model or "Meta-Llama-3.3-70B-Instruct"
        elif provider == "fireworks":
            if api_key:
                env_dict["FIREWORKS_API_KEY"] = api_key
            env_dict["FIREWORKS_MODEL"] = model or "accounts/fireworks/models/llama-v3p3-70b-instruct"
        elif provider == "perplexity":
            if api_key:
                env_dict["PERPLEXITY_API_KEY"] = api_key
            env_dict["PERPLEXITY_MODEL"] = model or "sonar-pro"
        elif provider == "cohere":
            if api_key:
                env_dict["COHERE_API_KEY"] = api_key
            env_dict["COHERE_MODEL"] = model or "command-r-plus"
        elif provider == "ollama":
            env_dict["OLLAMA_BASE_URL"] = base_url or "http://localhost:11434"
            env_dict["OLLAMA_MODEL"] = model or "llama3"
        elif provider == "custom" or base_url:
            if base_url:
                env_dict["OPENAI_BASE_URL"] = base_url
            if api_key:
                env_dict["OPENAI_API_KEY"] = api_key
            env_dict["OPENAI_MODEL"] = model or "default"
        else:  # standard openai or any other provider
            if api_key:
                env_dict["OPENAI_API_KEY"] = api_key
            env_dict["OPENAI_MODEL"] = model or "gpt-4o-mini"
            if base_url:
                env_dict["OPENAI_BASE_URL"] = base_url

        # Apply to live os.environ
        for k, v in env_dict.items():
            os.environ[k] = v

        # Write back to .env
        out_content = "# Moros AI Environment Configuration (Saved from Dashboard)\n"
        for k, v in env_dict.items():
            out_content += f"{k}={v}\n"
        env_file.write_text(out_content, encoding="utf-8")

        return {
            "status": "success",
            "message": "LLM configuration saved to .env and activated successfully",
            "config": self.get_llm_config()
        }

    def test_llm_config(self, body):
        provider = str(body.get("provider", "openai")).strip().lower()
        model = str(body.get("model", "")).strip() or None
        api_key = str(body.get("api_key", "")).strip() or None
        base_url = str(body.get("base_url", "")).strip() or None

        try:
            client = LLMClient(provider=provider, model=model, api_key=api_key, base_url=base_url)
            if not client.is_available():
                return {"status": "error", "message": "LLM credentials missing or incomplete"}
            resp = client.complete("Ping. Respond with 'PONG' only.", max_tokens=15)
            if resp:
                return {"status": "success", "message": f"Connected to {client.provider}/{client.model}! Response: {resp.strip()}"}
            else:
                detail = client.last_error or f"{client.provider} returned an empty response"
                return {"status": "error", "message": f"Connection failed: {detail}"}
        except Exception as e:
            return {"status": "error", "message": f"Connection test failed: {e}"}

    # ==================== DATA COLLECTORS ====================

    def get_system_info(self):
        playwright_ok = False
        try:
            import playwright
            playwright_ok = True
        except ImportError:
            pass

        return {
            "name": "Moros AI Agent Dashboard",
            "version": "1.0.0",
            "python_version": sys.version,
            "playwright_installed": playwright_ok,
            "active_scans_count": len(active_scans),
            "targets_count": len(list(TARGETS_DIR.glob("*"))) if TARGETS_DIR.exists() else 0,
            "all_skills_count": len(SkillRegistry().list_skills()),
        }

    def get_targets_list(self):
        targets = []
        if not TARGETS_DIR.exists():
            return targets

        for d in TARGETS_DIR.iterdir():
            if d.is_dir():
                scope_files = list(d.glob("scope-of-work.*"))
                has_scope = len(scope_files) > 0

                findings = self.get_target_findings(d.name)
                sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0, "UNASSESSED": 0}
                for f in findings:
                    sev = f.get("severity_level", "INFO")
                    sev_counts[sev] = sev_counts.get(sev, 0) + 1

                is_scanning = d.name in active_scans and active_scans[d.name]["status"] == "running"

                targets.append({
                    "name": d.name,
                    "has_scope": has_scope,
                    "scope_file": scope_files[0].name if has_scope else None,
                    "findings_total": len(findings),
                    "severities": sev_counts,
                    "is_scanning": is_scanning,
                    "created_at": datetime.fromtimestamp(d.stat().st_ctime, tz=timezone.utc).isoformat(),
                })

        return sorted(targets, key=lambda x: x["name"])

    def get_skills_meta(self):
        skills = SkillRegistry().list_skills()
        for s in skills:
            s["name"] = s.get("title", s["id"])
            s["has_definition"] = True
        return skills

    def get_target_summary(self, target_name):
        target_dir = TARGETS_DIR / target_name
        output_dir = target_dir / "output"

        scope_files = list(target_dir.glob("scope-of-work.*"))
        has_scope = len(scope_files) > 0

        findings = self.get_target_findings(target_name)
        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0, "UNASSESSED": 0}
        for f in findings:
            sev = f.get("severity_level", "INFO")
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        # Read tech fingerprint if present
        tech_file = output_dir / "js" / "tech-fingerprint.json"
        tech_data = {}
        if tech_file.exists():
            try:
                tech_data = json.loads(tech_file.read_text(encoding="utf-8"))
            except Exception:
                pass

        # Read endpoints count from JavaScript and OpenAPI inventories.
        endpoints_count = self.get_target_endpoints(target_name).get("total_endpoints", 0)

        # Read JS files count
        raw_js_dir = output_dir / "js" / "raw"
        js_count = len(list(raw_js_dir.rglob("*.js"))) if raw_js_dir.exists() else 0

        # Subdomains count
        subdomains_file = output_dir / "recon" / "subdomains-all.txt"
        subdomain_count = 0
        if subdomains_file.exists():
            subdomain_count = len([line for line in subdomains_file.read_text().splitlines() if line.strip()])

        return {
            "target": target_name,
            "has_scope": has_scope,
            "scope_file": scope_files[0].name if has_scope else None,
            "total_findings": len(findings),
            "severities": sev_counts,
            "total_endpoints": endpoints_count,
            "total_js_files": js_count,
            "total_subdomains": subdomain_count,
            "tech_fingerprint": tech_data,
            "is_scanning": target_name in active_scans and active_scans[target_name]["status"] == "running",
        }

    def get_agent_greeting(self, target_name, agent):
        greetings = {
            "coordinator": (
                f"ðŸ›¡ï¸ **Moros Master Coordinator â€” Active**\n\n"
                f"Target workspace: `{target_name}` | Status: `READY`\n\n"
                "I orchestrate multi-agent operations, attack trees, and skill dispatch. "
                "You can command me to run assessments, verify candidate findings, or coordinate sub-agents."
            ),
            "recon-agent": (
                f"ðŸŒ **Reconnaissance Specialist Agent â€” Active**\n\n"
                f"Target workspace: `{target_name}` | Status: `READY`\n\n"
                "Specialized in subdomain enumeration, DNS resolution, alive checks, and Wayback scraping.\n\n"
                "**Directives supported:**\n"
                "- `Scan subdomains` / `Run recon`\n"
                "- `Check alive hosts`\n"
                "- `Scrape Wayback URLs`\n"
                "- `Summarize mapped attack surface`"
            ),
            "js-analyzer": (
                f"âš¡ **JavaScript & API Hunter Agent â€” Active**\n\n"
                f"Target workspace: `{target_name}` | Status: `READY`\n\n"
                "Specialized in headless browser crawling, source map recovery, AST route extraction, and credential pattern detection.\n\n"
                "**Directives supported:**\n"
                "- `Analyze JavaScript files`\n"
                "- `Extract API endpoints`\n"
                "- `Scan for exposed secrets and tokens`\n"
                "- `Audit client-side source maps`"
            ),
            "xss-specialist": (
                f"ðŸŽ¯ **XSS & Client-Side Specialist Agent â€” Active**\n\n"
                f"Target workspace: `{target_name}` | Status: `READY`\n\n"
                "Specialized in DOM, Reflected, Stored, and Blind XSS payload injection with context-escape analysis.\n\n"
                "**Directives supported:**\n"
                "- `Test reflected parameters`\n"
                "- `Trace DOM sinks and sources`\n"
                "- `Generate context-tailored XSS payloads`"
            ),
            "ssrf-specialist": (
                f"â˜ï¸ **SSRF & Cloud Metadata Hunter Agent â€” Active**\n\n"
                f"Target workspace: `{target_name}` | Status: `READY`\n\n"
                "Specialized in SSRF identification, out-of-band canary interaction, and AWS/GCP/Azure instance metadata pivots.\n\n"
                "**Directives supported:**\n"
                "- `Audit SSRF vectors`\n"
                "- `Probe cloud metadata endpoints`\n"
                "- `Inspect webhook and callback parameters`"
            ),
            "auth-race-specialist": (
                f"ðŸ”‘ **Auth & Race Condition Agent â€” Active**\n\n"
                f"Target workspace: `{target_name}` | Status: `READY`\n\n"
                "Specialized in IdP multi-threaded race conditions, token collisions, and password reset rate-limit auditing.\n\n"
                "**Directives supported:**\n"
                "- `Audit multi-threaded race conditions`\n"
                "- `Test rate limit bypass vectors`\n"
                "- `Evaluate OAuth/SAML state handling`"
            ),
            "review-verifier": (
                f"ðŸ” **Review-Skill Verifier Gate â€” Active**\n\n"
                f"Target workspace: `{target_name}` | Status: `READY`\n\n"
                "Specialized in strict evidence enforcement, independent cURL reproduction replay, and false-positive elimination.\n\n"
                "**Directives supported:**\n"
                "- `Verify candidate findings`\n"
                "- `Replay reproduction cURLs`\n"
                "- `Enforce verification proof standards`"
            ),
            "report-specialist": (
                f"ðŸ“„ **Reporting & Synthesis Agent â€” Active**\n\n"
                f"Target workspace: `{target_name}` | Status: `READY`\n\n"
                "Specialized in OASIS SARIF 2.1.0 deliverable compilation, CVSS v3.1 scoring, and executive markdown synthesis.\n\n"
                "**Directives supported:**\n"
                "- `Generate SARIF 2.1.0 report`\n"
                "- `Compile executive assessment report`\n"
                "- `Export findings for GitHub Code Scanning`"
            ),
        }
        return greetings.get(agent, (
            f"ðŸ›¡ï¸ **Moros Specialist Agent â€” {agent}**\n\n"
            f"Target workspace: `{target_name}` | Status: `READY`\n\n"
            "Ready to execute operational directives for authorized assessment scope."
        ))

    def get_subagent_roster(self, target_name):
        target_path = TARGETS_DIR / target_name
        store = ConversationStore(target_path)
        scan_state = active_scans.get(target_name, {}).get("status", "idle")
        llm_available = LLMClient(provider="auto").is_available()

        def _agent_status(agent_id):
            if scan_state in {"starting", "running"}:
                return "RUNNING" if agent_id == "coordinator" else "QUEUED"
            if scan_state in {"stopping", "stopped", "failed"}:
                return scan_state.upper()
            if agent_id == "coordinator" and not llm_available:
                return "LLM OFFLINE"
            return "READY"

        roster = [
            {
                "id": "coordinator",
                "name": "Coordinator Master",
                "role": "Attack tree orchestration, plan dispatch & multi-agent planner",
                "tier": "Coordinator / Configured LLM",
                "status": _agent_status("coordinator"),
                "icon": "shield-alert",
                "messages_count": len(store.read("coordinator", 200)),
            },
            {
                "id": "recon-agent",
                "name": "Reconnaissance Specialist",
                "role": "Subdomain discovery, asset mapping, DNS brute & Wayback fetch",
                "tier": "Active Tooling (Subdomain / DNS / Alive)",
                "status": _agent_status("recon-agent"),
                "icon": "globe",
                "messages_count": len(store.read("recon-agent", 200)),
            },
            {
                "id": "js-analyzer",
                "name": "JavaScript & API Hunter",
                "role": "Headless browser spider, source map unminifier, AST parser & secret scanner",
                "tier": "Active Tooling (AST / Crawler / Regex)",
                "status": _agent_status("js-analyzer"),
                "icon": "code",
                "messages_count": len(store.read("js-analyzer", 200)),
            },
            {
                "id": "xss-specialist",
                "name": "XSS & Client-Side Specialist",
                "role": "DOM, Reflected, Stored, and Blind XSS payload injection & context escape",
                "tier": "Active Tooling (Reflection / Sink Tracer)",
                "status": _agent_status("xss-specialist"),
                "icon": "zap",
                "messages_count": len(store.read("xss-specialist", 200)),
            },
            {
                "id": "ssrf-specialist",
                "name": "SSRF & Cloud Metadata Hunter",
                "role": "SSRF identification, out-of-band canary interaction, AWS/GCP/K8s pivot",
                "tier": "Active Tooling (OOB Canary / Metadata)",
                "status": _agent_status("ssrf-specialist"),
                "icon": "cloud-lightning",
                "messages_count": len(store.read("ssrf-specialist", 200)),
            },
            {
                "id": "auth-race-specialist",
                "name": "Auth & Race Condition Agent",
                "role": "IdP multi-threaded race conditions & password reset rate-limit audit",
                "tier": "Active Tooling (Concurrent Worker Pool)",
                "status": _agent_status("auth-race-specialist"),
                "icon": "key",
                "messages_count": len(store.read("auth-race-specialist", 200)),
            },
            {
                "id": "review-verifier",
                "name": "Review-Skill Verifier Gate",
                "role": "False-positive pruning, independent cURL replay & proof verification",
                "tier": "Verification Gate (Deterministic Proofs)",
                "status": _agent_status("review-verifier"),
                "icon": "check-circle",
                "messages_count": len(store.read("review-verifier", 200)),
            },
            {
                "id": "report-specialist",
                "name": "Reporting & Synthesis Agent",
                "role": "Executive deliverable synthesis, CVSS scoring & OASIS SARIF 2.1.0",
                "tier": "SARIF 2.1.0 & Executive Exporter",
                "status": _agent_status("report-specialist"),
                "icon": "file-text",
                "messages_count": len(store.read("report-specialist", 200)),
            },
        ]
        return roster

    def get_target_sarif(self, target_name):
        target_path = TARGETS_DIR / target_name
        sarif_file = target_path / "output" / "report" / "findings.sarif"
        if sarif_file.exists():
            try:
                return json.loads(sarif_file.read_text(encoding="utf-8"))
            except Exception:
                pass
        from tools.sarif_exporter import build_sarif_report
        findings = self.get_target_findings(target_name)
        return build_sarif_report(findings, target=target_name)

    def execute_subagent_chat(self, target: str, agent: str, message: str) -> Dict[str, Any]:
        target_path = TARGETS_DIR / target
        store = ConversationStore(target_path)
        store.append(agent, "user", message, source="dashboard")

        # Track session in RunManager
        rm = RunManager(target_path)
        latest_run = rm.get_latest_or_active_run()
        if not latest_run:
            latest_run = rm.create_run(target=target, skills=[agent], dry_run=False, models="interactive")
        run_id = latest_run["run_id"]
        rm.register_agent_session(run_id, agent_id=agent, skill=agent, status="running")
        rm.log_event(run_id, "agent_chat_directive", {"agent": agent, "directive": message[:200]})

        # Check for tools execution
        from tools.agent_runtime import AgentContext, AgentResult, AgentRunner, ToolRegistry
        from tools.skill_runner import SkillRunner
        from tools.sarif_exporter import write_sarif_report

        runner = SkillRunner(target=target, target_dir=target_path)
        registry = ToolRegistry()

        def _tool_recon(active: bool = False):
            res = runner.run_recon_subdomain(active_validation=active)
            return f"Recon completed: {res.get('subdomains_found', 0)} subdomains, {res.get('alive_hosts', 0)} alive hosts."

        def _tool_js_analyze():
            res = runner.run_js_analyze()
            return f"JavaScript analysis completed: {res.get('secrets_found', 0)} secrets, {res.get('endpoints_found', 0)} endpoints."

        def _tool_review():
            res = runner.run_review_skill("all")
            return f"Review gate executed: {res.get('overall_status', 'SUCCESS')}"

        def _tool_sarif():
            findings = self.get_target_findings(target)
            out_file = target_path / "output" / "report" / "findings.sarif"
            write_sarif_report(out_file, findings, target=target)
            return f"SARIF 2.1.0 written to {out_file} ({len(findings)} findings)"

        def _tool_list_endpoints():
            ep_file = target_path / "output" / "recon" / "endpoints.txt"
            if not ep_file.exists():
                ep_file = target_path / "output" / "content" / "discovered-endpoints.txt"
            if ep_file.exists():
                lines = [line.strip() for line in ep_file.read_text(encoding="utf-8").splitlines() if line.strip()]
                return lines[:30]
            return []

        def _tool_list_findings():
            return self.get_target_findings(target)[:20]

        registry.register("run_subdomain_recon", _tool_recon, "Execute subdomain discovery & alive host enumeration", {"active": "bool"})
        registry.register("run_js_analysis", _tool_js_analyze, "Execute headless JavaScript crawling, AST parsing & secret extraction")
        registry.register("run_review_verification", _tool_review, "Execute independent verification gate and false positive pruning")
        registry.register("generate_sarif_report", _tool_sarif, "Generate GitHub Code Scanning compliant SARIF 2.1.0 deliverable")
        registry.register("list_endpoints", _tool_list_endpoints, "Retrieve discovered HTTP endpoints for the target")
        registry.register("list_findings", _tool_list_findings, "Retrieve security findings and candidate triage items")

        client = LLMClient(provider="auto")
        source = "llm"
        answer = None

        if client.is_available():
            context = AgentContext(
                target=target,
                target_dir=target_path,
                skill=agent,
                run_id=run_id,
            )
            system_prompt = (
                f"You are the Moros AI specialist agent '{agent}' assessing target '{target}'. "
                "You have direct execution access to target workspace tools and artifacts. "
                "Stay strictly within authorization scope. When directed to run actions, invoke the appropriate tool. "
                "Provide crisp, elite technical pentester output with cURL reproductions and remediation."
            )
            try:
                agent_runner = AgentRunner(llm_client=client)
                result = agent_runner.run(context, registry, system_prompt, message)
                if result.status == "completed" and result.summary:
                    answer = result.summary
                    source = "agent_runner"
            except Exception as e:
                logger.warning(f"AgentRunner execution failed: {e}")

        if not answer:
            # Deterministic specialist directive handling (offline / LLM unavailable)
            msg_lower = message.lower()
            if any(k in msg_lower for k in ["recon", "subdomain", "enumerate", "alive hosts"]):
                res = runner.run_recon_subdomain(active_validation=False)
                sub_count = res.get("subdomains_found", 0)
                alive_count = res.get("alive_hosts", 0)
                sub_file = target_path / "output" / "recon" / "subdomains.txt"
                sample_subs = []
                if sub_file.exists():
                    sample_subs = [s.strip() for s in sub_file.read_text(encoding="utf-8").splitlines() if s.strip()][:8]
                sub_list = "\n".join(f"- `{s}`" for s in sample_subs) if sample_subs else "- None recorded yet"
                answer = (
                    f"ðŸŒ **[RECON-AGENT] Subdomain Enumeration Directive Executed**\n\n"
                    f"Target: `{target}` | Status: `COMPLETED`\n\n"
                    f"### Key Metrics\n"
                    f"- **Total Subdomains Discovered:** `{sub_count}`\n"
                    f"- **Alive Web Endpoints:** `{alive_count}`\n"
                    f"- **Workspace Output:** `targets/{target}/output/recon/`\n\n"
                    f"### Discovered Subdomain Sample\n{sub_list}\n\n"
                    f"**Next Action:** Run `run_js_analyze` or test active endpoints for parameter reflection."
                )
                source = "deterministic-execution"
            elif any(k in msg_lower for k in ["js", "javascript", "secret", "token", "source map", "sourcemap", "ast"]):
                res = runner.run_js_analyze()
                sec_count = res.get("secrets_found", 0)
                ep_count = res.get("endpoints_found", 0)
                sec_file = target_path / "output" / "js" / "secrets-findings.json"
                sec_items = []
                if sec_file.exists():
                    try:
                        s_data = json.loads(sec_file.read_text(encoding="utf-8"))
                        sec_items = s_data.get("findings", [])[:5]
                    except Exception:
                        pass
                sec_summary = "\n".join(f"- `{s.get('type')}` in `{s.get('source_file')}` ({s.get('severity')})" for s in sec_items) if sec_items else "- No exposed API keys or tokens identified."
                answer = (
                    f"âš¡ **[JS-ANALYZER] JavaScript & Secret Extraction Executed**\n\n"
                    f"Target: `{target}` | Status: `COMPLETED`\n\n"
                    f"### Key Metrics\n"
                    f"- **Secrets / Credentials Flagged:** `{sec_count}`\n"
                    f"- **Endpoints Extracted via AST:** `{ep_count}`\n"
                    f"- **Workspace Output:** `targets/{target}/output/js/`\n\n"
                    f"### Extracted Secrets\n{sec_summary}\n\n"
                    f"**Next Action:** Validate detected secret patterns against live endpoints or test candidate routes."
                )
                source = "deterministic-execution"
            elif any(k in msg_lower for k in ["sarif", "github", "code scanning", "export", "report"]):
                res = runner.run_report_conglomeration()
                findings_count = res.get("findings_count", 0)
                sarif_path = res.get("sarif_path") or f"targets/{target}/output/report/findings.sarif"
                report_path = res.get("report_path") or f"targets/{target}/output/report/"
                answer = (
                    f"ðŸ“„ **[REPORT-SPECIALIST] Enterprise Deliverables Compiled**\n\n"
                    f"Target: `{target}` | Status: `COMPLETED`\n\n"
                    f"### Export Artifacts\n"
                    f"- **OASIS SARIF 2.1.0:** `{sarif_path}` (Directly uploadable via `github/codeql-action/upload-sarif`)\n"
                    f"- **Executive Deliverable:** `{report_path}`\n"
                    f"- **Total Triage Items Processed:** `{findings_count}`\n\n"
                    f"**CI/CD Integration Hint:**\n"
                    f"```bash\n"
                    f"# Upload to GitHub Code Scanning Alerts\n"
                    f"gh code-scanning upload-sarif --sarif {sarif_path}\n"
                    f"```"
                )
                source = "deterministic-execution"
            elif any(k in msg_lower for k in ["verify", "verification", "review", "proof", "reproduce", "candidate"]):
                res = runner.run_review_skill("all")
                status_str = res.get("overall_status", "SUCCESS")
                answer = (
                    f"ðŸ” **[REVIEW-VERIFIER] Verification Gate Executed**\n\n"
                    f"Target: `{target}` | Status: `{status_str}`\n\n"
                    f"- Evaluated candidate findings against strict evidence gates.\n"
                    f"- Verified reproduction proof standards (independent evidence, cURL validation).\n"
                    f"- Findings without reproducible evidence marked as unverified candidates to eliminate false positives."
                )
                source = "deterministic-execution"
            elif any(k in msg_lower for k in ["endpoint", "endpoints", "routes", "url", "urls"]):
                eps = _tool_list_endpoints()
                ep_text = "\n".join(f"- `{e}`" for e in eps[:15]) if eps else "- No endpoints discovered yet. Run recon or js-analyze first."
                answer = (
                    f"ðŸ›¡ï¸ **[AGENT: {agent.upper()}] Discovered Endpoints Inventory**\n\n"
                    f"Target: `{target}` | Inventory Count: `{len(eps)}`\n\n"
                    f"### Target Routes\n{ep_text}\n\n"
                    f"Directives available: Ask to test specific endpoints or run vulnerability auditing."
                )
                source = "artifact-query"
            elif any(k in msg_lower for k in ["finding", "findings", "vuln", "vulnerabilities", "bug", "status"]):
                findings = self.get_target_findings(target)
                validated = sum(1 for f in findings if f.get("validation_status") == "validated")
                candidates = len(findings) - validated
                f_sample = "\n".join(f"- **{f.get('title')}** â€” `{f.get('severity')}` [{f.get('validation_status')}]" for f in findings[:8]) if findings else "- No findings recorded in workspace."
                answer = (
                    f"ðŸ›¡ï¸ **[AGENT: {agent.upper()}] Workspace Triage Overview**\n\n"
                    f"Target: `{target}` | Total Items: `{len(findings)}` ({validated} validated, {candidates} unverified candidates)\n\n"
                    f"### Key Findings\n{f_sample}\n\n"
                    f"Use `Verify findings` to invoke the verification gate or `Generate SARIF 2.1.0` to compile CI/CD reports."
                )
                source = "artifact-query"
            else:
                summary_data = self.get_target_summary(target)
                endpoints = summary_data.get("total_endpoints", 0)
                findings = summary_data.get("total_findings", 0)
                answer = (
                    f"ðŸ›¡ï¸ **[AGENT: {agent.upper()}] Operational Briefing**\n\n"
                    f"Target: `{target}` | Status: `READY`\n\n"
                    f"I have initialized workspace context for `{target}` with {endpoints} endpoints and {findings} triage items. "
                    f"I am ready to execute tasks under authorization scope.\n\n"
                    f"**Suggested Directives:**\n"
                    f"- `Run subdomain recon` â€” Enumerate subdomains & alive hosts\n"
                    f"- `Analyze JavaScript` â€” Crawl JS files, extract AST routes & scan for secrets\n"
                    f"- `Verify findings` â€” Execute independent cURL replay & prune false positives\n"
                    f"- `Export SARIF 2.1.0` â€” Build GitHub Code Scanning deliverable"
                )
                source = "specialist-briefing"

        provider = client.provider if source in ("llm", "agent_runner") else "agent-runtime"
        model_name = client.model if source in ("llm", "agent_runner") else "specialist-tooling"
        store.append(agent, "assistant", answer, provider=provider, model=model_name, source=source)
        rm.update_agent_session(run_id, agent_id=agent, status="completed", summary=answer[:200])

        return {
            "status": "success",
            "agent": agent,
            "provider": provider,
            "model": model_name,
            "message": answer,
            "source": source
        }
        return roster

    def get_target_skills_status(self, target_name):
        target_dir = TARGETS_DIR / target_name
        output_dir = target_dir / "output"
        logs_dir = output_dir / "logs"

        latest_status = {}
        try:
            latest_run = RunManager(target_dir).get_latest_or_active_run()
            if latest_run:
                events_path = output_dir / "runs" / latest_run["run_id"] / "events.jsonl"
                if events_path.is_file():
                    for line in events_path.read_text(encoding="utf-8").splitlines():
                        try:
                            event = json.loads(line)
                            details = event.get("details", {})
                            skill = details.get("skill")
                            kind = event.get("event", "")
                            if skill and kind.startswith("SKILL_"):
                                latest_status[skill] = kind.removeprefix("SKILL_").lower()
                        except (json.JSONDecodeError, AttributeError):
                            continue
        except (OSError, KeyError, TypeError):
            pass

        statuses = []
        registry = SkillRegistry()
        all_skills = registry.list_skills()
        for s_obj in all_skills:
            s = s_obj["id"]
            skill_log_dir = logs_dir / s
            has_logs = skill_log_dir.exists() and any(skill_log_dir.glob("*.log"))

            # Determine status
            state = "pending"
            log_files = []
            if has_logs:
                log_files = [f.name for f in skill_log_dir.glob("*.log")]
                state = "completed"

            run_state = latest_status.get(s)
            if run_state in {"running", "failed", "blocked", "blocked_scope"}:
                state = run_state
            elif run_state == "candidates_only":
                state = "candidates_only"
            elif run_state == "not_implemented":
                state = "not_implemented"
            elif run_state in {"completed", "success"}:
                state = "completed"

            # Check if review failed
            review_log = logs_dir / "review" / f"{s}-review-1.json"
            review_status = "unreviewed"
            if review_log.exists():
                try:
                    rev_data = json.loads(review_log.read_text(encoding="utf-8"))
                    review_status = rev_data.get("overall_status", "PASS")
                    if review_status == "FAIL":
                        state = "failed"
                except Exception:
                    pass

            statuses.append({
                "skill": s,
                "name": s_obj.get("title", s),
                "title": s_obj.get("title", s),
                "category": s_obj.get("category", "General"),
                "description": s_obj.get("description", ""),
                "is_custom": s_obj.get("is_custom", False),
                "state": state,
                "review_status": review_status,
                "logs_count": len(log_files),
                "log_files": log_files,
            })

        return statuses

    def get_target_findings(self, target_name):
        target_dir = TARGETS_DIR / target_name
        output_dir = target_dir / "output"
        findings = []

        # 1. From findings/* directory
        findings_dir = output_dir / "findings"
        if findings_dir.exists():
            for fpath in findings_dir.rglob("*.json"):
                if fpath.name.startswith(("confirmed-", "candidates-")) or fpath.name.endswith("-results.json"):
                    try:
                        content = json.loads(fpath.read_text(encoding="utf-8"))
                        items = content if isinstance(content, list) else content.get("findings", [content])
                        for item in items:
                            if isinstance(item, dict) and ("type" in item or "title" in item or "url" in item):
                                raw_sev = item.get("severity", "Triage Severity: UNASSESSED â€” pending evidence and human review")
                                sev_lvl = "UNASSESSED" if "UNASSESSED" in raw_sev.upper() else "MEDIUM"
                                if "CRITICAL" in raw_sev.upper():
                                    sev_lvl = "CRITICAL"
                                elif "HIGH" in raw_sev.upper():
                                    sev_lvl = "HIGH"
                                elif "LOW" in raw_sev.upper():
                                    sev_lvl = "LOW"
                                elif "INFO" in raw_sev.upper():
                                    sev_lvl = "INFO"

                                validation = item.get("validation_record") or {}
                                human_validation = (
                                    isinstance(validation, dict)
                                    and str(validation.get("verified_by", "")).startswith("human:")
                                    and bool(validation.get("method"))
                                    and bool(validation.get("evidence_ids"))
                                    and validation.get("outcome") == "reproduced"
                                )
                                findings.append({
                                    "id": f"{fpath.stem}-{len(findings)+1}",
                                    "title": item.get("title", item.get("type", fpath.stem)),
                                    "category": fpath.parent.name,
                                    "severity": raw_sev,
                                    "severity_level": sev_lvl,
                                    "endpoint": item.get("url", item.get("endpoint", "")),
                                    "parameter": item.get("parameter", item.get("param", "")),
                                    "payload": item.get("payload", ""),
                                    "curl_command": item.get("curl", ""),
                                    "source_file": str(fpath.relative_to(output_dir)),
                                    "details": item.get("notes", item.get("context", "")),
                                    "status": "validated" if human_validation else "candidate",
                                    "validation_status": "validated" if human_validation else "unverified",
                                    "confidence": item.get("confidence", "not-scored"),
                                    "evidence_ids": item.get("evidence_ids", []),
                                })
                    except Exception:
                        pass

        # 2. From secrets-findings.json
        secrets_file = output_dir / "js" / "secrets-findings.json"
        if secrets_file.exists():
            try:
                s_data = json.loads(secrets_file.read_text(encoding="utf-8"))
                for s in s_data.get("findings", []):
                    raw_sev = s.get("severity", "Triage Severity: MEDIUM â€” pending human review")
                    sev_lvl = "MEDIUM"
                    if "HIGH" in raw_sev.upper():
                        sev_lvl = "HIGH"
                    elif "CRITICAL" in raw_sev.upper():
                        sev_lvl = "CRITICAL"
                    elif "LOW" in raw_sev.upper():
                        sev_lvl = "LOW"

                    findings.append({
                        "id": f"secret-{len(findings)+1}",
                        "title": f"Hardcoded Secret: {s.get('type')}",
                        "category": "secrets",
                        "severity": raw_sev,
                        "severity_level": sev_lvl,
                        # A local artifact path is provenance, never a target URL.
                        "endpoint": s.get("url", ""),
                        "parameter": s.get("pattern_name", ""),
                        "payload": s.get("value_preview", ""),
                        "curl_command": "",
                        "source_file": s.get("source_file", ""),
                        "line": s.get("line_number"),
                        "details": s.get("context", ""),
                        "status": "pending_review",
                    })
            except Exception:
                pass

        # 3. From gadgets.json (DOM XSS sinks)
        gadgets_file = output_dir / "js" / "gadgets.json"
        if gadgets_file.exists():
            try:
                g_data = json.loads(gadgets_file.read_text(encoding="utf-8"))
                for g in g_data.get("gadgets", []):
                    findings.append({
                        "id": f"gadget-{len(findings)+1}",
                        "title": f"Dangerous Sink: {g.get('type')}",
                        "category": "dom-xss",
                        "severity": "Triage Severity: MEDIUM â€” pending human review",
                        "severity_level": "MEDIUM",
                        "endpoint": g.get("source_file", ""),
                        "parameter": g.get("controllable_source", ""),
                        "payload": g.get("code_snippet", ""),
                        "curl_command": "",
                        "source_file": g.get("source_file", ""),
                        "line": g.get("line_number"),
                        "details": g.get("risk", ""),
                        "status": "pending_review",
                    })
            except Exception:
                pass

        return findings

    def get_target_endpoints(self, target_name):
        ep_file = TARGETS_DIR / target_name / "output" / "js" / "endpoints.json"
        api_file = TARGETS_DIR / target_name / "output" / "api" / "endpoints.json"
        legacy_api_file = TARGETS_DIR / target_name / "output" / "api" / "openapi-endpoints.json"
        inventory = {"endpoints": [], "total_endpoints": 0}
        if ep_file.exists():
            try:
                inventory = json.loads(ep_file.read_text(encoding="utf-8"))
            except Exception as e:
                return {"error": str(e), "endpoints": []}
        endpoints = inventory.get("endpoints", [])
        for endpoint in endpoints:
            endpoint.setdefault("source", "javascript")
        if api_file.exists() or legacy_api_file.exists():
            try:
                source_file = api_file if api_file.exists() else legacy_api_file
                api_inventory = json.loads(source_file.read_text(encoding="utf-8"))
                for endpoint in api_inventory.get("endpoints", []):
                    if not isinstance(endpoint, dict):
                        continue
                    endpoint["source"] = "openapi"
                    endpoint["url"] = endpoint.get("base_url", "").rstrip("/") + endpoint.get("path", "")
                    endpoints.append(endpoint)
            except Exception as e:
                return {"error": str(e), "endpoints": endpoints}
        inventory["endpoints"] = endpoints
        inventory["total_endpoints"] = len(endpoints)
        return inventory

    def get_target_tech_fingerprint(self, target_name):
        tech_file = TARGETS_DIR / target_name / "output" / "js" / "tech-fingerprint.json"
        if tech_file.exists():
            try:
                return json.loads(tech_file.read_text(encoding="utf-8"))
            except Exception as e:
                return {"error": str(e)}
        return {}

    def get_target_logs(self, target_name, specific_file=None):
        logs_dir = TARGETS_DIR / target_name / "output" / "logs"
        if not logs_dir.exists():
            return {"logs": [], "content": ""}

        all_logs = []
        for p in logs_dir.rglob("*.log"):
            all_logs.append({
                "path": str(p.relative_to(logs_dir)).replace("\\", "/"),
                "size": p.stat().st_size,
                "modified": datetime.fromtimestamp(p.stat().st_mtime, tz=timezone.utc).isoformat(),
            })

        content = ""
        if specific_file:
            safe_p = (logs_dir / specific_file).resolve()
            if str(safe_p).startswith(str(logs_dir)) and safe_p.exists():
                content = safe_p.read_text(encoding="utf-8", errors="ignore")

        return {"logs": sorted(all_logs, key=lambda x: x["path"]), "content": content}

    def get_target_checkpoints(self, target_name):
        target_dir = TARGETS_DIR / target_name
        cp_mgr = CheckpointManager(target_name, target_dir)
        return cp_mgr.list_checkpoints()

    def handle_checkpoint_decision(self, target_name, checkpoint_id, action, notes):
        target_dir = TARGETS_DIR / target_name
        cp_mgr = CheckpointManager(target_name, target_dir)
        decided = cp_mgr.decide(checkpoint_id, action, notes, decider="dashboard_operator")
        return {
            "status": "success",
            "message": f"Checkpoint {checkpoint_id} marked as {decided.get('status')}",
            "checkpoint": decided
        }

    def get_target_report(self, target_name):
        report_dir = TARGETS_DIR / target_name / "output" / "report"
        if not report_dir.exists():
            return {"markdown": "# No Report Generated Yet", "json": {}}

        md_files = list(report_dir.glob("*.md"))
        json_files = list(report_dir.glob("*.json"))

        md_content = md_files[0].read_text(encoding="utf-8") if md_files else "# No report markdown found"
        json_content = {}
        if json_files:
            try:
                json_content = json.loads(json_files[0].read_text(encoding="utf-8"))
            except Exception:
                pass

        return {"markdown": md_content, "json": json_content, "files": [f.name for f in md_files + json_files]}

    # ==================== SCAN MANAGEMENT ====================

    def start_scan_job(self, target, skills, models, dry_run=False, scan_mode="quick"):
        if target in active_scans and active_scans[target]["status"] == "running":
            return {"status": "error", "message": f"A scan is already running for {target}"}

        target_dir = TARGETS_DIR / target
        initialized = not target_dir.is_dir()
        if initialized:
            try:
                from setup import init_target
                init_target(target)
            except Exception as exc:
                return {"status": "error", "message": f"Could not initialize target workspace: {exc}"}

        log_buffer = []

        def run_worker():
            active_scans[target]["status"] = "running"
            active_scans[target]["start_time"] = datetime.now(timezone.utc).isoformat()

            cmd = [
                sys.executable,
                str(PROJECT_ROOT / "run.py"),
                "--target", target,
                "--skills", skills,
                "--models", models,
                "--scan-mode", scan_mode,
                "--https-only",
                "--max-http-requests", "40",
                "--request-delay", "0.4",
            ]
            if dry_run:
                cmd.append("--dry-run")

            log_buffer.append(f"[{datetime.now(timezone.utc).strftime('%H:%M:%S')}] Executing: {' '.join(cmd)}\n")

            try:
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    bufsize=1,
                    cwd=str(PROJECT_ROOT),
                )
                active_scans[target]["process"] = proc

                for line in iter(proc.stdout.readline, ""):
                    log_buffer.append(line)
                    if len(log_buffer) > 2000:
                        log_buffer.pop(0)

                proc.stdout.close()
                proc.wait()

                active_scans[target]["status"] = "completed" if proc.returncode == 0 else "failed"
                log_buffer.append(f"\n[Finished with exit code {proc.returncode}]\n")
                notification = send_discord_scan_summary(target, active_scans[target]["status"])
                if notification != "not configured":
                    log_buffer.append(f"[Discord] Scan summary notification: {notification}.\n")
            except Exception as e:
                active_scans[target]["status"] = "error"
                log_buffer.append(f"\n[Execution error: {e}]\n")

        thread = threading.Thread(target=run_worker, daemon=True)
        active_scans[target] = {
            "thread": thread,
            "status": "starting",
            "logs": log_buffer,
            "target": target,
        }
        thread.start()

        message = f"Scan started for {target}"
        if initialized:
            message += ". A workspace was created; without a matching readable scope-of-work note, only passive recon can run."
        return {"status": "success", "message": message, "target": target, "initialized_target": initialized}

    def stop_scan_job(self, target):
        if target in active_scans and active_scans[target].get("process"):
            try:
                active_scans[target]["process"].terminate()
                active_scans[target]["status"] = "stopped"
                return {"status": "success", "message": f"Scan for {target} stopped"}
            except Exception as e:
                return {"status": "error", "message": str(e)}
        return {"status": "error", "message": f"No active scan found for {target}"}

    def get_scan_status(self, target):
        if not target or target not in active_scans:
            return {"status": "idle", "logs": []}

        scan_info = active_scans[target]
        return {
            "status": scan_info.get("status", "idle"),
            "target": target,
            "start_time": scan_info.get("start_time"),
            "logs": "".join(scan_info.get("logs", [])),
        }


def run_dashboard(host="127.0.0.1", port=8080, open_browser=True, default_target=None):
    """Run the Moros AI Agent dashboard server."""
    if host.lower() not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("Dashboard binds to loopback only; remote access requires authentication first")
    server_address = (host, port)
    httpd = ThreadedHTTPServer(server_address, DashboardHandler)

    url = f"http://{host}:{port}"
    if default_target:
        url += f"?target={default_target}"

    print("=" * 60)
    print("ðŸ›¡ï¸  MOROS AI AGENT â€” WEB DASHBOARD")
    print(f"ðŸ“¡ Dashboard running at: {url}")
    print(f"ðŸ“‚ Project Root: {PROJECT_ROOT}")
    print("âŒ¨ï¸  Press Ctrl+C to stop the dashboard server")
    print("=" * 60)

    if open_browser:
        import webbrowser
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nðŸ›‘ Dashboard server stopped.")
    finally:
        httpd.server_close()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Moros AI Agent â€” Web Dashboard Server")
    parser.add_argument("--host", default="127.0.0.1", help="Host address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8080, help="Port (default: 8080)")
    parser.add_argument("--target", default=None, help="Default target domain to open")
    parser.add_argument("--no-open", action="store_true", help="Do not open browser automatically")

    args = parser.parse_args()
    run_dashboard(host=args.host, port=args.port, open_browser=not args.no_open, default_target=args.target)

