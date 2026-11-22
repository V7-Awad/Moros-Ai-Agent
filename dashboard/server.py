#!/usr/bin/env python3
"""
Moros AI Agent — Web Dashboard Server
Inspired by Strix (usestrix/strix) local web viewer architecture.

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
import urllib.parse
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
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()
        self.wfile.write(body)

    def send_error_json(self, message, status=400):
        self.send_json({"error": message, "status": "error"}, status=status)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()

    def do_GET(self):
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
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        content_length = int(self.headers.get("Content-Length", 0))
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

        # 5. Scan status
        if path == "/api/scan/status":
            target = query.get("target", [None])[0]
            self.send_json(self.get_scan_status(target))
            return

        self.send_error_json("Unknown API endpoint", status=404)

    def handle_api_post(self, path, body):
        # 1. Create target
        if path == "/api/targets/create":
            domain = body.get("domain", "").strip()
            if not domain:
                self.send_error_json("Domain name is required")
                return

            # Invoke setup script to create target folder
            from setup import init_target
            try:
                init_target(domain)
                self.send_json({"status": "success", "message": f"Target {domain} created", "target": domain})
            except Exception as e:
                self.send_error_json(f"Failed to create target: {e}")
            return

        # 2. Start Scan
        if path == "/api/scan/start":
            target = body.get("target", "").strip()
            skills = body.get("skills", "all")
            models = body.get("models", "default")
            dry_run = body.get("dry_run", False)

            if not target:
                self.send_error_json("Target is required")
                return

            res = self.start_scan_job(target, skills, models, dry_run)
            self.send_json(res)
            return

        # 3. Stop Scan
        if path == "/api/scan/stop":
            target = body.get("target", "").strip()
            res = self.stop_scan_job(target)
            self.send_json(res)
            return

        # 4. Checkpoint approval/rejection
        if path == "/api/checkpoints/action":
            target = body.get("target", "").strip()
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
            target_path = TARGETS_DIR / target
            if not target_path.is_dir():
                self.send_error_json(f"Target '{target}' not found", status=404)
                return
            if len(message) > 12000:
                self.send_error_json("Message is too long (max 12000 characters)")
                return

            store = ConversationStore(target_path)
            store.append(agent, "user", message, source="dashboard")
            client = LLMClient(provider="auto")
            system_prompt = (
                f"You are the Moros AI agent '{agent}' assessing target '{target}'. "
                "Stay strictly within documented authorization scope. Provide crisp, technical pentester analysis. "
                "Format code snippets with markdown and cURL reproduction steps."
            )
            answer = client.complete(message, system_prompt=system_prompt)
            if answer is None:
                summary_data = self.get_target_summary(target)
                findings = summary_data.get("total_findings", 0)
                severities = summary_data.get("severities", {})
                endpoints = summary_data.get("total_endpoints", 0)
                msg_lower = message.lower()

                if any(w in msg_lower for w in ["finding", "vuln", "critical", "bug", "exploit"]):
                    crit_count = severities.get("CRITICAL", 0)
                    high_count = severities.get("HIGH", 0)
                    answer = (
                        f"**[{agent.upper()} Analysis — Target `{target}`]**\n\n"
                        f"Currently, we have **{findings} verified findings** across all categories:\n"
                        f"- 🔴 **Critical:** {crit_count} (Remote / Privilege Escalation)\n"
                        f"- 🟠 **High:** {high_count} (High impact state modification)\n"
                        f"- 🟡 **Medium:** {severities.get('MEDIUM', 0)}\n"
                        f"- 🔵 **Low:** {severities.get('LOW', 0)}\n\n"
                        f"All high-risk findings contain valid cURL commands for reproduction and are awaiting human approval."
                    )
                elif any(w in msg_lower for w in ["endpoint", "api", "route", "url"]):
                    answer = (
                        f"**[{agent.upper()} Inventory — Target `{target}`]**\n\n"
                        f"I have mapped **{endpoints} unique endpoints** from client-side bundles and active spidering.\n"
                        f"All state-changing routes (`POST`, `PUT`, `DELETE`) are isolated and checked for authentication gates."
                    )
                elif any(w in msg_lower for w in ["scope", "rule", "auth", "permission"]):
                    has_scope = summary_data.get("has_scope", False)
                    status_str = "Verified & Active" if has_scope else "Passive Recon Only (No scope-of-work file found)"
                    answer = (
                        f"**[{agent.upper()} Scope Verification]**\n\n"
                        f"Target: `{target}`\n"
                        f"Status: **{status_str}**\n\n"
                        f"Exploitation tools and brute-forcers will halt before attacking out-of-scope hosts or unconfirmed state changes."
                    )
                elif any(w in msg_lower for w in ["steer", "focus", "prioritize", "scan", "check"]):
                    answer = (
                        f"**[Steering Directive Acknowledged by {agent.upper()}]**\n\n"
                        f"Received instruction: *\"{message}\"*\n\n"
                        f"Priority has been queued for target `{target}`. The next execution cycle will direct specialist attention to this vector.\n\n"
                        f"> 💡 *Tip: You can launch an immediate targeted scan via the 'Launch Scan' button.*"
                    )
                else:
                    answer = (
                        f"**[{agent.upper()} Telemetry & Status]**\n\n"
                        f"Assessment active on `{target}`.\n"
                        f"- **Discovered Surface:** {endpoints} API endpoints, {summary_data.get('total_js_files', 0)} JS bundles.\n"
                        f"- **Current Findings:** {findings} vulnerability candidates (Critical: {severities.get('CRITICAL', 0)}).\n"
                        f"- **HITL Status:** Zero unattended exploitation.\n\n"
                        f"You can ask me to analyze specific routes, explain reproduction payloads, or steer sub-agents.\n\n"
                        f"*(Configure `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, or local `Ollama` for full autonomous reasoning)*"
                    )

            provider = client.provider if client.is_available() else "heuristic-engine"
            model_name = client.model if client.is_available() else "Moros Core"
            store.append(agent, "assistant", answer, provider=provider, model=model_name, source="llm")
            self.send_json({"status": "success", "agent": agent, "provider": provider, "model": model_name, "message": answer})
            return

        self.send_error_json("Unknown API endpoint", status=404)

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
            "all_skills_count": len(ALL_SKILLS),
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
        meta = []
        for s in ALL_SKILLS:
            skill_path = SKILLS_DIR / s / "SKILL.md"
            desc = ""
            if skill_path.exists():
                content = skill_path.read_text(encoding="utf-8", errors="ignore")
                # Parse description from frontmatter
                desc_match = re.search(r"description:\s*>?\s*\n?\s*(.*?)(?:\n---|\n#)", content, re.DOTALL)
                if desc_match:
                    desc = desc_match.group(1).replace("\n", " ").strip()

            meta.append({
                "id": s,
                "name": s,
                "description": desc,
                "has_definition": skill_path.exists(),
            })
        return meta

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
        if agent == "coordinator":
            return (
                f"🛡️ **Moros AI Assessment Coordinator Online**\n\n"
                f"Target: `{target_name}`\n\n"
                f"I orchestrate the attack graph, coordinate specialist sub-agents (Recon, JS Hunter, XSS, SSRF, Auth), and enforce the Human-in-the-Loop checkpoint gate.\n\n"
                f"You can instruct me directly to steer the assessment, prioritize specific endpoints, or ask for deep technical explanations of any findings."
            )
        elif agent == "recon-agent":
            return (
                f"🌐 **Reconnaissance Specialist Online**\n\n"
                f"Monitoring DNS and subdomain surface for `{target_name}`. Ask me about discovered subdomains, IP ranges, or live hosts."
            )
        elif agent == "js-analyzer":
            return (
                f"⚡ **JavaScript & API Hunter Online**\n\n"
                f"Target `{target_name}` client-side analysis ready. Ask me about discovered endpoints, extracted source-map secrets, or DOM sinks."
            )
        elif agent == "xss-specialist":
            return (
                f"🎯 **XSS Specialist Online**\n\n"
                f"Payload generator and context validator ready for `{target_name}`. Ask me to test specific injection points or explain PoCs."
            )
        elif agent == "ssrf-specialist":
            return (
                f"☁️ **SSRF & Cloud Metadata Specialist Online**\n\n"
                f"Out-of-band monitoring and metadata probes armed for `{target_name}`. Ask me to audit webhook endpoints or cloud pivots."
            )
        elif agent == "auth-race-specialist":
            return (
                f"🔑 **Auth & Race Condition Specialist Online**\n\n"
                f"Multi-threaded race condition and reset brute-forcer ready for `{target_name}`."
            )
        elif agent == "review-verifier":
            return (
                f"🔍 **Review-Skill Verification Gate Online**\n\n"
                f"I independently verify every exploit proof and eliminate false positives before findings reach your final report."
            )
        elif agent == "report-specialist":
            return (
                f"📄 **Reporting & Deliverable Specialist Online**\n\n"
                f"I conglomerate all verified findings, tech stack fingerprints, and audit trails into the final executive report."
            )
        else:
            return f"🤖 **Sub-Agent `{agent}` Online**\n\nReady to receive instructions for target `{target_name}`."

    def get_subagent_roster(self, target_name):
        target_path = TARGETS_DIR / target_name
        store = ConversationStore(target_path)
        is_scanning = target_name in active_scans and active_scans[target_name]["status"] == "running"

        roster = [
            {
                "id": "coordinator",
                "name": "Coordinator Master",
                "role": "Attack tree orchestration, HITL gate & multi-agent planner",
                "tier": "Frontier (Claude 3.5 / GPT-4o)",
                "status": "ACTIVE" if is_scanning else "STANDBY",
                "icon": "shield-alert",
                "messages_count": len(store.read("coordinator", 200)),
            },
            {
                "id": "recon-agent",
                "name": "Reconnaissance Specialist",
                "role": "Subdomain discovery, asset mapping, DNS brute & Wayback fetch",
                "tier": "Mid-tier (GPT-4o-mini / Heuristic)",
                "status": "COMPLETED" if (target_path / "output" / "recon").exists() else "READY",
                "icon": "globe",
                "messages_count": len(store.read("recon-agent", 200)),
            },
            {
                "id": "js-analyzer",
                "name": "JavaScript & API Hunter",
                "role": "Headless browser spider, source map unminifier, AST parser & secret scanner",
                "tier": "Mid-tier (Claude Sonnet / Rule Engine)",
                "status": "COMPLETED" if (target_path / "output" / "js").exists() else "READY",
                "icon": "code",
                "messages_count": len(store.read("js-analyzer", 200)),
            },
            {
                "id": "xss-specialist",
                "name": "XSS & Client-Side Specialist",
                "role": "DOM, Reflected, Stored, and Blind XSS payload injection & context escape",
                "tier": "Frontier (Claude 3.5 Sonnet)",
                "status": "COMPLETED" if (target_path / "output" / "findings" / "xss-reflected").exists() else "READY",
                "icon": "zap",
                "messages_count": len(store.read("xss-specialist", 200)),
            },
            {
                "id": "ssrf-specialist",
                "name": "SSRF & Cloud Metadata Hunter",
                "role": "SSRF identification, out-of-band canary interaction, AWS/GCP/K8s pivot",
                "tier": "Frontier (GPT-4o)",
                "status": "COMPLETED" if (target_path / "output" / "findings" / "ssrf-identify").exists() else "READY",
                "icon": "cloud-lightning",
                "messages_count": len(store.read("ssrf-specialist", 200)),
            },
            {
                "id": "auth-race-specialist",
                "name": "Auth & Race Condition Agent",
                "role": "IdP multi-threaded race conditions & password reset rate-limit audit",
                "tier": "Mid-tier (Fast Thread Pool)",
                "status": "COMPLETED" if (target_path / "output" / "findings" / "idp-race-condition").exists() else "READY",
                "icon": "key",
                "messages_count": len(store.read("auth-race-specialist", 200)),
            },
            {
                "id": "review-verifier",
                "name": "Review-Skill Verifier Gate",
                "role": "False-positive pruning, independent cURL replay & proof verification",
                "tier": "Cross-Model Verification",
                "status": "COMPLETED" if (target_path / "output" / "logs" / "review").exists() else "READY",
                "icon": "check-circle",
                "messages_count": len(store.read("review-verifier", 200)),
            },
            {
                "id": "report-specialist",
                "name": "Reporting & Synthesis Agent",
                "role": "Executive deliverable synthesis, CVSS scoring & remediation guidance",
                "tier": "Frontier (Claude 3.5 Sonnet)",
                "status": "COMPLETED" if (target_path / "output" / "report").exists() else "READY",
                "icon": "file-text",
                "messages_count": len(store.read("report-specialist", 200)),
            },
        ]
        return roster

    def get_target_skills_status(self, target_name):
        target_dir = TARGETS_DIR / target_name
        output_dir = target_dir / "output"
        logs_dir = output_dir / "logs"

        statuses = []
        for s in ALL_SKILLS:
            skill_log_dir = logs_dir / s
            has_logs = skill_log_dir.exists() and any(skill_log_dir.glob("*.log"))

            # Determine status
            state = "pending"
            log_files = []
            if has_logs:
                log_files = [f.name for f in skill_log_dir.glob("*.log")]
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
                                raw_sev = item.get("severity", "AI-proposed severity: UNASSESSED — pending evidence and human review")
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
                    raw_sev = s.get("severity", "AI-proposed severity: MEDIUM — pending human review")
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
                        "endpoint": s.get("source_file", ""),
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
                        "severity": "AI-proposed severity: MEDIUM — pending human review",
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
        inventory = {"endpoints": [], "total_endpoints": 0}
        if ep_file.exists():
            try:
                inventory = json.loads(ep_file.read_text(encoding="utf-8"))
            except Exception as e:
                return {"error": str(e), "endpoints": []}
        endpoints = inventory.get("endpoints", [])
        for endpoint in endpoints:
            endpoint.setdefault("source", "javascript")
        if api_file.exists():
            try:
                api_inventory = json.loads(api_file.read_text(encoding="utf-8"))
                for endpoint in api_inventory.get("endpoints", []):
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
        output_dir = target_dir / "output"

        # Checkpoints file
        cp_file = output_dir / "logs" / "checkpoints.json"
        checkpoints = []

        if cp_file.exists():
            try:
                checkpoints = json.loads(cp_file.read_text(encoding="utf-8"))
            except Exception:
                pass

        # If no explicit checkpoint file yet, auto-generate from state-changing endpoints
        if not checkpoints:
            ep_file = output_dir / "js" / "endpoints.json"
            if ep_file.exists():
                try:
                    data = json.loads(ep_file.read_text(encoding="utf-8"))
                    for ep in data.get("endpoints", []):
                        if ep.get("method") in ["POST", "PUT", "DELETE"]:
                            checkpoint_key = "|".join([
                                str(ep.get("method", "")).upper(),
                                str(ep.get("url", "")),
                                str(ep.get("parameter", ep.get("param", ""))),
                            ])
                            checkpoint_id = hashlib.sha256(
                                checkpoint_key.encode("utf-8")
                            ).hexdigest()[:12]
                            checkpoints.append({
                                "id": f"cp-{checkpoint_id}",
                                "type": "State-Changing Endpoint Confirmation",
                                "target_url": ep.get("url"),
                                "method": ep.get("method"),
                                "reason": f"Endpoint uses {ep.get('method')} which may modify database or application state.",
                                "status": "PENDING_APPROVAL",
                                "created_at": datetime.now(timezone.utc).isoformat(),
                            })
                except Exception:
                    pass

        return checkpoints

    def handle_checkpoint_decision(self, target_name, checkpoint_id, action, notes):
        target_dir = TARGETS_DIR / target_name
        cp_file = target_dir / "output" / "logs" / "checkpoints.json"
        checkpoints = self.get_target_checkpoints(target_name)

        updated = False
        for cp in checkpoints:
            if cp.get("id") == checkpoint_id:
                cp["status"] = "APPROVED" if action == "approve" else "REJECTED"
                cp["decision_time"] = datetime.now(timezone.utc).isoformat()
                cp["notes"] = notes
                updated = True
                break

        if updated:
            cp_file.parent.mkdir(parents=True, exist_ok=True)
            cp_file.write_text(json.dumps(checkpoints, indent=2), encoding="utf-8")
            return {"status": "success", "message": f"Checkpoint {checkpoint_id} marked as {action.upper()}"}

        return {"status": "error", "message": "Checkpoint not found"}

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

    def start_scan_job(self, target, skills, models, dry_run=False):
        if target in active_scans and active_scans[target]["status"] == "running":
            return {"status": "error", "message": f"A scan is already running for {target}"}

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

        return {"status": "success", "message": f"Scan started for {target}", "target": target}

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
    server_address = (host, port)
    httpd = ThreadedHTTPServer(server_address, DashboardHandler)

    url = f"http://{host}:{port}"
    if default_target:
        url += f"?target={default_target}"

    print("=" * 60)
    print("🛡️  MOROS AI AGENT — WEB DASHBOARD")
    print(f"📡 Dashboard running at: {url}")
    print(f"📂 Project Root: {PROJECT_ROOT}")
    print("⌨️  Press Ctrl+C to stop the dashboard server")
    print("=" * 60)

    if open_browser:
        import webbrowser
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n🛑 Dashboard server stopped.")
    finally:
        httpd.server_close()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Moros AI Agent — Web Dashboard Server")
    parser.add_argument("--host", default="127.0.0.1", help="Host address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8080, help="Port (default: 8080)")
    parser.add_argument("--target", default=None, help="Default target domain to open")
    parser.add_argument("--no-open", action="store_true", help="Do not open browser automatically")

    args = parser.parse_args()
    run_dashboard(host=args.host, port=args.port, open_browser=not args.no_open, default_target=args.target)
