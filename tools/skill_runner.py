#!/usr/bin/env python3
"""
skill_runner.py — Real Skill Execution Engine for Moros AI Agent.

Implements the actual execution logic for each of the 15 micro-skills:
- Reconnaissance & CT log discovery
- JavaScript collection, beautification & analysis
- Secret scanning & endpoint mapping
- Content discovery with tech-stack-aware wordlists
- Bounded, same-host, non-destructive HTTP checks
- Completion verification (Review-Skill)
- Final report conglomeration
"""

import hashlib
import json
import logging
import os
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List

tools_dir = Path(__file__).parent.resolve()
if str(tools_dir) not in sys.path:
    sys.path.insert(0, str(tools_dir))

from agent_runtime import AgentRunner, AgentContext, AgentResult, ToolRegistry
from scoped_http import ScopedHttpClient

logger = logging.getLogger("skill-runner")
PROJECT_ROOT = Path(__file__).parent.parent.resolve()


class SkillRunner:
    def __init__(self, target: str, target_dir: Path, llm_client=None,
                 max_http_requests: int = 40, request_delay: float = 0.4):
        self.target = target
        self.target_dir = Path(target_dir)
        self.output_dir = self.target_dir / "output"
        self.logs_dir = self.output_dir / "logs"
        self.llm = llm_client
        self._recorded_evidence_ids = None
        self.scope_authorized = False
        self.http = ScopedHttpClient(target, max_requests=max_http_requests, delay_seconds=request_delay)

    @staticmethod
    def _host_is_in_root_scope(host: str, root: str) -> bool:
        host = str(host).strip().lower().rstrip(".")
        root = str(root).strip().lower().rstrip(".")
        return bool(root) and (host == root or host.endswith("." + root))

    def record_candidate_evidence(self, skill: str, finding_type: str, artifact_path: Path,
                                  endpoint: dict, claim: str) -> dict:
        """Record a content-addressed source reference; endpoint metadata is not exploit proof."""
        artifact_path = Path(artifact_path)
        try:
            digest = hashlib.sha256()
            with artifact_path.open("rb") as artifact_stream:
                for chunk in iter(lambda: artifact_stream.read(1024 * 1024), b""):
                    digest.update(chunk)
            artifact_hash = digest.hexdigest()
            artifact_ref = str(artifact_path.relative_to(self.target_dir)).replace("\\", "/")
            available = True
        except (OSError, ValueError):
            artifact_hash = ""
            artifact_ref = str(artifact_path)
            available = False

        route = endpoint.get("url") or (str(endpoint.get("base_url", "")).rstrip("/") + str(endpoint.get("path", "")))
        parameter = endpoint.get("parameters", [])
        if parameter and isinstance(parameter[0], dict):
            parameter = parameter[0].get("name", "")
        elif parameter:
            parameter = str(parameter[0])
        else:
            parameter = ""
        identity = "|".join([self.target, skill, finding_type, route, str(parameter), artifact_hash])
        evidence_id = "ev-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]
        evidence = {
            "evidence_id": evidence_id,
            "evidence_type": "endpoint_metadata",
            "source_artifact": artifact_ref,
            "source_sha256": artifact_hash,
            "source_available": available,
            "claim": claim,
            "limitations": "Metadata supports triage only; no vulnerability behavior was independently reproduced.",
            "verification_status": "unverified",
            "recorded_at": datetime.now(timezone.utc).isoformat(),
        }

        if self._recorded_evidence_ids is None:
            self._recorded_evidence_ids = set()
            ledger = self.output_dir / "evidence" / "ledger.jsonl"
            if ledger.is_file():
                try:
                    with ledger.open("r", encoding="utf-8") as stream:
                        for line in stream:
                            try:
                                old_entry = json.loads(line)
                                if old_entry.get("evidence_id"):
                                    self._recorded_evidence_ids.add(old_entry["evidence_id"])
                            except json.JSONDecodeError:
                                continue
                except OSError:
                    pass
        if evidence_id not in self._recorded_evidence_ids:
            ledger = self.output_dir / "evidence" / "ledger.jsonl"
            ledger.parent.mkdir(parents=True, exist_ok=True)
            with ledger.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps({"target": self.target, "skill": skill, "finding_type": finding_type,
                                         **evidence}, ensure_ascii=False) + "\n")
            self._recorded_evidence_ids.add(evidence_id)
        return evidence

    def log_step(self, skill: str, log_name: str, message: str):
        """Append a message to a skill's step log file."""
        skill_log_dir = self.logs_dir / skill
        skill_log_dir.mkdir(parents=True, exist_ok=True)
        log_file = skill_log_dir / log_name

        timestamp = datetime.now(timezone.utc).isoformat()
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] {message}\n")

    # ==================== SKILL 1: RECON-SUBDOMAIN ====================

    def run_recon_subdomain(self, active_validation: bool = False, max_active_hosts: int = 20,
                            root_only: bool = False, https_only: bool = False) -> Dict[str, Any]:
        skill = "recon-subdomain"
        recon_dir = self.output_dir / "recon"
        recon_dir.mkdir(parents=True, exist_ok=True)

        self.log_step(skill, "step-01-auth-check.log",
                      f"Scope note matched configured target {self.target}; this is not independent proof of authorization.")
        subdomains = set([self.target])

        # Step 2: Certificate Transparency Logs (crt.sh)
        self.log_step(skill, "step-02-ct-logs.log", f"Querying crt.sh for %{self.target}...")
        try:
            url = f"https://crt.sh/?q=%25.{self.target}&output=json"
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 Moros-AI-Recon"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="ignore"))
                for item in data:
                    name = item.get("name_value", "")
                    for sub in name.split("\n"):
                        sub = sub.strip().lower().lstrip("*.")
                        if self._host_is_in_root_scope(sub, self.target):
                            subdomains.add(sub)
            self.log_step(skill, "step-02-ct-logs.log", f"crt.sh returned {len(subdomains)} unique subdomains.")
        except Exception as e:
            self.log_step(skill, "step-02-ct-logs.log", f"crt.sh query completed/fallback: {e}")

        # Step 3: Wayback Machine CDX API subdomains
        self.log_step(skill, "step-03-web-archives.log", f"Querying Wayback CDX for *.{self.target}/*...")
        try:
            cdx_url = f"https://web.archive.org/cdx/search/cdx?url=*.{self.target}/*&output=json&fl=original&collapse=urlkey&limit=300"
            req = urllib.request.Request(cdx_url, headers={"User-Agent": "Mozilla/5.0 Moros-AI-Recon"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                rows = json.loads(resp.read().decode("utf-8", errors="ignore"))
                for row in rows[1:]:
                    parsed = urllib.parse.urlparse(row[0])
                    host = parsed.netloc.split(":")[0].lower()
                    if self._host_is_in_root_scope(host, self.target):
                        subdomains.add(host)
            self.log_step(skill, "step-03-web-archives.log", f"Total subdomains after archives: {len(subdomains)}")
        except Exception as e:
            self.log_step(skill, "step-03-web-archives.log", f"Archive query fallback: {e}")

        # Save subdomains
        passive_file = recon_dir / "subdomains-passive.txt"
        all_file = recon_dir / "subdomains-all.txt"
        sorted_subs = sorted(list(subdomains))

        passive_file.write_text("\n".join(sorted_subs), encoding="utf-8")
        all_file.write_text("\n".join(sorted_subs), encoding="utf-8")
        self.log_step(skill, "step-06-merge.log", f"Merged {len(sorted_subs)} unique subdomains to {all_file}")

        # Step 7: Active reachability checks require an authorization document.
        live_hosts = []
        if active_validation:
            # Until an explicit machine-readable multi-host scope is loaded, only
            # the exact configured hostname is eligible for active checks.
            hosts_to_check = [self.target]
            protocols = ["https"] if https_only else ["https", "http"]
            self.log_step(skill, "step-07-live-validation.log",
                          f"Active HEAD checks: {len(hosts_to_check)} host(s), protocols={','.join(protocols)}, timeout=4s.")
            for sub in hosts_to_check:
                for proto in protocols:
                    test_url = f"{proto}://{sub}"
                    try:
                        response = self.http.request(test_url, method="HEAD")
                        if response.get("status") == "response" and response.get("status_code", 0) < 500:
                            response_headers = response.get("headers", {})
                            live_hosts.append({"host": sub, "url": response.get("url", test_url),
                                               "status": response["status_code"],
                                               "server": response_headers.get("server", "Unknown"),
                                               "content_type": response_headers.get("content-type", "")})
                            break
                    except Exception:
                        continue
        else:
            self.log_step(skill, "step-07-live-validation.log", "Skipped active reachability checks because no scope authorization was verified.")

        (recon_dir / "live-hosts.json").write_text(json.dumps(live_hosts, indent=2), encoding="utf-8")
        self.log_step(skill, "step-07-live-validation.log", f"Observed {len(live_hosts)} responsive hosts; an empty list means none answered the probe.")

        # Step 8: Recon summary
        summary_md = f"# Reconnaissance Summary — {self.target}\n\n- Total subdomains from passive sources (including supplied root): {len(sorted_subs)}\n- Responsive hosts observed by HTTP HEAD checks: {len(live_hosts)}\n- Active reachability checks: {'performed' if active_validation else 'skipped (no verified scope)'}\n\n## Observed Hosts\n"
        for h in live_hosts:
            summary_md += f"- **{h['url']}** (Status: {h.get('status')}, Server: {h.get('server')})\n"
        (recon_dir / "recon-summary.md").write_text(summary_md, encoding="utf-8")
        self.log_step(skill, "step-08-summary.log", "Recon summary generated.")

        return {"status": "SUCCESS", "subdomains": len(sorted_subs), "live_hosts": len(live_hosts),
                "active_validation": active_validation}

    # ==================== SKILL 2: API-SPEC-DISCOVERY ====================

    def run_api_spec_discovery(self) -> Dict[str, Any]:
        skill = "api-spec-discovery"
        api_dir = self.output_dir / "api"
        api_dir.mkdir(parents=True, exist_ok=True)
        self.log_step(skill, "step-01-discover.log", f"Checking for OpenAPI / Swagger specs for {self.target}")

        out_file = api_dir / "endpoints.json"
        endpoints = []

        # Check for local spec file in target folder
        local_specs = list(self.target_dir.glob("*.json")) + list(self.target_dir.glob("*.yaml")) + list(self.target_dir.glob("*.yml"))
        imported = False

        for spec_path in local_specs:
            if "openapi" in spec_path.name.lower() or "swagger" in spec_path.name.lower():
                try:
                    cmd = [
                        sys.executable,
                        str(PROJECT_ROOT / "tools" / "openapi_import.py"),
                        "--spec", str(spec_path),
                        "--output", str(out_file),
                        "--target", self.target
                    ]
                    subprocess.run(cmd, capture_output=True, text=True, check=True)
                    self.log_step(skill, "step-02-import.log", f"Imported spec from {spec_path.name}")
                    imported = True
                    break
                except Exception as e:
                    self.log_step(skill, "step-02-import.log", f"Import error: {e}")

        if not imported:
            # Preserve only an inventory that names a real source document. Replace legacy
            # fallback inventories (which had no provenance) with an explicit empty state.
            has_provenance = False
            if out_file.is_file():
                try:
                    prior = json.loads(out_file.read_text(encoding="utf-8"))
                    has_provenance = bool(prior.get("source_file"))
                except (OSError, json.JSONDecodeError):
                    pass
            if not has_provenance:
                out_file.write_text(json.dumps({
                    "target": self.target, "status": "NO_SPEC_PROVIDED",
                    "total_endpoints": 0, "endpoints": [],
                }, indent=2), encoding="utf-8")
                self.log_step(skill, "step-02-import.log", "No local specification found; no endpoints were inferred or fabricated.")
            else:
                self.log_step(skill, "step-02-import.log", "No new local specification found; retained the existing source-linked inventory.")

        return {"status": "SUCCESS" if imported else "NO_SPEC", "imported": imported, "endpoints": 0}

    # ==================== SKILL 3: JS-DISCOVER ====================

    def run_js_discover(self) -> Dict[str, Any]:
        skill = "js-discover"
        js_dir = self.output_dir / "js"
        raw_ext = js_dir / "raw" / "external"
        raw_inline = js_dir / "raw" / "inline"
        raw_lazy = js_dir / "raw" / "lazy-loaded"
        raw_hist = js_dir / "raw" / "historical"
        beautified_dir = js_dir / "beautified"

        for d in [raw_ext, raw_inline, raw_lazy, raw_hist, beautified_dir]:
            d.mkdir(parents=True, exist_ok=True)

        if not self.scope_authorized:
            self.log_step(skill, "step-01-auth-check.log", "Blocked: no matching scope note; no target requests were sent.")
            return {"status": "BLOCKED_SCOPE", "files_collected": 0}

        self.log_step(skill, "step-01-auth-check.log", "Scope note matched the exact configured target; network policy is same-host GET/HEAD only.")
        self.log_step(skill, "step-02-browser-crawl.log", f"Starting bounded same-host browser crawl for {self.http.base_url}")

        remaining = self.http.max_requests - self.http.request_count
        browser_budget = min(20, remaining)
        if browser_budget > 0:
            browser_summary = js_dir / "crawl-summary.json"
            try:
                crawl = subprocess.run(
                    [sys.executable, str(PROJECT_ROOT / "tools" / "browser-crawl.py"),
                     "--target", self.http.base_url, "--output-dir", str(js_dir / "raw"),
                     "--safe-mode", "--max-requests", str(browser_budget),
                     "--request-delay", str(self.http.delay_seconds),
                     "--max-depth", "2", "--max-pages", "2", "--timeout", "15000"],
                    capture_output=True, text=True, timeout=90,
                )
                if browser_summary.is_file():
                    crawl_data = json.loads(browser_summary.read_text(encoding="utf-8"))
                    used = min(browser_budget, int(crawl_data.get("requests_sent", 0)))
                    self.http.record_external_requests(used)
                    self.log_step(skill, "step-02-browser-crawl.log",
                                  f"Safe browser visited {crawl_data.get('pages_visited', 0)} pages; "
                                  f"captured {crawl_data.get('external_js_collected', 0)} bundles and "
                                  f"{crawl_data.get('inline_scripts_collected', 0)} inline scripts; "
                                  f"requests={used}/{browser_budget}.")
                elif crawl.returncode:
                    self.http.record_external_requests(browser_budget)
                    self.log_step(skill, "step-02-browser-crawl.log",
                                  f"Browser crawl unavailable; continuing with bounded HTTP fallback: {crawl.stderr[-500:]}")
                else:
                    self.http.record_external_requests(browser_budget)
                    self.log_step(skill, "step-02-browser-crawl.log",
                                  "Browser crawl produced no summary; reserving its full request budget before fallback.")
            except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError, ValueError) as exc:
                self.http.record_external_requests(browser_budget)
                self.log_step(skill, "step-02-browser-crawl.log",
                              f"Browser crawl fallback: {str(exc)[:300]}")

        collected_files = []
        root_response = self.http.request("/", method="GET")
        if root_response.get("status") == "response":
            html_content = root_response.get("body", "")
            script_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html_content, re.IGNORECASE)
            for i, src in enumerate(script_srcs[:10]):
                full_src = urllib.parse.urljoin(self.http.base_url + "/", src)
                bundle = self.http.request(full_src, method="GET")
                if bundle.get("status") != "response" or bundle.get("status_code") != 200:
                    continue
                fname = re.sub(r'[^\w\-.]', '_', urllib.parse.urlparse(src).path.split("/")[-1] or f"bundle_{i}.js")
                if not fname.endswith(".js"):
                    fname += ".js"
                out_path = raw_ext / fname
                out_path.write_text(bundle.get("body", ""), encoding="utf-8")
                collected_files.append(str(out_path))

            inlines = re.findall(r'<script(?![^>]*src=)[^>]*>(.*?)</script>', html_content,
                                 re.DOTALL | re.IGNORECASE)
            for idx, block in enumerate(inlines):
                if block.strip():
                    inline_path = raw_inline / f"index_block_{idx}.js"
                    inline_path.write_text(block.strip(), encoding="utf-8")
                    collected_files.append(str(inline_path))
        else:
            self.log_step(skill, "step-02-browser-crawl.log",
                          f"Root fetch failed: {root_response.get('error', root_response.get('status'))}")

        # Historical wildcard fetching is intentionally disabled until an explicit
        # multi-host scope allowlist is supported.
        self.log_step(skill, "step-05-historical.log", "Historical wildcard downloads skipped by same-host scope policy.")

        # Step 6: Source map hunter
        try:
            cmd = [
                sys.executable,
                str(PROJECT_ROOT / "tools" / "sourcemap-hunter.py"),
                "--js-dir", str(js_dir / "raw"),
                "--output-dir", str(js_dir / "source-maps"),
            ]
            subprocess.run(cmd, capture_output=True, text=True, timeout=20)
            self.log_step(skill, "step-06-source-maps.log", "Sourcemap hunting completed.")
        except Exception as e:
            self.log_step(skill, "step-06-source-maps.log", f"Sourcemap notice: {e}")

        # Step 7: Beautify all JS
        try:
            cmd = [
                sys.executable,
                str(PROJECT_ROOT / "tools" / "js-beautifier.py"),
                "--input-dir", str(js_dir / "raw"),
                "--output-dir", str(beautified_dir)
            ]
            subprocess.run(cmd, capture_output=True, text=True, check=True)
            self.log_step(skill, "step-07-beautify.log", "JavaScript beautified successfully.")
        except Exception as e:
            self.log_step(skill, "step-07-beautify.log", f"Beautify fallback: {e}")

        # Step 8 & 9: Manifest and Stats
        all_raw = list((js_dir / "raw").rglob("*.js"))
        manifest = {
            "target": self.target,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_files": len(all_raw),
            "files": [str(p.relative_to(js_dir)) for p in all_raw]
        }
        (js_dir / "collection-manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        self.log_step(skill, "step-08-manifest.log", f"Collection manifest saved ({len(all_raw)} files).")

        stats = {
            "target": self.target,
            "external_js_count": len(list(raw_ext.glob("*.js"))),
            "inline_js_count": len(list(raw_inline.glob("*.js"))),
            "historical_js_count": len(list(raw_hist.glob("*.js"))),
        }
        (js_dir / "collection-stats.json").write_text(json.dumps(stats, indent=2), encoding="utf-8")
        self.log_step(skill, "step-09-stats.log", "Collection stats saved.")

        return {"status": "SUCCESS" if all_raw else "NO_ARTIFACTS", "files_collected": len(all_raw)}

    # ==================== SKILL 4: JS-ANALYZE ====================

    def run_js_analyze(self) -> Dict[str, Any]:
        skill = "js-analyze"
        js_dir = self.output_dir / "js"
        beautified_dir = js_dir / "beautified"
        input_target_dir = beautified_dir if beautified_dir.exists() and any(beautified_dir.glob("*.js")) else js_dir / "raw"

        self.log_step(skill, "step-01-verify-input.log", f"Checking beautified JS in {beautified_dir}")

        # Define tools for ReAct Agent
        def tool_extract_endpoints():
            cmd = [
                sys.executable,
                str(PROJECT_ROOT / "tools" / "endpoint-extractor.py"),
                "--input-dir", str(input_target_dir),
                "--output-endpoints", str(js_dir / "endpoints.json"),
                "--output-params", str(js_dir / "parameters.json"),
                "--output-curl", str(js_dir / "curl-commands.sh"),
                "--target-domain", self.target
            ]
            subprocess.run(cmd, capture_output=True, text=True)
            count = 0
            ep_file = js_dir / "endpoints.json"
            if ep_file.exists():
                try:
                    count = len(json.loads(ep_file.read_text(encoding="utf-8")).get("endpoints", []))
                except Exception:
                    pass
            self.log_step(skill, "step-03-endpoints.log", f"Extracted {count} endpoints and parameters.")
            return {"status": "success", "endpoints_count": count, "artifact": str(ep_file)}

        def tool_scan_secrets():
            cmd_sec = [
                sys.executable,
                str(PROJECT_ROOT / "tools" / "secret-scanner.py"),
                "--input-dir", str(js_dir / "raw"),
                "--output", str(js_dir / "secrets-findings.json")
            ]
            subprocess.run(cmd_sec, capture_output=True, text=True)
            sec_file = js_dir / "secrets-findings.json"
            findings = []
            if sec_file.exists():
                try:
                    findings = json.loads(sec_file.read_text(encoding="utf-8")).get("findings", [])
                except Exception:
                    pass
            self.log_step(skill, "step-10-secrets.log", f"Scanned secrets: found {len(findings)} candidates.")
            return {"status": "success", "findings": findings, "artifact": str(sec_file)}

        def tool_extract_dom_gadgets():
            gadgets = []
            gadget_patterns = [
                (r'innerHTML\s*=', "innerHTML assignment"),
                (r'document\.write\s*\(', "document.write invocation"),
                (r'eval\s*\(', "eval execution"),
                (r'location\.href\s*=', "location.href redirect"),
            ]
            for js_p in js_dir.rglob("*.js"):
                try:
                    txt = js_p.read_text(encoding="utf-8", errors="ignore")
                    for pat, label in gadget_patterns:
                        if re.search(pat, txt):
                            gadgets.append({
                                "type": label,
                                "source_file": str(js_p.name),
                                "risk": "MEDIUM — Unsanitized DOM sink",
                                "severity": "Triage Severity: MEDIUM — pending human review"
                            })
                except Exception:
                    pass
            gadgets_file = js_dir / "gadgets.json"
            gadgets_file.write_text(json.dumps({"target": self.target, "gadgets": gadgets}, indent=2), encoding="utf-8")
            self.log_step(skill, "step-05-gadgets.log", f"Identified {len(gadgets)} DOM sink gadgets.")
            return {"status": "success", "gadgets_count": len(gadgets), "artifact": str(gadgets_file)}

        def tool_fingerprint_tech():
            signatures = {
                "React": ("React.createElement", "__REACT_DEVTOOLS_GLOBAL_HOOK__", "react-dom"),
                "Vue": ("Vue.createApp", "__VUE__", "vue.runtime"),
                "Angular": ("ng-version", "@angular/core"),
                "jQuery": ("jQuery", "window.$"),
            }
            js_sources = []
            detected_signatures = []
            bytes_scanned = 0
            for js_path in js_dir.rglob("*.js"):
                if len(js_sources) >= 250 or bytes_scanned >= 20 * 1024 * 1024:
                    break
                try:
                    with js_path.open("rb") as source_file:
                        content = source_file.read(min(1024 * 1024, 20 * 1024 * 1024 - bytes_scanned))
                    bytes_scanned += len(content)
                    source_text = content.decode("utf-8", errors="ignore")
                    js_sources.append(str(js_path.relative_to(js_dir)))
                    for technology, markers in signatures.items():
                        for marker in markers:
                            if marker in source_text:
                                detected_signatures.append({"technology": technology, "marker": marker,
                                                            "source_file": str(js_path.relative_to(js_dir))})
                except OSError as exc:
                    self.log_step(skill, "step-09-fingerprint.log", f"Could not inspect {js_path.name}: {exc}")

            detected = sorted({item["technology"] for item in detected_signatures})
            fingerprint = {
                "target": self.target,
                "frontend": {"framework": detected or "Unknown", "confidence": "signature-based" if detected else "insufficient-evidence"},
                "backend_indicators": {"likely_framework": "Unknown", "confidence": "not-assessed"},
                "known_misconfigs_for_stack": [],
                "collection_status": "analyzed" if js_sources else "no-javascript-artifacts",
                "evidence_files": js_sources,
                "signatures": detected_signatures,
                "bytes_scanned": bytes_scanned,
                "truncated": len(js_sources) >= 250 or bytes_scanned >= 20 * 1024 * 1024,
            }
            tech_file = js_dir / "tech-fingerprint.json"
            tech_file.write_text(json.dumps(fingerprint, indent=2), encoding="utf-8")
            self.log_step(skill, "step-09-fingerprint.log", "Generated technology fingerprint.")
            return {"status": "success", "frameworks": detected, "artifact": str(tech_file)}

        # Register tools in ToolRegistry
        registry = ToolRegistry()
        registry.register("extract_endpoints", tool_extract_endpoints, "Extract HTTP endpoints, parameters, and reproduction cURL commands from JavaScript files.")
        registry.register("scan_secrets", tool_scan_secrets, "Scan collected JavaScript files for hardcoded API keys, tokens, and credentials.")
        registry.register("extract_dom_gadgets", tool_extract_dom_gadgets, "Search JavaScript files for hazardous DOM sinks (eval, innerHTML, document.write).")
        registry.register("fingerprint_tech_stack", tool_fingerprint_tech, "Detect frontend frameworks and client libraries from script markers.")

        def fallback_fn(ctx: AgentContext) -> AgentResult:
            """Deterministic fallback when LLM is unavailable or unconfigured."""
            res_ep = tool_extract_endpoints()
            res_sec = tool_scan_secrets()
            res_gad = tool_extract_dom_gadgets()
            res_tech = tool_fingerprint_tech()

            summary = (
                f"# JavaScript Analysis Summary — {self.target}\n\n"
                f"- Extracted {res_ep.get('endpoints_count', 0)} API endpoints.\n"
                f"- Scanned {len(res_sec.get('findings', []))} secret candidates.\n"
                f"- Found {res_gad.get('gadgets_count', 0)} DOM sinks.\n"
                f"- Detected frameworks: {', '.join(res_tech.get('frameworks', [])) or 'None'}.\n"
            )
            (js_dir / "analysis-summary.md").write_text(summary, encoding="utf-8")
            self.log_step(skill, "step-12-summary.log", "Deterministic fallback analysis completed.")
            return AgentResult(
                status="completed",
                summary=f"Deterministic JS analysis completed for {self.target}",
                findings=res_sec.get("findings", []),
                artifacts=[res_ep.get("artifact", ""), res_sec.get("artifact", ""), res_gad.get("artifact", ""), res_tech.get("artifact", "")],
                next_actions=["content-discovery", "xss-reflected", "ssrf-identify"]
            )

        context = AgentContext(
            target=self.target,
            target_dir=self.target_dir,
            skill=skill,
            run_id=f"js-analyze-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
        )

        agent_runner = AgentRunner(llm_client=self.llm)
        agent_result = agent_runner.run(
            context=context,
            tools=registry,
            system_prompt=(
                f"You are the JavaScript & API Hunter agent analyzing '{self.target}'. "
                "Use the available tools to extract endpoints, scan for leaked credentials, identify DOM sinks, and fingerprint the frontend stack."
            ),
            user_goal=f"Analyze all JavaScript assets of {self.target}. Discover endpoints, parameters, secrets, gadgets, and tech stack.",
            fallback_fn=fallback_fn
        )

        summary_md = js_dir / "analysis-summary.md"
        if not summary_md.exists():
            summary_content = f"# JavaScript Analysis Summary — {self.target}\n\n{agent_result.summary}\n"
            summary_md.write_text(summary_content, encoding="utf-8")
            self.log_step(skill, "step-12-summary.log", "Agent analysis summary generated.")

        return {
            "status": "SUCCESS" if agent_result.status in ["completed", "llm_unavailable"] else "FAILED",
            "agent_status": agent_result.status,
            "summary": agent_result.summary,
            "findings_count": len(agent_result.findings),
        }

    # ==================== SKILL 5: CONTENT-DISCOVERY ====================

    def run_content_discovery(self) -> Dict[str, Any]:
        skill = "content-discovery"
        cd_dir = self.output_dir / "content-discovery"
        cd_dir.mkdir(parents=True, exist_ok=True)

        if not self.scope_authorized:
            self.log_step(skill, "step-06-scan.log", "Blocked: no matching scope note; no target requests were sent.")
            return {"status": "BLOCKED_SCOPE", "paths_checked": 0, "findings_count": 0}

        self.log_step(skill, "step-01-verify.log", "Prerequisites verified.")

        # Low-impact public routes only. Sensitive files, backups, admin paths, and
        # state-changing routes are deliberately excluded from automatic probing.
        combined = [
            "/", "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
            "/openapi.json", "/swagger.json", "/api-docs", "/swagger",
            "/docs", "/health", "/status", "/api", "/search",
        ]

        (cd_dir / "wordlist-generic.txt").write_text("\n".join(combined), encoding="utf-8")
        (cd_dir / "wordlist-framework-specific.txt").write_text("", encoding="utf-8")
        (cd_dir / "wordlist-combined.txt").write_text("\n".join(combined), encoding="utf-8")

        self.log_step(skill, "step-05-combine.log", f"Generated combined wordlist ({len(combined)} paths).")

        probe_results = {}

        def probe_safe_path(path: str) -> Dict[str, Any]:
            path = str(path)
            if path not in combined:
                return {"status": "blocked", "reason": "Path is not in the approved low-impact route list."}
            if path in probe_results:
                return probe_results[path]
            response = self.http.request(path, method="GET")
            row = {key: value for key, value in response.items() if key != "body"}
            row["path"] = path
            probe_results[path] = row
            if row.get("status") != "response":
                self.log_step(skill, "step-06-scan.log",
                              f"{path}: {row.get('status')} {row.get('error', row.get('reason', ''))}")
            return row

        registry = ToolRegistry()
        registry.register(
            "probe_safe_path", probe_safe_path,
            "Send one same-host GET to a path from the fixed low-impact public route list. No other paths or methods are accepted.",
            parameters={"path": {"type": "string", "enum": combined}},
        )

        def deterministic_fallback(_context: AgentContext) -> AgentResult:
            for path in combined:
                probe_safe_path(path)
            return AgentResult(
                status="completed",
                summary=f"Checked {len(probe_results)} low-impact public routes with same-host GET requests.",
                artifacts=[str(cd_dir / "discovered-paths.json")],
                usage={"requests_used": self.http.request_count},
            )

        agent_result = AgentRunner(llm_client=self.llm).run(
            context=AgentContext(
                target=self.target,
                target_dir=self.target_dir,
                skill=skill,
                run_id=f"content-discovery-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
                scope={"allowed_hosts": [self.http.target], "methods": ["GET"],
                       "request_budget": self.http.max_requests},
                budget={"max_steps": min(10, len(combined)), "max_tokens": 2000,
                        "timeout_seconds": 120},
            ),
            tools=registry,
            system_prompt=(
                f"You are Moros's content discovery agent for the authorized host {self.http.target}. "
                "Only choose paths from the tool's fixed enum. Use GET only. Do not request secrets, backups, "
                "admin panels, authentication actions, or state-changing routes. Summarize observed HTTP metadata only."
            ),
            user_goal=("Choose and inspect relevant paths from the safe route list. Prefer robots.txt, sitemap.xml, "
                       "public API documentation, health/status, and the root page. Do not invent paths."),
            fallback_fn=deterministic_fallback,
        )

        discovered = list(probe_results.values())
        interesting = [
            {"path": row["path"], "status_code": row["status_code"],
             "content_type": row.get("headers", {}).get("content-type", ""),
             "classification": "reachable_route_for_manual_review"}
            for row in discovered
            if row.get("status") == "response" and row.get("status_code") in {200, 401, 403}
            and row.get("path") != "/"
        ]
        root_response = probe_results.get("/")

        header_rows = []
        if root_response and root_response.get("status") == "response":
            response_headers = root_response.get("headers", {})
            for header in ["strict-transport-security", "content-security-policy",
                           "x-content-type-options", "x-frame-options", "referrer-policy"]:
                header_rows.append({"header": header, "present": header in response_headers,
                                    "value": response_headers.get(header, "")})

        output = {"target": self.target, "policy": {"methods": ["GET"], "same_host_only": True,
                  "request_budget": self.http.max_requests, "requests_used": self.http.request_count},
                  "paths_checked": discovered, "interesting_routes": interesting,
                  "root_security_headers": header_rows}
        (cd_dir / "discovered-paths.json").write_text(json.dumps(output, indent=2), encoding="utf-8")
        (cd_dir / "interesting-findings.json").write_text(json.dumps(interesting, indent=2), encoding="utf-8")
        summary = (f"# Safe Content Discovery — {self.target}\n\n"
                   f"Sent {len(discovered)} same-host GET checks; {len(interesting)} routes need manual review. "
                   "No credentials, payloads, state-changing methods, or cross-host redirects were used.\n")
        (cd_dir / "content-discovery-summary.md").write_text(summary, encoding="utf-8")

        self.log_step(skill, "step-06-scan.log", f"Completed {len(discovered)} same-host GET checks; request budget used {self.http.request_count}/{self.http.max_requests}; agent={agent_result.status}.")
        return {"status": "COMPLETED", "agent_status": agent_result.status,
                "paths_checked": len(discovered), "findings_count": len(interesting),
                "requests_used": self.http.request_count}

    # ==================== SKILL 6-12: VULNERABILITY TESTING ====================

    def run_vuln_skill(self, skill_name: str) -> Dict[str, Any]:
        v_dir = self.output_dir / "findings" / skill_name
        v_dir.mkdir(parents=True, exist_ok=True)
        self.log_step(skill_name, "step-01-verify.log", f"Starting {skill_name} testing.")
        request_count_before = self.http.request_count

        if not self.scope_authorized:
            self.log_step(skill_name, "step-06-document.log", "Blocked: no matching scope note; no target requests were sent.")
            return {"status": "BLOCKED_SCOPE", "findings_count": 0}

        # Build the candidate surface only from observed JS and imported API artifacts.
        endpoints = []
        for ep_file in [self.output_dir / "js" / "endpoints.json", self.output_dir / "api" / "endpoints.json", self.output_dir / "api" / "openapi-endpoints.json"]:
            if not ep_file.exists():
                continue
            try:
                loaded = json.loads(ep_file.read_text(encoding="utf-8")).get("endpoints", [])
                for endpoint in loaded:
                    if isinstance(endpoint, dict):
                        endpoint["_source_artifact"] = str(ep_file)
                        endpoints.append(endpoint)
            except (OSError, json.JSONDecodeError) as exc:
                self.log_step(skill_name, "step-01-verify.log", f"Could not parse endpoint artifact {ep_file.name}: {exc}")

        findings = []

        # Heuristics create triage candidates. They do not prove exploitability.
        if skill_name == "xss-reflected":
            for ep in endpoints:
                params = ep.get("parameters", [])
                param_names = [p.get("name") if isinstance(p, dict) else p for p in params]
                if ep.get("method", "GET").upper() == "GET" and param_names:
                    param_name = str(param_names[0] or "")
                    url = ep.get("url") or (str(ep.get("base_url", "")).rstrip("/") + str(ep.get("path", "")))
                    parsed_url = urllib.parse.urlparse(url if "://" in url else urllib.parse.urljoin(self.http.base_url + "/", url))
                    if not param_name or parsed_url.hostname != self.http.target or any(
                        token in parsed_url.path.lower() for token in ["logout", "delete", "unsubscribe", "reset", "callback", "track"]
                    ):
                        continue
                    marker = "MOROS_REFLECT_" + hashlib.sha256(f"{url}|{param_name}".encode()).hexdigest()[:12]
                    probe_value = f"<moros-probe>{marker}</moros-probe>"
                    clean_url = urllib.parse.urlunparse(parsed_url._replace(query="", fragment=""))
                    probe = self.http.request(clean_url, method="GET", params={param_name: probe_value})
                    body = probe.get("body", "")
                    if probe.get("status") != "response" or marker not in body:
                        continue
                    context_start = max(0, body.find(marker) - 100)
                    context = body[context_start:body.find(marker) + len(marker) + 100]
                    escaped = f"&lt;moros-probe&gt;{marker.lower()}&lt;/moros-probe&gt;" in body.lower()
                    evidence = self.record_candidate_evidence(
                        skill_name, "Reflected XSS", Path(ep.get("_source_artifact", ep_file)), ep,
                        "A harmless, non-executable HTML marker was reflected in the response. This does not prove script execution.",
                    )
                    probe_artifact = self.output_dir / "evidence" / "http-probes" / (
                        "xss-reflected-" + hashlib.sha256(f"{clean_url}|{param_name}|{marker}".encode()).hexdigest()[:16] + ".json"
                    )
                    probe_artifact.parent.mkdir(parents=True, exist_ok=True)
                    probe_artifact.write_text(json.dumps({
                        "target": self.target,
                        "method": "GET",
                        "url": clean_url,
                        "parameter": param_name,
                        "probe": "non-executable <moros-probe> marker",
                        "marker": marker,
                        "response_status": probe.get("status_code"),
                        "response_sha256": probe.get("body_sha256"),
                        "marker_escaped": escaped,
                        "response_context": context,
                        "script_executed": False,
                    }, indent=2), encoding="utf-8")
                    findings.append({
                        "title": f"Reflected input observed on {url}",
                        "type": "Reflected XSS",
                        "url": url,
                        "parameter": param_name,
                        "status": "candidate",
                        "validation_status": "unverified",
                        "confidence": "medium" if not escaped else "low",
                        "evidence_ids": [evidence["evidence_id"]],
                        "evidence": [{**evidence, "probe_artifact": str(probe_artifact),
                                      "response_sha256": probe.get("body_sha256"),
                                      "response_status": probe.get("status_code"),
                                      "marker_escaped": escaped, "response_context": context}],
                        "severity": "Triage Severity: UNASSESSED — pending evidence and human review",
                        "notes": "A harmless marker was reflected. No script payload was sent or executed; manual context review is required."
                    })
        elif skill_name == "ssrf-identify":
            for ep in endpoints:
                raw_params = ep.get("parameters", [])
                params = [str(p.get("name", "") if isinstance(p, dict) else p).lower() for p in raw_params]
                if any(k in params for k in ["url", "uri", "image_url", "dest", "redirect", "webhook"]):
                    matched_param = next((p for p in params if p in ["url", "uri", "image_url", "dest", "webhook"]), "")
                    evidence = self.record_candidate_evidence(
                        skill_name, "SSRF", Path(ep.get("_source_artifact", ep_file)), ep,
                        f"A URL-like parameter named {matched_param} exists; server-side fetching is unknown.",
                    )
                    findings.append({
                        "title": f"Potential server-side URL input on {ep.get('url') or ep.get('path', 'unknown route')}",
                        "type": "SSRF",
                        "url": ep.get("url") or ep.get("path", ""),
                        "parameter": matched_param,
                        "status": "candidate",
                        "validation_status": "unverified",
                        "confidence": "low",
                        "evidence_ids": [evidence["evidence_id"]],
                        "evidence": [evidence],
                        "severity": "Triage Severity: UNASSESSED — pending evidence and human review",
                        "notes": "Endpoint-shape heuristic only. No outbound request or SSRF behavior was observed."
                    })

        out_findings = v_dir / f"candidates-{skill_name}.json"
        if skill_name == "xss-reflected":
            requests_used = self.http.request_count - request_count_before
            result_status = "COMPLETED"
            summary = (f"Sent {requests_used} same-host GET marker probes. "
                       f"Observed {len(findings)} harmless marker reflections; none is confirmed as executable XSS.")
        elif skill_name == "ssrf-identify":
            result_status = "CANDIDATES_ONLY"
            summary = (f"Recorded {len(findings)} URL-like parameter candidates. "
                       "No SSRF callback or server-side fetch test was sent.")
        else:
            result_status = "NOT_IMPLEMENTED"
            summary = "This skill is not implemented as an active check yet; no vulnerability test was performed."
            findings = []
        out_findings.write_text(json.dumps({"target": self.target, "status": result_status,
                                           "findings": findings}, indent=2), encoding="utf-8")
        (v_dir / f"{skill_name}-summary.md").write_text(
            f"# {skill_name} Assessment — {self.target}\n\n{summary}", encoding="utf-8")
        self.log_step(skill_name, "step-06-document.log",
                      f"Status: {result_status}; {summary}")

        return {"status": result_status, "findings_count": len(findings), "summary": summary,
                "requests_used": self.http.request_count - request_count_before}

    # ==================== DYNAMIC CUSTOM SKILL RUNNER ====================

    def run_custom_skill(self, skill_name: str) -> Dict[str, Any]:
        """Execute a dynamic custom security skill."""
        from skill_registry import SkillRegistry
        registry = SkillRegistry()
        skill_meta = registry.get_skill(skill_name)
        title = skill_meta["title"] if skill_meta else skill_name.replace("-", " ").title()

        v_dir = self.output_dir / "findings"
        v_dir.mkdir(parents=True, exist_ok=True)
        out_findings = v_dir / f"candidates-{skill_name}.json"

        # Discover endpoints
        ep_file = self.output_dir / "recon" / "endpoints.txt"
        if not ep_file.exists():
            ep_file = self.output_dir / "content" / "discovered-endpoints.txt"
        endpoints = []
        if ep_file.exists():
            endpoints = [line.strip() for line in ep_file.read_text(encoding="utf-8").splitlines() if line.strip()]

        findings = []
        summary = f"Custom security audit '{title}' executed against {len(endpoints)} target endpoints."

        for ep in endpoints[:15]:
            if any(k in skill_name.lower() for k in ["api", "jwt", "auth", "token", "oauth", "header"]):
                if any(x in ep.lower() for x in ["auth", "token", "login", "api", "oauth", "v1", "v2"]):
                    findings.append({
                        "title": f"Candidate target for {title}: {ep}",
                        "severity": "MEDIUM",
                        "url": ep,
                        "skill": skill_name,
                        "status": "candidate",
                        "validation_status": "unverified",
                        "notes": f"Identified matching endpoint for custom skill audit '{title}'."
                    })

        out_findings.write_text(json.dumps({
            "target": self.target,
            "skill": skill_name,
            "title": title,
            "status": "COMPLETED",
            "findings": findings
        }, indent=2), encoding="utf-8")

        self.log_step(skill_name, "step-custom-audit.log", f"{title} completed: {len(findings)} candidates identified.")
        return {
            "status": "COMPLETED",
            "skill": skill_name,
            "title": title,
            "findings_count": len(findings),
            "summary": summary
        }

    # ==================== SKILL 13: REVIEW-SKILL ====================

    def run_review_skill(self, target_skill_name: str) -> Dict[str, Any]:
        """Verify completion of the target skill fighting completion bias (Section 6)."""
        review_dir = self.logs_dir / "review"
        review_dir.mkdir(parents=True, exist_ok=True)

        target_skill_log_dir = self.logs_dir / target_skill_name
        logs_exist = target_skill_log_dir.exists() and any(target_skill_log_dir.glob("*.log"))

        # Verify that log files are non-zero byte
        non_zero_logs = []
        if logs_exist:
            for log_p in target_skill_log_dir.glob("*.log"):
                if log_p.stat().st_size > 0:
                    non_zero_logs.append(log_p.name)

        passed = len(non_zero_logs) > 0
        review_result = {
            "skill_reviewed": target_skill_name,
            "target": self.target,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "overall_status": "PASS" if passed else "FAIL",
            "non_zero_logs_count": len(non_zero_logs),
            "logs_verified": non_zero_logs,
        }

        if not passed:
            nudge = (
                f"Your work on {target_skill_name} was just reviewed and it was found that either you missed "
                f"a step of analysis or did not generate an artifact of sufficient proof. Look at the Markdown checklist "
                f"and the output for each step, find what you missed, and complete the step."
            )
            review_result["nudge_prompt"] = nudge

        out_path = review_dir / f"{target_skill_name}-review-1.json"
        out_path.write_text(json.dumps(review_result, indent=2), encoding="utf-8")

        self.log_step("review-skill", f"review-{target_skill_name}.log", f"Review status: {review_result['overall_status']}")
        return review_result

    # ==================== SKILL 14: REPORT-CONGLOMERATION ====================

    def run_report_conglomeration(self) -> Dict[str, Any]:
        skill = "report-conglomeration"
        report_dir = self.output_dir / "report"
        report_dir.mkdir(parents=True, exist_ok=True)

        self.log_step(skill, "step-01-collect.log", "Aggregating all findings from output directories...")

        all_findings = []
        findings_dir = self.output_dir / "findings"
        if findings_dir.exists():
            for p in findings_dir.rglob("*.json"):
                if p.name.startswith(("confirmed-", "candidates-")):
                    try:
                        data = json.loads(p.read_text(encoding="utf-8"))
                        items = data if isinstance(data, list) else data.get("findings", [data])
                        for item in items:
                            if isinstance(item, dict) and "title" in item:
                                # Filenames and model claims never establish validation.
                                finding = dict(item)
                                validation = finding.get("validation_record") or {}
                                human_validation = (
                                    isinstance(validation, dict)
                                    and str(validation.get("verified_by", "")).startswith("human:")
                                    and bool(validation.get("method"))
                                    and bool(validation.get("evidence_ids"))
                                    and validation.get("outcome") == "reproduced"
                                )
                                if not human_validation:
                                    finding["status"] = "candidate"
                                    finding["validation_status"] = "unverified"
                                else:
                                    finding["status"] = "validated"
                                    finding["validation_status"] = "validated"
                                all_findings.append(finding)
                    except Exception:
                        pass

        # Also pull secrets
        sec_file = self.output_dir / "js" / "secrets-findings.json"
        if sec_file.exists():
            try:
                s_data = json.loads(sec_file.read_text(encoding="utf-8"))
                for s in s_data.get("findings", []):
                    all_findings.append({
                        "title": f"Exposed Secret: {s.get('type')}",
                        "severity": s.get("severity", "Triage Severity: MEDIUM — pending human review"),
                        "url": s.get("url"),
                        "source_artifact": s.get("source_file"),
                        "notes": s.get("context", ""),
                        "status": "candidate",
                        "validation_status": "unverified",
                        "confidence": "low",
                        "evidence_fingerprint": s.get("value_fingerprint"),
                    })
            except Exception:
                pass

        date_str = datetime.now(timezone.utc).strftime("%Y%m%d")
        report_md_file = report_dir / f"hackbot-report-{self.target}-{date_str}.md"
        report_json_file = report_dir / f"hackbot-report-{self.target}-{date_str}.json"

        # Generate Full Markdown Report
        md = f"# Penetration Testing Assessment Report — {self.target}\n\n"
        md += f"**Assessment Date:** {datetime.now(timezone.utc).strftime('%Y-%m-%d')}\n"
        md += f"**Target Organization:** {self.target}\n"
        md += "**Compliance Notice:** All findings are tagged `Triage Severity — pending human review`.\n\n"
        candidate_count = sum(f.get("validation_status") != "validated" for f in all_findings)
        validated_count = len(all_findings) - candidate_count
        md += "## Executive Summary\n\n"
        md += f"Moros AI processed artifacts for `{self.target}` and recorded **{len(all_findings)} triage items**: **{candidate_count} unverified candidates** and **{validated_count} validated findings**. An empty result means insufficient observed evidence, not proof of absence.\n\n"
        md += "| Finding Title | Validation | Severity | Affected URL |\n|---|---|---|---|\n"
        for f in all_findings:
            md += f"| {f.get('title')} | {f.get('validation_status', 'unverified')} | {f.get('severity', 'Unassessed')} | `{f.get('url', '-')}` |\n"

        md += "\n## Evidence and Triage Items\n\n"
        for idx, f in enumerate(all_findings, 1):
            md += f"### {idx}. {f.get('title')}\n"
            md += f"- **Validation:** `{f.get('validation_status', 'unverified')}`\n"
            md += f"- **Confidence:** `{f.get('confidence', 'not-scored')}`\n"
            md += f"- **Severity:** `{f.get('severity', 'Unassessed')}`\n"
            md += f"- **Target URL:** `{f.get('url')}`\n"
            if f.get("source_artifact"):
                md += f"- **Source artifact:** `{f.get('source_artifact')}`\n"
            for evidence in f.get("evidence", []):
                md += f"- **Evidence:** `{evidence.get('evidence_id', 'unlinked')}` from `{evidence.get('source_artifact', 'unknown source')}` (SHA256: `{evidence.get('source_sha256', 'unavailable')}`)\n"
            if f.get("curl"):
                md += f"- **Reproduction cURL:**\n```bash\n{f.get('curl')}\n```\n"
            if f.get("notes"):
                md += f"- **Details:** {f.get('notes')}\n"
            md += "\n"

        report_md_file.write_text(md, encoding="utf-8")
        report_json_file.write_text(json.dumps({"target": self.target, "summary": {
            "triage_items": len(all_findings), "unverified_candidates": candidate_count,
            "validated_findings": validated_count,
        }, "findings": all_findings}, indent=2), encoding="utf-8")

        # Generate SARIF 2.1.0 sidecar for GitHub Code Scanning and CI/CD
        sarif_file = report_dir / "findings.sarif"
        try:
            from sarif_exporter import write_sarif_report
            write_sarif_report(sarif_file, all_findings, target=self.target)
        except Exception as e:
            self.log_step(skill, "step-08-sarif-error.log", f"SARIF export failed: {e}")

        self.log_step(skill, "step-07-full-report.log", f"Generated deliverable report: {report_md_file.name}")
        return {
            "status": "SUCCESS",
            "report_path": str(report_md_file),
            "sarif_path": str(sarif_file) if sarif_file.exists() else None,
            "findings_count": len(all_findings),
        }
