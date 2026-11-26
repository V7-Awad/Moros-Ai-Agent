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
import subprocess
import sys
import shutil
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional

tools_dir = Path(__file__).parent.resolve()
if str(tools_dir) not in sys.path:
    sys.path.insert(0, str(tools_dir))

from agent_runtime import AgentRunner, AgentContext, AgentResult, ToolRegistry
import sandbox_manager
from scoped_http import ScopedHttpClient
from finding_review import review_candidates
from finding_dedupe import deduplicate_findings

logger = logging.getLogger("skill-runner")
PROJECT_ROOT = Path(__file__).parent.parent.resolve()


class SkillRunner:
    def __init__(self, target: str, target_dir: Path, llm_client=None,
                 max_http_requests: int = 40, request_delay: float = 0.4,
                 sandbox_mode: Optional[str] = None,
                 max_subagents: Optional[int] = None):
        self.target = target
        self.target_dir = Path(target_dir)
        self.output_dir = self.target_dir / "output"
        self.logs_dir = self.output_dir / "logs"
        self.llm = llm_client
        self._recorded_evidence_ids = None
        self.scope_authorized = False
        self.run_started_at = None
        self.cost_tracker = None
        self.tracer = None
        self.memory_manager = None
        self.model_router = None
        self.trace_id = None
        self.mcp_clients = []
        raw_sb = sandbox_mode if sandbox_mode is not None else os.environ.get("MOROS_SANDBOX_MODE", "local")
        self.sandbox_mode = str(raw_sb or "local").strip().lower() or "local"
        if max_subagents is not None:
            self.max_subagents = max(0, int(max_subagents))
        else:
            try:
                self.max_subagents = max(0, int(os.environ.get("MOROS_MAX_SUBAGENTS", 5)))
            except ValueError:
                self.max_subagents = 5
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

    def record_evidence(self, skill: str, artifact_ref: str, finding_type: str,
                        claim: str, url: str = "") -> dict:
        """Compatibility wrapper delegating to record_candidate_evidence."""
        artifact_path = Path(artifact_ref)
        if not artifact_path.is_absolute():
            candidate = self.output_dir / artifact_ref
            artifact_path = candidate if candidate.exists() else (self.target_dir / artifact_ref)
        return self.record_candidate_evidence(
            skill=skill,
            finding_type=finding_type,
            artifact_path=artifact_path,
            endpoint={"url": url, "parameters": []},
            claim=claim,
        )

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

        policy = getattr(getattr(self.http, "scope_validator", None), "policy", {})
        external_sources_allowed = policy.get("allow_cross_host_sources", True)
        if external_sources_allowed:
            # Certificate transparency and archives are queried only when the
            # assessment policy permits contacting third-party data sources.
            self.log_step(skill, "step-02-ct-logs.log", f"Querying crt.sh for %{self.target}...")
            try:
                url = f"https://crt.sh/?q=%25.{self.target}&output=json"
                req = urllib.request.Request(url, headers={"User-Agent": "MorosAI/1.0 (authorized passive reconnaissance)"})
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

            self.log_step(skill, "step-03-web-archives.log", f"Querying Wayback CDX for *.{self.target}/*...")
            try:
                cdx_url = f"https://web.archive.org/cdx/search/cdx?url=*.{self.target}/*&output=json&fl=original&collapse=urlkey&limit=3000"
                req = urllib.request.Request(cdx_url, headers={"User-Agent": "MorosAI/1.0 (authorized passive reconnaissance)"})
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
        else:
            self.log_step(skill, "step-02-ct-logs.log", "Skipped: scope policy forbids cross-host navigation/data-source requests.")
            self.log_step(skill, "step-03-web-archives.log", "Skipped: scope policy forbids cross-host navigation/data-source requests.")

        # Save subdomains
        passive_file = recon_dir / "subdomains-passive.txt"
        all_file = recon_dir / "subdomains-all.txt"
        sorted_subs = sorted(list(subdomains))

        passive_file.write_text("\n".join(sorted_subs), encoding="utf-8")
        all_file.write_text("\n".join(sorted_subs), encoding="utf-8")
        self.log_step(skill, "step-06-merge.log", f"Merged {len(sorted_subs)} unique subdomains to {all_file}")

        # Step 7: Active reachability checks require an authorization document.
        live_hosts = []
        if active_validation and policy.get("same_host_only"):
            # A same-host-only scope note does not authorize probing discovered
            # subdomains; the root host is the sole permitted destination.
            hosts_to_check = [self.target]
            protocols = ["https"] if https_only else ["https", "http"]
            self.log_step(skill, "step-07-live-validation.log",
                          f"Active HEAD checks restricted to exact target host by scope policy; protocols={','.join(protocols)}.")
            for proto in protocols:
                response = self.http.request(f"{proto}://{self.target}", method="HEAD")
                if response.get("status") == "response" and response.get("status_code", 0) < 500:
                    live_hosts.append({"host": self.target, "url": response.get("url"),
                                       "status": response["status_code"],
                                       "server": response.get("headers", {}).get("server", "Unknown"),
                                       "content_type": response.get("headers", {}).get("content-type", "")})
                    break
        elif active_validation:
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

    # ==================== SKILL 1B: DEEP-RECON (PARALLEL FAN-OUT) ====================

    def run_deep_recon(self, active_validation: bool = False) -> Dict[str, Any]:
        """Parallel fan-out reconnaissance with explicit per-source attribution."""
        from concurrent.futures import ThreadPoolExecutor

        skill = "deep-recon"
        recon_dir = self.output_dir / "recon"
        recon_dir.mkdir(parents=True, exist_ok=True)

        policy = getattr(getattr(self.http, "scope_validator", None), "policy", {})
        external_sources_allowed = policy.get("allow_cross_host_sources", True)
        provenance: Dict[str, set] = {self.target: {"seed_target"}}

        def fetch_crtsh() -> Dict[str, Any]:
            if not external_sources_allowed:
                return {"source": "crt.sh", "subdomains": [], "skipped": True}
            found = []
            try:
                url = f"https://crt.sh/?q=%25.{self.target}&output=json"
                req = urllib.request.Request(url, headers={"User-Agent": "MorosAI/2.3"})
                with urllib.request.urlopen(req, timeout=15) as resp:
                    data = json.loads(resp.read().decode("utf-8", errors="ignore"))
                for item in data:
                    for sub in str(item.get("name_value", "")).split("\n"):
                        sub = sub.strip().lower().lstrip("*.")
                        if self._host_is_in_root_scope(sub, self.target):
                            found.append(sub)
                return {"source": "crt.sh", "subdomains": sorted(set(found)), "error": None}
            except Exception as exc:
                return {"source": "crt.sh", "subdomains": [], "error": str(exc)}

        def fetch_wayback() -> Dict[str, Any]:
            if not external_sources_allowed:
                return {"source": "wayback_cdx", "subdomains": [], "urls": [], "skipped": True}
            found_hosts = []
            found_urls = []
            try:
                cdx_url = (
                    f"https://web.archive.org/cdx/search/cdx?url=*.{self.target}/*"
                    "&output=json&fl=original&collapse=urlkey&limit=2000"
                )
                req = urllib.request.Request(cdx_url, headers={"User-Agent": "MorosAI/2.3"})
                with urllib.request.urlopen(req, timeout=15) as resp:
                    rows = json.loads(resp.read().decode("utf-8", errors="ignore"))
                for row in rows[1:]:
                    raw_url = row[0]
                    host = urllib.parse.urlparse(raw_url).netloc.split(":")[0].lower()
                    if self._host_is_in_root_scope(host, self.target):
                        found_hosts.append(host)
                        found_urls.append(raw_url)
                return {
                    "source": "wayback_cdx",
                    "subdomains": sorted(set(found_hosts)),
                    "urls": found_urls[:200],
                    "error": None,
                }
            except Exception as exc:
                return {"source": "wayback_cdx", "subdomains": [], "urls": [], "error": str(exc)}

        def fingerprint_target() -> Dict[str, Any]:
            if not active_validation:
                return {"source": "http_fingerprint", "wafs": [], "technologies": [], "skipped": True}
            wafs, techs = [], []
            try:
                resp = self.http.request(f"https://{self.target}/")
                if resp.get("status") == "response":
                    from waf_detector import WafDetector
                    from tech_profiler import TechProfiler
                    w_info = WafDetector().inspect_response(
                        resp.get("status_code", 0), resp.get("headers", {}), resp.get("body", "")
                    )
                    wafs = [d["waf"] for d in w_info.get("detected_wafs", [])]
                    t_info = TechProfiler().profile_target(resp.get("headers", {}), resp.get("body", ""))
                    techs = t_info.get("technologies", [])
            except Exception as exc:
                return {"source": "http_fingerprint", "wafs": wafs, "technologies": techs, "error": str(exc)}
            return {"source": "http_fingerprint", "wafs": wafs, "technologies": techs, "error": None}

        with ThreadPoolExecutor(max_workers=3) as pool:
            f_crt = pool.submit(fetch_crtsh)
            f_wb = pool.submit(fetch_wayback)
            f_fp = pool.submit(fingerprint_target)
            crt_res = f_crt.result()
            wb_res = f_wb.result()
            fp_res = f_fp.result()

        for sub in crt_res.get("subdomains", []):
            provenance.setdefault(sub, set()).add("crt.sh")
        for sub in wb_res.get("subdomains", []):
            provenance.setdefault(sub, set()).add("wayback_cdx")

        merged_subs = sorted(provenance.keys())
        (recon_dir / "subdomains-all.txt").write_text("\n".join(merged_subs), encoding="utf-8")

        summary = {
            "target": self.target,
            "total_subdomains": len(merged_subs),
            "subdomains": [{"host": h, "sources": sorted(provenance[h])} for h in merged_subs],
            "wafs_detected": fp_res.get("wafs", []),
            "technologies_detected": fp_res.get("technologies", []),
            "archival_urls_sample": wb_res.get("urls", [])[:50],
            "worker_status": {
                "crt.sh": crt_res.get("error") or ("skipped" if crt_res.get("skipped") else "ok"),
                "wayback_cdx": wb_res.get("error") or ("skipped" if wb_res.get("skipped") else "ok"),
                "http_fingerprint": fp_res.get("error") or ("skipped" if fp_res.get("skipped") else "ok"),
            },
        }
        (recon_dir / "deep-recon-summary.json").write_text(
            json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8"
        )

        # Persist target facts to tiered semantic memory
        try:
            from memory_manager import MemoryManager
            mm = MemoryManager(self.target_dir)
            if fp_res.get("wafs"):
                mm.store_fact("waf", ", ".join(fp_res["wafs"]), category="infrastructure", source="deep-recon")
            if fp_res.get("technologies"):
                mm.store_fact("tech_stack", ", ".join(fp_res["technologies"]), category="infrastructure", source="deep-recon")
            mm.store_fact("subdomain_count", str(len(merged_subs)), category="recon", source="deep-recon")
            mm.record_event("deep_recon", f"Merged {len(merged_subs)} subdomains across parallel workers", skill=skill)
        except Exception as exc:
            logger.debug("MemoryManager write skipped in deep-recon: %s", exc)

        self.log_step(
            skill, "step-01-fanout.log",
            f"Deep recon merged {len(merged_subs)} subdomains; WAFs={fp_res.get('wafs', [])}; Tech={fp_res.get('technologies', [])}",
        )
        return {
            "status": "SUCCESS",
            "subdomains": len(merged_subs),
            "wafs": fp_res.get("wafs", []),
            "technologies": fp_res.get("technologies", []),
        }

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

        traffic_log = js_dir / "traffic-log.json"
        if traffic_log.is_file():
            history_dir = js_dir / "traffic-history"
            history_dir.mkdir(parents=True, exist_ok=True)
            stamp = datetime.fromtimestamp(traffic_log.stat().st_mtime, timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            archived = history_dir / f"traffic-log-{stamp}.json"
            if not archived.exists():
                shutil.copy2(traffic_log, archived)
        traffic_log.write_text("[]", encoding="utf-8")

        remaining = self.http.max_requests - self.http.request_count
        browser_budget = min(50, remaining)
        policy = getattr(getattr(self.http, "scope_validator", None), "policy", {})
        browser_redirect_risk = policy.get("same_host_only") and not policy.get("allow_cross_host_sources", True)
        if browser_redirect_risk:
            # Browser navigation can follow a cross-host HTTP redirect before a
            # request route is re-applied. Use ScopedHttpClient below, whose
            # redirect handler rejects hosts outside the exact target.
            self.log_step(skill, "step-02-browser-crawl.log",
                          "Browser crawl skipped: strict same-host policy cannot safely constrain automatic cross-host redirects; using scoped HTTP fallback.")
        elif browser_budget > 0:
            browser_summary = js_dir / "crawl-summary.json"
            try:
                crawl = subprocess.run(
                    [sys.executable, str(PROJECT_ROOT / "tools" / "browser-crawl.py"),
                     "--target", self.http.base_url, "--output-dir", str(js_dir / "raw"),
                     "--safe-mode", "--max-requests", str(browser_budget),
                     "--request-delay", str(self.http.delay_seconds),
                     *( ["--exact-host-only"] if not policy.get("allow_cross_host_sources", True) else [] ),
                     "--max-depth", "3", "--max-pages", "10", "--timeout", "20000"],
                    capture_output=True, text=True, timeout=120,
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
            final_url = root_response.get("url") or self.http.base_url
            for i, src in enumerate(script_srcs[:100]):
                full_src = urllib.parse.urljoin(final_url + "/", src)
                parsed_src = urllib.parse.urlparse(full_src)
                from scoped_http import is_in_target_scope
                if not is_in_target_scope(parsed_src.hostname, self.http.target):
                    continue
                bundle = self.http.request(full_src, method="GET")
                if bundle.get("status") != "response" or bundle.get("status_code") != 200:
                    continue
                clean_path = parsed_src.path.rstrip("/")
                fname = re.sub(r'[^\w\-.]', '_', clean_path.split("/")[-1] or f"bundle_{i}.js")
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
                "React": ("React.createElement", "__REACT_DEVTOOLS_GLOBAL_HOOK__", "react-dom", "react.production.min.js"),
                "Next.js": ("__NEXT_DATA__", "_next/static", "next/router"),
                "Vue": ("Vue.createApp", "__VUE__", "vue.runtime", "vue.min.js"),
                "Nuxt": ("__NUXT__", "_nuxt/"),
                "Angular": ("ng-version", "@angular/core", "ng-app"),
                "Svelte": ("svelte-", "__svelte"),
                "jQuery": ("jQuery", "window.$", "jQuery.fn"),
                "Alpine.js": ("Alpine.data", "x-data", "x-init"),
                "HTMX": ("htmx.org", "hx-get", "hx-post"),
                "Astro": ("astro-island", "astro:"),
                "Webpack": ("webpackChunk", "__webpack_require__"),
                "Vite": ("/@vite/client", "__vite_plugin_"),
            }
            js_sources = []
            detected_signatures = []
            bytes_scanned = 0
            for js_path in js_dir.rglob("*.js"):
                if len(js_sources) >= 1000 or bytes_scanned >= 100 * 1024 * 1024:
                    break
                try:
                    with js_path.open("rb") as source_file:
                        content = source_file.read(min(1024 * 1024, 100 * 1024 * 1024 - bytes_scanned))
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

        # High-value non-destructive public discovery routes: API specs, docs,
        # health/status, GraphQL, discovery indices, and common application entrypoints.
        combined = [
            "/", "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
            "/.well-known/openid-configuration", "/.well-known/assetlinks.json",
            "/.well-known/apple-app-site-association",
            "/openapi.json", "/openapi.yaml", "/swagger.json", "/swagger.yaml",
            "/swagger/v1/swagger.json", "/swagger-ui.html", "/api-docs", "/v2/api-docs",
            "/v3/api-docs", "/docs", "/api/docs", "/swagger", "/apidocs",
            "/graphql", "/graphiql", "/api/graphql", "/query",
            "/health", "/healthz", "/livez", "/readyz", "/status", "/ping",
            "/metrics", "/info", "/actuator", "/actuator/health", "/actuator/info",
            "/api", "/api/v1", "/api/v2", "/api/v3", "/api/health", "/api/status",
            "/api/version", "/version", "/build-info",
            "/search", "/login", "/auth", "/oauth/authorize",
            "/static", "/assets", "/public", "/dist",
            "/server-status", "/env", "/config", "/manifest.json",
            "/favicon.ico", "/crossdomain.xml", "/clientaccesspolicy.xml",
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
                budget={"max_steps": min(35, len(combined)), "max_tokens": 4000,
                        "timeout_seconds": 240},
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
            oob_base = (os.environ.get("MOROS_OOB_URL") or os.environ.get("MOROS_CALLBACK_URL") or "").strip()
            for ep in endpoints:
                raw_params = ep.get("parameters", [])
                params = [str(p.get("name", "") if isinstance(p, dict) else p).lower() for p in raw_params]
                if any(k in params for k in ["url", "uri", "image_url", "dest", "redirect", "webhook"]):
                    matched_param = next((p for p in params if p in ["url", "uri", "image_url", "dest", "webhook"]), "")
                    ep_url = ep.get("url") or ep.get("path", "")
                    canary_url = None
                    if oob_base:
                        token = f"ssrf-{hashlib.sha256(f'{ep_url}:{matched_param}'.encode('utf-8')).hexdigest()[:10]}"
                        canary_url = f"{oob_base.rstrip('/')}/{token}"
                    evidence = self.record_candidate_evidence(
                        skill_name, "SSRF", Path(ep.get("_source_artifact", ep_file)), ep,
                        f"A URL-like parameter named {matched_param} exists; server-side fetching is unknown.",
                    )
                    findings.append({
                        "title": f"Potential server-side URL input on {ep.get('url') or ep.get('path', 'unknown route')}",
                        "type": "SSRF",
                        "url": ep_url,
                        "parameter": matched_param,
                        "callback_listener_configured": bool(oob_base),
                        "oob_canary_url": canary_url,
                        "status": "candidate",
                        "validation_status": "unverified",
                        "confidence": "low",
                        "evidence_ids": [evidence["evidence_id"]],
                        "evidence": [evidence],
                        "severity": "Triage Severity: UNASSESSED — pending evidence and human review",
                        "notes": "Endpoint-shape heuristic only. No outbound request or SSRF behavior was observed."
                    })

        elif skill_name == "xss-dom":
            # Scan collected JS bundles for dangerous DOM sources and sinks
            js_dir = self.output_dir / "js"
            js_candidates = list((js_dir / "beautified").rglob("*.js")) or list((js_dir / "raw").rglob("*.js"))
            sink_patterns = [
                ("innerHTML", re.compile(r'\.innerHTML\s*=', re.IGNORECASE)),
                ("outerHTML", re.compile(r'\.outerHTML\s*=', re.IGNORECASE)),
                ("document.write", re.compile(r'document\.(write|writeln)\s*\(', re.IGNORECASE)),
                ("insertAdjacentHTML", re.compile(r'\.insertAdjacentHTML\s*\(', re.IGNORECASE)),
                ("eval", re.compile(r'\beval\s*\(', re.IGNORECASE)),
                ("setTimeout", re.compile(r'\bsetTimeout\s*\(\s*["\'`]', re.IGNORECASE)),
                ("location.href", re.compile(r'location\.(href|assign|replace)\s*=', re.IGNORECASE)),
            ]
            source_patterns = [
                ("location.search", re.compile(r'location\.(search|hash|pathname|href)', re.IGNORECASE)),
                ("document.URL", re.compile(r'document\.(URL|documentURI|referrer)', re.IGNORECASE)),
                ("window.name", re.compile(r'window\.name', re.IGNORECASE)),
            ]
            for js_path in js_candidates[:60]:
                try:
                    content = js_path.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    continue
                for sink_name, sink_re in sink_patterns:
                    matches = list(sink_re.finditer(content))
                    if not matches:
                        continue
                    m = matches[0]
                    line_no = content[:m.start()].count("\n") + 1
                    snippet = content[max(0, m.start() - 60):min(len(content), m.end() + 60)].strip()
                    has_source = any(src_re.search(content) for _, src_re in source_patterns)
                    evidence = self.record_candidate_evidence(
                        skill_name, "DOM XSS", js_path, {"file": js_path.name, "sink": sink_name, "line": line_no},
                        f"Potentially dangerous DOM sink '{sink_name}' identified at line {line_no} in {js_path.name}.",
                    )
                    findings.append({
                        "title": f"Potential DOM XSS Sink '{sink_name}' in {js_path.name}",
                        "type": "DOM XSS",
                        "url": f"{self.http.base_url}/{js_path.name}#L{line_no}",
                        "sink": sink_name,
                        "line": line_no,
                        "snippet": snippet,
                        "has_source_co_located": has_source,
                        "status": "candidate",
                        "validation_status": "unverified",
                        "confidence": "medium" if has_source else "low",
                        "evidence_ids": [evidence["evidence_id"]],
                        "evidence": [evidence],
                        "severity": "Triage Severity: UNASSESSED — pending evidence and human review",
                        "notes": f"DOM sink '{sink_name}' detected. Static analysis candidate; manual context trace to source is required."
                    })

        elif skill_name == "xss-stored":
            storage_params = {"comment", "message", "body", "bio", "content", "text", "description", "title", "name", "feedback", "review", "note", "status", "profile", "post"}
            for ep in endpoints:
                raw_params = ep.get("parameters", [])
                params = [str(p.get("name", "") if isinstance(p, dict) else p).lower() for p in raw_params]
                matched = [p for p in params if p in storage_params]
                url = ep.get("url") or (str(ep.get("base_url", "")).rstrip("/") + str(ep.get("path", "")))
                is_storage_route = any(w in url.lower() for w in ["comment", "feedback", "review", "profile", "message", "post", "ticket"])
                if matched or is_storage_route:
                    param_name = matched[0] if matched else "path_context"
                    evidence = self.record_candidate_evidence(
                        skill_name, "Stored XSS", Path(ep.get("_source_artifact", ep_file)), ep,
                        f"Stored input candidate parameter '{param_name}' or route '{url}' identified.",
                    )
                    findings.append({
                        "title": f"Stored Input Candidate on {url}",
                        "type": "Stored XSS",
                        "url": url,
                        "parameter": param_name,
                        "status": "candidate",
                        "validation_status": "unverified",
                        "confidence": "low",
                        "evidence_ids": [evidence["evidence_id"]],
                        "evidence": [evidence],
                        "severity": "Triage Severity: UNASSESSED — pending evidence and human review",
                        "notes": "Identified parameter or endpoint structure indicative of persistent data storage. No stored payload was submitted."
                    })

        elif skill_name == "xss-blind":
            blind_params = {"contact", "feedback", "support", "ticket", "inquiry", "report", "bug", "message", "subject", "email_body", "user_agent", "referrer"}
            callback_listener = (os.environ.get("MOROS_OOB_URL") or os.environ.get("MOROS_CALLBACK_URL") or "").strip()
            for ep in endpoints:
                raw_params = ep.get("parameters", [])
                params = [str(p.get("name", "") if isinstance(p, dict) else p).lower() for p in raw_params]
                matched = [p for p in params if p in blind_params]
                url = ep.get("url") or (str(ep.get("base_url", "")).rstrip("/") + str(ep.get("path", "")))
                is_blind_route = any(w in url.lower() for w in ["contact", "support", "feedback", "report", "ticket", "help"])
                if matched or is_blind_route:
                    param_name = matched[0] if matched else "contact_context"
                    evidence = self.record_candidate_evidence(
                        skill_name, "Blind XSS", Path(ep.get("_source_artifact", ep_file)), ep,
                        f"Out-of-band / asynchronous input candidate on parameter '{param_name}'.",
                    )
                    findings.append({
                        "title": f"Blind XSS Candidate Entry Point on {url}",
                        "type": "Blind XSS",
                        "url": url,
                        "parameter": param_name,
                        "callback_listener_configured": bool(callback_listener),
                        "status": "candidate",
                        "validation_status": "unverified",
                        "confidence": "low",
                        "evidence_ids": [evidence["evidence_id"]],
                        "evidence": [evidence],
                        "severity": "Triage Severity: UNASSESSED — pending evidence and human review",
                        "notes": "Candidate for asynchronous / admin-rendered XSS. Safe OOB monitoring recommended."
                    })

        elif skill_name == "ssrf-post-exploit":
            ssrf_cand_file = self.output_dir / "findings" / "ssrf-identify" / "candidates-ssrf-identify.json"
            if not ssrf_cand_file.is_file():
                ssrf_cand_file = v_dir / "candidates-ssrf-identify.json"
            upstream_candidates = []
            if ssrf_cand_file.is_file():
                try:
                    c_data = json.loads(ssrf_cand_file.read_text(encoding="utf-8"))
                    upstream_candidates = c_data.get("findings", [])
                except Exception:
                    pass
            for cand in upstream_candidates:
                cand_url = cand.get("url", "")
                param = cand.get("parameter", "")
                evidence = self.record_candidate_evidence(
                    skill_name, "SSRF Post-Exploit", ssrf_cand_file, cand,
                    f"Generated remediation & post-exploitation assessment vectors for SSRF candidate {cand_url} (param: {param}).",
                )
                findings.append({
                    "title": f"SSRF Impact Analysis & Boundary Vectors for {cand_url}",
                    "type": "SSRF Post-Exploit",
                    "url": cand_url,
                    "parameter": param,
                    "boundary_vectors": [
                        {"target": "AWS Metadata (IMDSv1)", "url": "http://169.254.169.254/latest/meta-data/"},
                        {"target": "GCP Metadata", "url": "http://metadata.google.internal/computeMetadata/v1/"},
                        {"target": "Localhost Services", "url": "http://127.0.0.1:8080/"},
                        {"target": "RFC 1918 Internal Ranges", "cidr": "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16"},
                    ],
                    "status": "candidate",
                    "validation_status": "unverified",
                    "confidence": "low",
                    "evidence_ids": [evidence["evidence_id"]],
                    "evidence": [evidence],
                    "severity": "Triage Severity: UNASSESSED — pending evidence and human review",
                    "notes": "Post-exploitation boundary map generated. Active metadata probes require explicit scope authorization and HITL approval."
                })

        elif skill_name == "idp-race-condition":
            race_tokens = ["oauth", "token", "authorize", "callback", "exchange", "coupon", "redeem", "transfer", "invite", "mfa", "otp", "claim", "gift"]
            for ep in endpoints:
                url = ep.get("url") or (str(ep.get("base_url", "")).rstrip("/") + str(ep.get("path", "")))
                if any(w in url.lower() for w in race_tokens):
                    evidence = self.record_candidate_evidence(
                        skill_name, "Race Condition", Path(ep.get("_source_artifact", ep_file)), ep,
                        f"State mutation or one-time redemption route '{url}' identified as race condition candidate.",
                    )
                    findings.append({
                        "title": f"Candidate IdP / State Mutation Race Condition on {url}",
                        "type": "Race Condition",
                        "url": url,
                        "status": "candidate",
                        "validation_status": "unverified",
                        "confidence": "low",
                        "evidence_ids": [evidence["evidence_id"]],
                        "evidence": [evidence],
                        "severity": "Triage Severity: UNASSESSED — pending evidence and human review",
                        "notes": "Single-use token or stateful exchange route identified. Concurrency testing requires authorized multi-request burst evaluation."
                    })

        elif skill_name == "auth-password-reset-bruteforce":
            reset_tokens = ["forgot", "reset", "recover", "verify-otp", "verify-code", "challenge", "password_reset"]
            for ep in endpoints:
                url = ep.get("url") or (str(ep.get("base_url", "")).rstrip("/") + str(ep.get("path", "")))
                if any(w in url.lower() for w in reset_tokens):
                    parsed = urllib.parse.urlparse(url if "://" in url else urllib.parse.urljoin(self.http.base_url + "/", url))
                    clean_url = urllib.parse.urlunparse(parsed._replace(query="", fragment=""))
                    headers_found = {}
                    if parsed.hostname == self.http.target:
                        probe = self.http.request(clean_url, method="HEAD")
                        headers_found = probe.get("headers", {})
                    has_ratelimit = any(k.startswith(("x-ratelimit", "retry-after")) for k in headers_found)
                    evidence = self.record_candidate_evidence(
                        skill_name, "Password Reset Flow", Path(ep.get("_source_artifact", ep_file)), ep,
                        f"Password reset / recovery route '{url}' identified (Rate limit headers present: {has_ratelimit}).",
                    )
                    findings.append({
                        "title": f"Authentication Recovery Endpoint: {url}",
                        "type": "Auth Password Reset",
                        "url": url,
                        "rate_limiting_detected": has_ratelimit,
                        "status": "candidate",
                        "validation_status": "unverified",
                        "confidence": "low" if has_ratelimit else "medium",
                        "evidence_ids": [evidence["evidence_id"]],
                        "evidence": [evidence],
                        "severity": "Triage Severity: UNASSESSED — pending evidence and human review",
                        "notes": "Password reset flow evaluated. Anti-automation, token entropy, and rate limiting verification recommended."
                    })

        out_findings = v_dir / f"candidates-{skill_name}.json"
        if skill_name == "xss-reflected":
            requests_used = self.http.request_count - request_count_before
            result_status = "COMPLETED"
            summary = (f"Sent {requests_used} same-host GET marker probes. "
                       f"Observed {len(findings)} harmless marker reflections; none is confirmed as executable XSS.")
        elif skill_name == "xss-dom":
            result_status = "COMPLETED"
            summary = (f"Analyzed JavaScript artifacts for DOM XSS sources & sinks. "
                       f"Identified {len(findings)} candidate sink locations.")
        elif skill_name in ["xss-stored", "xss-blind"]:
            result_status = "CANDIDATES_ONLY"
            summary = (f"Recorded {len(findings)} candidate entry points for {skill_name}. "
                       "Active payload storage / OOB callbacks were not triggered.")
        elif skill_name == "ssrf-identify":
            result_status = "CANDIDATES_ONLY"
            summary = (f"Recorded {len(findings)} URL-like parameter candidates. "
                       "No SSRF callback or server-side fetch test was sent.")
        elif skill_name == "ssrf-post-exploit":
            result_status = "COMPLETED"
            summary = (f"Mapped boundary exploitation vectors for {len(findings)} SSRF candidates. "
                       "No unauthorized cloud metadata egress was attempted.")
        elif skill_name == "idp-race-condition":
            result_status = "CANDIDATES_ONLY"
            summary = (f"Identified {len(findings)} state mutation / token redemption race condition candidates. "
                       "No concurrent request flooding was executed.")
        elif skill_name == "auth-password-reset-bruteforce":
            requests_used = self.http.request_count - request_count_before
            result_status = "COMPLETED"
            summary = (f"Evaluated {len(findings)} password reset and recovery mechanisms ({requests_used} HEAD probes).")
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
        """Execute a dynamic custom security skill using scripts, ReAct agent loop, or smart heuristics."""
        import subprocess
        from skill_registry import SkillRegistry, SKILLS_DIR
        from agent_runtime import AgentContext, AgentRunner, build_default_agent_tools

        registry = SkillRegistry()
        skill_meta = registry.get_skill(skill_name)
        title = skill_meta["title"] if skill_meta else skill_name.replace("-", " ").title()
        description = skill_meta.get("description", "") if skill_meta else ""

        v_dir = self.output_dir / "findings"
        v_dir.mkdir(parents=True, exist_ok=True)
        out_findings = v_dir / f"candidates-{skill_name}.json"

        # Check for dedicated execution script in skills/<skill_name>/
        skill_folder = SKILLS_DIR / skill_name
        script_candidates = ["run.py", "execute.py", "audit.py"]
        exec_script = next((skill_folder / s for s in script_candidates if (skill_folder / s).is_file()), None)

        findings = []
        summary = ""

        if exec_script:
            script_source = exec_script.read_text(encoding="utf-8", errors="ignore")
            unscoped_network_patterns = (
                r"\b(?:import|from)\s+requests\b",
                r"\brequests\.(?:get|post|put|patch|delete|head|options|request|Session|session|api|adapters)\b",
                r"\burllib\.request\b", r"\bfrom\s+urllib\s+import\s+request\b", r"\burllib3\b",
                r"\b(?:import|from)\s+httpx\b",
                r"\bhttpx\.(?:get|post|put|patch|delete|head|options|request|Client|AsyncClient)\b",
                r"\bhttpcore\b", r"\baiohttp\b",
                r"\b(?:import|from)\s+socket\b",
                r"\bsocket\.(?:socket|create_connection|getaddrinfo|gethostbyname)\b",
                r"\bhttp\.client\b", r"\bfrom\s+http\s+import\s+client\b",
                r"\bplaywright\b", r"\bselenium\b",
                r"\bsubprocess\b", r"\bos\.system\s*\(", r"\bos\.popen\s*\(",
            )
            if any(re.search(pattern, script_source, re.IGNORECASE) for pattern in unscoped_network_patterns):
                reason = (
                    f"Custom script '{exec_script.name}' contains direct network/process APIs and does not use "
                    "the shared scope-enforced HTTP client. Execution blocked until it is migrated to the shared client."
                )
                self.log_step(skill_name, "step-custom-audit.log", f"BLOCKED_SCOPE: {reason}")
                return {"status": "BLOCKED_SCOPE", "findings_count": 0, "summary": reason}
            self.log_step(skill_name, "step-custom-audit.log", f"Executing custom skill script: {exec_script.name}")
            cmd = [
                sys.executable,
                str(exec_script.resolve()),
                "--target", self.target,
                "--target-dir", str(self.target_dir.resolve()),
                "--output-dir", str(self.output_dir.resolve()),
            ]
            sandbox_mode = str(
                getattr(self, "sandbox_mode", None) or os.environ.get("MOROS_SANDBOX_MODE", "local")
            ).strip().lower() or "local"

            if sandbox_mode == "none":
                try:
                    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                    if proc.stdout:
                        self.log_step(skill_name, "script-stdout.log", proc.stdout)
                    if proc.stderr:
                        self.log_step(skill_name, "script-stderr.log", proc.stderr)
                except Exception as e:
                    self.log_step(skill_name, "step-custom-audit.log", f"Script execution warning: {e}")
            else:
                extra_env: Dict[str, str] = {}
                if "MOROS_HTTP_REQUESTS_REMAINING" not in os.environ and hasattr(self.http, "max_requests"):
                    extra_env["MOROS_HTTP_REQUESTS_REMAINING"] = str(
                        max(0, self.http.max_requests - self.http.request_count)
                    )
                if "MOROS_REQUEST_DELAY" not in os.environ and hasattr(self.http, "delay_seconds"):
                    extra_env["MOROS_REQUEST_DELAY"] = str(self.http.delay_seconds)
                try:
                    with sandbox_manager.create_sandbox(sandbox_mode, extra_env=extra_env, scrub_secrets=True) as sb:
                        sb_res = sb.run_command(cmd, timeout=120)
                    if sb_res.stdout:
                        self.log_step(skill_name, "script-stdout.log", sb_res.stdout)
                    if sb_res.stderr:
                        self.log_step(skill_name, "script-stderr.log", sb_res.stderr)
                    if sb_res.timed_out:
                        self.log_step(
                            skill_name,
                            "step-custom-audit.log",
                            f"Script execution timed out in {sb_res.backend} sandbox.",
                        )
                except Exception as e:
                    self.log_step(
                        skill_name,
                        "step-custom-audit.log",
                        f"Sandbox error ({e}); falling back to scrubbed subprocess.",
                    )
                    try:
                        proc = subprocess.run(
                            cmd,
                            env=sandbox_manager.build_scrubbed_env(extra_env),
                            capture_output=True,
                            text=True,
                            timeout=120,
                        )
                        if proc.stdout:
                            self.log_step(skill_name, "script-stdout.log", proc.stdout)
                        if proc.stderr:
                            self.log_step(skill_name, "script-stderr.log", proc.stderr)
                    except Exception as sub_e:
                        self.log_step(skill_name, "step-custom-audit.log", f"Script execution warning: {sub_e}")

            # Read any findings generated by the script
            if out_findings.exists():
                try:
                    data = json.loads(out_findings.read_text(encoding="utf-8"))
                    findings = data if isinstance(data, list) else data.get("findings", [])
                except Exception:
                    pass
            summary = f"Custom script '{exec_script.name}' executed for {title} with {len(findings)} findings."

        else:
            # ReAct Agent Execution or Heuristic Fallback
            # Load endpoints
            ep_file = self.output_dir / "recon" / "endpoints.txt"
            if not ep_file.exists():
                ep_file = self.output_dir / "content" / "discovered-endpoints.txt"
            endpoints = []
            if ep_file.exists():
                endpoints = [line.strip() for line in ep_file.read_text(encoding="utf-8").splitlines() if line.strip()]

            # Try LLM ReAct agent execution if LLM is available
            if self.llm and self.llm.is_available():
                self.log_step(skill_name, "step-custom-audit.log", f"Launching autonomous ReAct agent for {title} with {self.llm.provider}/{self.llm.model}")
                sandbox_mode = str(
                    getattr(self, "sandbox_mode", None) or os.environ.get("MOROS_SANDBOX_MODE", "local")
                ).strip().lower() or "local"
                max_subagents = getattr(self, "max_subagents", 5)
                ctx = AgentContext(
                    target=self.target,
                    target_dir=self.target_dir,
                    skill=skill_name,
                    run_id=f"run-{skill_name}",
                    scope={
                        "allowed_hosts": [self.http.target],
                        "methods": getattr(self.http.scope_validator, "policy", {}).get("allowed_methods", ["GET", "HEAD"]),
                        "request_budget": max(0, self.http.max_requests - self.http.request_count),
                        "request_delay": self.http.delay_seconds,
                    },
                    budget={"max_steps": 6, "max_tokens": 4000, "timeout_seconds": 120,
                            "request_budget": max(0, self.http.max_requests - self.http.request_count),
                            "request_delay": self.http.delay_seconds,
                            "max_subagents": max_subagents},
                    max_subagents=max_subagents,
                    sandbox_mode=sandbox_mode,
                )
                tools = build_default_agent_tools(
                    ctx, llm_client=self.llm, allow_subagents=True,
                    max_subagents=max_subagents, http_client=self.http,
                    sandbox_mode=sandbox_mode,
                )
                for client in getattr(self, "mcp_clients", []) or []:
                    try:
                        tools.register_mcp_client(client)
                    except Exception as exc:
                        logger.debug("MCP client tool registration skipped: %s", exc)
                system_prompt = (
                    f"You are an expert security researcher executing the custom skill: '{title}'.\n"
                    f"Target: {self.target}\n"
                    f"Skill Description: {description}\n\n"
                    "Instructions:\n"
                    "1. Discover endpoints or code relevant to this security category.\n"
                    "2. You can use 'spawn_subagent' if you need a specialized child investigator on a complex endpoint.\n"
                    "3. Record any candidate findings using 'record_finding'.\n"
                    "4. Conclude with 'Final Answer: <concise summary>'."
                )
                user_goal = f"Execute offensive audit for '{title}' against {self.target}. Endpoints available: {len(endpoints)}"
                try:
                    from agent_security import ActionBudget
                    action_budget = ActionBudget()
                except ImportError:
                    action_budget = None
                runner = AgentRunner(
                    llm_client=self.llm,
                    cost_tracker=getattr(self, "cost_tracker", None),
                    tracer=getattr(self, "tracer", None),
                    memory_manager=getattr(self, "memory_manager", None),
                    action_budget=action_budget,
                    model_router=getattr(self, "model_router", None),
                    trace_id=getattr(self, "trace_id", None),
                    max_subagents=max_subagents,
                    sandbox_mode=sandbox_mode,
                )
                agent_res = runner.run(ctx, tools, system_prompt, user_goal)
                summary = agent_res.summary

                if out_findings.exists():
                    try:
                        data = json.loads(out_findings.read_text(encoding="utf-8"))
                        findings = data if isinstance(data, list) else data.get("findings", [])
                    except Exception:
                        pass

            # If no LLM or agent found 0 items, apply smart heuristic inspection
            if not findings:
                # Heuristic keyword matching on endpoints and JS bundles
                keywords = [k for k in skill_name.lower().split("-") if k not in ["audit", "check", "scanner", "hunter", "custom", "skill"]]
                matching_eps = [ep for ep in endpoints if any(kw in ep.lower() for kw in keywords)]

                for ep in matching_eps[:10]:
                    findings.append({
                        "title": f"Candidate target for {title}: {ep}",
                        "severity": "MEDIUM",
                        "url": ep if "://" in ep else f"https://{self.target}{ep if ep.startswith('/') else '/' + ep}",
                        "skill": skill_name,
                        "status": "candidate",
                        "validation_status": "unverified",
                        "notes": f"Identified matching attack surface route for {title}.",
                    })
                summary = f"Completed {title} audit: {len(findings)} candidates identified across {len(endpoints)} routes."

        # Write consolidated findings
        out_findings.write_text(json.dumps({
            "target": self.target,
            "skill": skill_name,
            "title": title,
            "status": "COMPLETED",
            "findings": findings
        }, indent=2), encoding="utf-8")

        for f in findings:
            self.record_candidate_evidence(
                skill=skill_name,
                finding_type=f.get("title", title),
                artifact_path=out_findings,
                endpoint={"url": f.get("url", ""), "parameters": []},
                claim=f.get("notes", title),
            )

        self.log_step(skill_name, "step-custom-audit.log", f"{title} completed: {len(findings)} candidates recorded.")
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
            retry_note = (
                f"Automated verification for {target_skill_name} failed: missing expected output artifacts or zero-byte logs. "
                f"Check required methodology steps and repeat unverified checks."
            )
            review_result["retry_directive"] = retry_note
            review_result["nudge_prompt"] = retry_note

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

        def generated_this_run(path: Path) -> bool:
            if self.run_started_at is None:
                return True
            try:
                return path.stat().st_mtime >= self.run_started_at.timestamp()
            except OSError:
                return False

        if findings_dir.exists():
            for p in findings_dir.rglob("*.json"):
                if p.name.startswith(("confirmed-", "candidates-")) and generated_this_run(p):
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
        if sec_file.exists() and generated_this_run(sec_file):
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

        # Pull interesting content discovery findings
        cd_file = self.output_dir / "content-discovery" / "interesting-findings.json"
        if cd_file.exists() and generated_this_run(cd_file):
            try:
                cd_data = json.loads(cd_file.read_text(encoding="utf-8"))
                cd_items = cd_data if isinstance(cd_data, list) else cd_data.get("findings", [])
                for item in cd_items:
                    if isinstance(item, dict) and ("url" in item or "path" in item):
                        all_findings.append({
                            "title": item.get("title") or f"Sensitive Route Discovered: {item.get('path', item.get('url'))}",
                            "type": "Content Discovery",
                            "severity": item.get("severity", "Triage Severity: LOW — informational route"),
                            "url": item.get("url") or f"{self.http.base_url}{item.get('path', '')}",
                            "source_artifact": str(cd_file),
                            "notes": item.get("notes") or f"Status: {item.get('status_code')}, Content-Type: {item.get('content_type', '')}",
                            "status": "candidate",
                            "validation_status": "unverified",
                            "confidence": "medium",
                        })
            except Exception:
                pass

        # Pull DOM sink gadgets
        gad_file = self.output_dir / "js" / "gadgets.json"
        if gad_file.exists() and generated_this_run(gad_file):
            try:
                g_data = json.loads(gad_file.read_text(encoding="utf-8"))
                for g in g_data.get("gadgets", []):
                    all_findings.append({
                        "title": f"DOM Sink Gadget: {g.get('type')}",
                        "type": "DOM XSS",
                        "severity": g.get("severity", "Triage Severity: MEDIUM — pending human review"),
                        "url": f"{self.http.base_url}/{g.get('source_file', '')}",
                        "source_artifact": str(gad_file),
                        "notes": f"DOM gadget pattern '{g.get('type')}' in {g.get('source_file')}.",
                        "status": "candidate",
                        "validation_status": "unverified",
                        "confidence": "medium",
                    })
            except Exception:
                pass

        # Generate Automated Reproducible PoC scripts for all actionable findings
        raw_findings_count = len(all_findings)
        all_findings = deduplicate_findings(all_findings)
        policy = getattr(self.http.scope_validator, "policy", {})
        finding_review = review_candidates(
            self.target, self.target_dir, all_findings,
            active_checks_allowed=policy.get("allow_active_vulnerability_checks", True),
        )
        review_path = report_dir / "finding-review.json"
        review_path.write_text(json.dumps(finding_review, indent=2), encoding="utf-8")

        try:
            try:
                from poc_generator import PoCGenerator
            except ImportError:
                from tools.poc_generator import PoCGenerator

            poc_gen = PoCGenerator(self.target, self.output_dir)
            for f in all_findings:
                if f.get("validation_status") == "validated" and f.get("url"):
                    try:
                        pocs = poc_gen.generate_poc(f, custom_headers=getattr(self.http, "auth_headers", None))
                        f["poc_sh"] = pocs["poc_sh"]
                        f["poc_py"] = pocs["poc_py"]
                    except Exception:
                        pass
        except Exception as e:
            self.log_step(skill, "step-02-poc.log", f"PoC generation notice: {e}")

        date_str = datetime.now(timezone.utc).strftime("%Y%m%d")
        report_md_file = report_dir / f"hackbot-report-{self.target}-{date_str}.md"
        report_json_file = report_dir / f"hackbot-report-{self.target}-{date_str}.json"
        report_sources = list(findings_dir.rglob("*.json")) if findings_dir.exists() else []
        report_sources.extend([
            self.output_dir / "js" / "secrets-findings.json",
            self.output_dir / "js" / "gadgets.json",
            self.output_dir / "content-discovery" / "interesting-findings.json",
        ])
        source_artifact_mtimes = {
            str(path.relative_to(self.target_dir)).replace("\\", "/"): path.stat().st_mtime
            for path in report_sources if path.is_file()
        }

        # Generate Full Markdown Report
        scope_audit_file = self.output_dir / "logs" / "scope-audit-latest.json"
        try:
            scope_execution = json.loads(scope_audit_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            scope_execution = {}
        scope_status = (
            "BLOCKED_SCOPE"
            if scope_execution.get("stopped_by_policy") or scope_execution.get("deviation_detected")
            else "COMPLETED"
        )
        md = f"# Penetration Testing Assessment Report — {self.target}\n\n"
        md += f"**Assessment Date:** {datetime.now(timezone.utc).strftime('%Y-%m-%d')}\n"
        md += f"**Target Organization:** {self.target}\n"
        md += "**Compliance Notice:** All findings are tagged `Triage Severity — pending human review`.\n\n"
        candidate_count = sum(f.get("validation_status") != "validated" for f in all_findings)
        validated_count = len(all_findings) - candidate_count
        md += "## Scope Execution\n\n"
        md += f"- **Execution status:** `{scope_status}`\n"
        md += f"- **Target requests:** `{scope_execution.get('request_count', 0)}/{scope_execution.get('request_limit', 'unknown')}`\n"
        md += f"- **Minimum request delay:** `{scope_execution.get('minimum_delay_seconds', 'unknown')}s`\n"
        md += f"- **Observed hosts:** `{json.dumps(scope_execution.get('hosts_observed', {}), sort_keys=True)}`\n"
        md += f"- **Observed methods:** `{json.dumps(scope_execution.get('methods_observed', {}), sort_keys=True)}`\n"
        md += f"- **Out-of-scope requests observed:** `{json.dumps(scope_execution.get('out_of_scope_hosts', {}), sort_keys=True)}`\n"
        blocked_redirects = [
            item for item in scope_execution.get("policy_violations", [])
            if item.get("kind") == "blocked_redirect"
        ]
        if blocked_redirects:
            destinations = sorted({str(item.get("to", "unknown")) for item in blocked_redirects})
            md += f"- **Redirects blocked before following:** `{', '.join(destinations)}`\n"
        if scope_execution.get("deviation_detected"):
            md += "- **Scope warning:** at least one out-of-policy request was observed; finding attribution requires operator review.\n"
        md += "\n"
        md += "## Executive Summary\n\n"
        raw_record_count = sum(int(f.get("raw_record_count", 1)) for f in all_findings)
        md += f"Moros AI processed artifacts for `{self.target}` and recorded **{len(all_findings)} unique triage items** from **{raw_findings_count} generated records** ({raw_record_count} raw occurrences): **{candidate_count} unverified candidates** and **{validated_count} validated findings**. An empty result means insufficient observed evidence, not proof of absence.\n\n"
        md += "| Finding Title | Validation | Severity | Affected URL | PoC Script |\n|---|---|---|---|---|\n"
        for f in all_findings:
            poc_link = f"`{f.get('poc_sh')}`" if f.get('poc_sh') else "-"
            md += f"| {f.get('title')} | {f.get('validation_status', 'unverified')} | {f.get('severity', 'Unassessed')} | `{f.get('url', '-')}` | {poc_link} |\n"

        md += "\n## Evidence & Triage Items\n\n"
        for idx, f in enumerate(all_findings, 1):
            md += f"### {idx}. {f.get('title')}\n"
            md += f"- **Validation:** `{f.get('validation_status', 'unverified')}`\n"
            md += f"- **Confidence:** `{f.get('confidence', 'not-scored')}`\n"
            md += f"- **Severity:** `{f.get('severity', 'Unassessed')}`\n"
            md += f"- **Target URL:** `{f.get('url')}`\n"
            if f.get("source_artifact"):
                md += f"- **Source artifact:** `{f.get('source_artifact')}`\n"
            if f.get("poc_sh"):
                md += f"- **cURL Reproduction PoC:** `{f.get('poc_sh')}`\n"
            if f.get("poc_py"):
                md += f"- **Python Reproduction Script:** `{f.get('poc_py')}`\n"
            for evidence in f.get("evidence", []):
                if isinstance(evidence, dict):
                    md += f"- **Evidence:** `{evidence.get('evidence_id', 'unlinked')}` from `{evidence.get('source_artifact', 'unknown source')}` (SHA256: `{evidence.get('source_sha256', 'unavailable')}`)\n"
                else:
                    md += f"- **Evidence:** `{evidence}`\n"
            if f.get("curl"):
                md += f"- **Reproduction cURL:**\n```bash\n{f.get('curl')}\n```\n"
            if f.get("notes"):
                md += f"- **Details:** {f.get('notes')}\n"
            evidence_review = f.get("evidence_review", {})
            skeptical_review = f.get("skeptical_review", {})
            if evidence_review:
                md += (f"- **Evidence integrity:** `{evidence_review.get('result')}`; source exists: "
                       f"`{evidence_review.get('source_exists')}`; hash matches: `{evidence_review.get('sha256_matches')}`\n")
            if skeptical_review:
                md += f"- **Adversarial review:** {skeptical_review.get('objection')}\n"
                md += f"- **Next step:** `{skeptical_review.get('required_next_step')}`\n"
            md += "\n"

        report_md_file.write_text(md, encoding="utf-8")
        if os.environ.get("MOROS_REPORT_LANG", "en").lower() == "ar":
            try:
                from report_i18n import format_report_markdown
                dialect = os.environ.get("MOROS_REPORT_DIALECT", "msa")
                ar_md = format_report_markdown(self.target, all_findings, lang="ar", dialect=dialect)
                (report_dir / f"hackbot-report-{self.target}-{date_str}-ar.md").write_text(ar_md, encoding="utf-8")
            except Exception as exc:
                self.log_step(skill, "step-08-i18n-error.log", f"Arabic report generation notice: {exc}")
        report_json_file.write_text(json.dumps({"target": self.target, "scope_execution": scope_execution,
            "summary": {
            "triage_items": len(all_findings), "raw_records": raw_findings_count,
            "raw_occurrences": raw_record_count, "unverified_candidates": candidate_count,
            "validated_findings": validated_count,
            "evidence_integrity_review": str(review_path.relative_to(self.target_dir)),
        }, "source_artifact_mtimes": source_artifact_mtimes,
            "finding_review": finding_review, "findings": all_findings}, indent=2), encoding="utf-8")

        # Generate SARIF 2.1.0 sidecar for GitHub Code Scanning and CI/CD
        sarif_file = report_dir / "findings.sarif"
        try:
            from sarif_exporter import write_sarif_report
            write_sarif_report(sarif_file, all_findings, target=self.target)
        except Exception as e:
            self.log_step(skill, "step-08-sarif-error.log", f"SARIF export failed: {e}")

        # Send Webhook Alert if configured
        try:
            try:
                from alert_dispatcher import AlertDispatcher
            except ImportError:
                from tools.alert_dispatcher import AlertDispatcher

            dispatcher = AlertDispatcher()
            if dispatcher.is_configured():
                high_count = sum(any(s in str(f.get("severity", "")).upper() for s in ["HIGH", "CRITICAL"]) for f in all_findings)
                dispatcher.send_alert(
                    title=f"Assessment Complete: {self.target}",
                    message=f"Moros AI recorded {len(all_findings)} triage findings ({high_count} High/Critical).",
                    severity="HIGH" if high_count > 0 else "INFO",
                    fields={
                        "Target": self.target,
                        "Total Findings": str(len(all_findings)),
                        "High/Critical": str(high_count),
                        "Report": report_md_file.name
                    }
                )
        except Exception as e:
            self.log_step(skill, "step-09-alert-error.log", f"Alert dispatch notice: {e}")

        self.log_step(skill, "step-07-full-report.log", f"Generated deliverable report: {report_md_file.name}")
        return {
            "status": "SUCCESS",
            "report_path": str(report_md_file),
            "sarif_path": str(sarif_file) if sarif_file.exists() else None,
            "findings_count": len(all_findings),
        }
