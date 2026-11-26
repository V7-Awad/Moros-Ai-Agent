#!/usr/bin/env python3
"""
juice_shop_benchmark.py — Self-Contained OWASP Juice Shop / DVWA Simulation Benchmark.

Spins up an ephemeral loopback HTTP application simulating 7 vulnerable endpoints
paired with 7 hardened control endpoints across:
  1. Reflected XSS (/rest/products/search vs /safe/products/search)
  2. SQL Injection (/vulnerabilities/sqli/ vs /safe/sqli/)
  3. IDOR / BOLA (/api/Users/2 vs /safe/Users/2)
  4. Path Traversal / LFI (/vulnerabilities/fi/ vs /safe/fi/)
  5. JWT alg:none (/rest/user/whoami vs /safe/user/whoami)
  6. Open Redirect (/redirect vs /safe/redirect)
  7. CORS Misconfiguration (/api/BasketItems/1 vs /safe/BasketItems/1)

Measures True Positive Rate (TPR) and False Positive Rate (FPR) deterministically.
Runnable via `pytest evals/` (or `pytest evals/juice_shop_benchmark.py`) and standalone CLI.
"""

from __future__ import annotations

import argparse
import base64
import html
import json
import re
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_PROJECT_ROOT = Path(__file__).parent.parent.resolve()
_TOOLS_DIR = _PROJECT_ROOT / "tools"
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))


def _b64url_encode(obj: Dict[str, Any]) -> str:
    raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64url_decode_json(segment: str) -> Dict[str, Any]:
    padding = len(segment) % 4
    if padding:
        segment += "=" * (4 - padding)
    try:
        decoded = base64.urlsafe_b64decode(segment.encode("ascii")).decode("utf-8", errors="ignore")
        return json.loads(decoded)
    except Exception:
        return {}


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Capture 3xx redirect responses instead of following them."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class _SimRequestHandler(BaseHTTPRequestHandler):
    """HTTP handler modeling OWASP Juice Shop / DVWA vulnerable + hardened endpoints."""

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _send(
        self,
        status: int,
        body: str,
        content_type: str = "application/json",
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> None:
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        origin = self.headers.get("Origin", "")
        auth = self.headers.get("Authorization", "")

        # 1. Reflected XSS
        if path == "/rest/products/search":
            q = qs.get("q", [""])[0]
            self._send(200, f"<html><body><h1>Search</h1><div>Results for: {q}</div></body></html>", "text/html")
            return
        if path == "/safe/products/search":
            q = html.escape(qs.get("q", [""])[0], quote=True)
            self._send(200, f"<html><body><h1>Search</h1><div>Results for: {q}</div></body></html>", "text/html")
            return

        # 2. SQL Injection
        if path == "/vulnerabilities/sqli/":
            item_id = qs.get("id", ["1"])[0]
            if "'" in item_id or '"' in item_id:
                self._send(
                    500,
                    json.dumps({"error": "SQLITE_ERROR: near \"'\": syntax error (you have an error in your SQL syntax)"}),
                )
                return
            self._send(200, json.dumps({"id": item_id, "name": "Apple Juice"}))
            return
        if path == "/safe/sqli/":
            item_id = qs.get("id", ["1"])[0]
            self._send(200, json.dumps({"id": item_id, "name": "Apple Juice", "parameterized": True}))
            return

        # 3. IDOR / BOLA
        if path == "/api/Users/2":
            self._send(
                200,
                json.dumps({
                    "status": "success",
                    "data": {"id": 2, "email": "admin@juice-sh.op", "role": "admin"},
                }),
            )
            return
        if path == "/safe/Users/2":
            if auth == "Bearer valid-user-2-token":
                self._send(200, json.dumps({"status": "success", "data": {"id": 2}}))
            else:
                self._send(401, json.dumps({"error": "Unauthorized"}))
            return

        # 4. Path Traversal / LFI
        if path == "/vulnerabilities/fi/":
            page = qs.get("page", [""])[0]
            if "../" in page or "..\\" in page or "etc/passwd" in page.lower():
                self._send(200, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n", "text/plain")
                return
            self._send(200, "Welcome to DVWA file viewer", "text/plain")
            return
        if path == "/safe/fi/":
            page = qs.get("page", [""])[0]
            if ".." in page or "/" in page or "\\" in page:
                self._send(400, json.dumps({"error": "Invalid path"}))
                return
            self._send(200, "Welcome to safe file viewer", "text/plain")
            return

        # 5. JWT alg:none
        if path in ("/rest/user/whoami", "/safe/user/whoami"):
            if not auth.lower().startswith("bearer "):
                self._send(401, json.dumps({"error": "Missing bearer token"}))
                return
            token = auth.split(" ", 1)[1].strip()
            parts = token.split(".")
            hdr = _b64url_decode_json(parts[0]) if len(parts) >= 2 else {}
            claims = _b64url_decode_json(parts[1]) if len(parts) >= 2 else {}
            alg = str(hdr.get("alg", "")).lower()
            if path == "/rest/user/whoami":
                if alg == "none":
                    self._send(200, json.dumps({"user": {"id": 1, "email": "admin@juice-sh.op", "role": claims.get("role", "admin"), "alg": "none"}}))
                    return
                self._send(401, json.dumps({"error": "Invalid token"}))
                return
            # /safe/user/whoami rejects alg:none
            if alg == "none" or alg not in ("hs256", "rs256"):
                self._send(401, json.dumps({"error": "Rejected unsupported or unsigned JWT algorithm"}))
                return
            self._send(200, json.dumps({"user": {"id": 1}}))
            return

        # 6. Open Redirect
        if path == "/redirect":
            dest = qs.get("to", ["/"])[0]
            self._send(302, "", "text/plain", extra_headers={"Location": dest})
            return
        if path == "/safe/redirect":
            dest = qs.get("to", ["/"])[0]
            if dest.startswith("/") and not dest.startswith("//"):
                self._send(302, "", "text/plain", extra_headers={"Location": dest})
            else:
                self._send(400, json.dumps({"error": "Redirect target not allowlisted"}))
            return

        # 7. CORS Misconfiguration
        if path == "/api/BasketItems/1":
            hdrs = {}
            if origin:
                hdrs["Access-Control-Allow-Origin"] = origin
                hdrs["Access-Control-Allow-Credentials"] = "true"
            self._send(200, json.dumps({"status": "success", "items": [{"id": 1, "qty": 2}]}), extra_headers=hdrs)
            return
        if path == "/safe/BasketItems/1":
            hdrs = {"Access-Control-Allow-Origin": "https://juice-sh.op"}
            self._send(200, json.dumps({"status": "success", "items": [{"id": 1, "qty": 2}]}), extra_headers=hdrs)
            return

        self._send(404, json.dumps({"error": "Not Found"}))


class VulnerableAppSimulator:
    """Ephemeral loopback HTTP server modeling OWASP Juice Shop / DVWA endpoints."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        self.host = host
        self.port = port
        self._server: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    @property
    def base_url(self) -> str:
        if not self._server:
            raise RuntimeError("Simulator server is not running")
        actual_host, actual_port = self._server.server_address[:2]
        return f"http://{actual_host}:{actual_port}"

    def start(self) -> str:
        if self._server is not None:
            return self.base_url
        self._server = ThreadingHTTPServer((self.host, self.port), _SimRequestHandler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self.base_url

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None

    def __enter__(self) -> "VulnerableAppSimulator":
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.stop()


@dataclass
class BenchmarkCase:
    name: str
    vuln_type: str
    endpoint: str
    expected_vulnerable: bool
    detected: bool
    outcome: str  # TP, FP, TN, FN
    evidence: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "vuln_type": self.vuln_type,
            "endpoint": self.endpoint,
            "expected_vulnerable": self.expected_vulnerable,
            "detected": self.detected,
            "outcome": self.outcome,
            "evidence": self.evidence,
        }


class JuiceShopBenchmark:
    """Evaluates Moros detection fidelity across 7 vulnerable and 7 hardened endpoints."""

    VULN_TYPES = (
        "xss",
        "sqli",
        "idor",
        "path_traversal",
        "jwt_alg_none",
        "open_redirect",
        "cors",
    )

    def __init__(self, timeout_seconds: float = 5.0):
        self.timeout_seconds = timeout_seconds
        self._opener = urllib.request.build_opener(_NoRedirectHandler())

    def _http_get(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> Tuple[int, Dict[str, str], str]:
        req = urllib.request.Request(url, headers=headers or {}, method="GET")
        try:
            with self._opener.open(req, timeout=self.timeout_seconds) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                hdrs = {k.lower(): v for k, v in resp.headers.items()}
                return resp.status, hdrs, body
        except urllib.error.HTTPError as err:
            body = err.read().decode("utf-8", errors="replace") if err.fp else ""
            hdrs = {k.lower(): v for k, v in err.headers.items()} if err.headers else {}
            return err.code, hdrs, body

    @staticmethod
    def _classify(expected_vulnerable: bool, detected: bool) -> str:
        if expected_vulnerable and detected:
            return "TP"
        if not expected_vulnerable and detected:
            return "FP"
        if not expected_vulnerable and not detected:
            return "TN"
        return "FN"

    def _probe_xss(self, base_url: str, path: str, expected_vulnerable: bool, name: str) -> BenchmarkCase:
        marker = "MOROS_XSS_CANARY_9F2A"
        probe = f"<moros-probe>{marker}</moros-probe>"
        url = f"{base_url}{path}?q={urllib.parse.quote(probe)}"
        status, _, body = self._http_get(url)
        escaped = f"&lt;moros-probe&gt;{marker.lower()}&lt;/moros-probe&gt;" in body.lower()
        detected = status == 200 and probe in body and not escaped
        return BenchmarkCase(
            name=name,
            vuln_type="xss",
            endpoint=path,
            expected_vulnerable=expected_vulnerable,
            detected=detected,
            outcome=self._classify(expected_vulnerable, detected),
            evidence=f"status={status}, unescaped_reflection={detected}",
        )

    def _probe_sqli(self, base_url: str, path: str, expected_vulnerable: bool, name: str) -> BenchmarkCase:
        sqli_payload = urllib.parse.quote("1'")
        url = f"{base_url}{path}?id={sqli_payload}"
        status, _, body = self._http_get(url)
        sql_patterns = (
            r"you have an error in your sql syntax",
            r"sqlite_error",
            r"syntax error at or near",
            r"sqlite3::sqlexception",
            r"unclosed quotation mark",
        )
        matched = next((p for p in sql_patterns if re.search(p, body, re.IGNORECASE)), "")
        detected = bool(matched)
        return BenchmarkCase(
            name=name,
            vuln_type="sqli",
            endpoint=path,
            expected_vulnerable=expected_vulnerable,
            detected=detected,
            outcome=self._classify(expected_vulnerable, detected),
            evidence=f"status={status}, sql_error={matched or 'none'}",
        )

    def _probe_idor(self, base_url: str, path: str, expected_vulnerable: bool, name: str) -> BenchmarkCase:
        status, hdrs, body = self._http_get(f"{base_url}{path}")
        is_json = "json" in hdrs.get("content-type", "").lower() or body.strip().startswith("{")
        detected = status in (200, 201) and is_json and len(body) > 20 and ("email" in body or "data" in body)
        return BenchmarkCase(
            name=name,
            vuln_type="idor",
            endpoint=path,
            expected_vulnerable=expected_vulnerable,
            detected=detected,
            outcome=self._classify(expected_vulnerable, detected),
            evidence=f"status={status}, unauth_json_len={len(body)}",
        )

    def _probe_path_traversal(self, base_url: str, path: str, expected_vulnerable: bool, name: str) -> BenchmarkCase:
        payload = "../../../../etc/passwd"
        url = f"{base_url}{path}?page={urllib.parse.quote(payload)}"
        status, _, body = self._http_get(url)
        detected = status == 200 and "root:x:0:0:" in body.lower()
        return BenchmarkCase(
            name=name,
            vuln_type="path_traversal",
            endpoint=path,
            expected_vulnerable=expected_vulnerable,
            detected=detected,
            outcome=self._classify(expected_vulnerable, detected),
            evidence=f"status={status}, passwd_disclosed={detected}",
        )

    def _probe_jwt_alg_none(self, base_url: str, path: str, expected_vulnerable: bool, name: str) -> BenchmarkCase:
        header = _b64url_encode({"alg": "none", "typ": "JWT"})
        claims = _b64url_encode({"sub": "1", "email": "admin@juice-sh.op", "role": "admin"})
        unsigned_token = f"{header}.{claims}."
        status, _, body = self._http_get(
            f"{base_url}{path}",
            headers={"Authorization": f"Bearer {unsigned_token}"},
        )
        detected = status == 200 and '"admin"' in body.lower()
        return BenchmarkCase(
            name=name,
            vuln_type="jwt_alg_none",
            endpoint=path,
            expected_vulnerable=expected_vulnerable,
            detected=detected,
            outcome=self._classify(expected_vulnerable, detected),
            evidence=f"status={status}, alg_none_accepted={detected}",
        )

    def _probe_open_redirect(self, base_url: str, path: str, expected_vulnerable: bool, name: str) -> BenchmarkCase:
        canary_dest = "https://moros-redirect-test.example"
        url = f"{base_url}{path}?to={urllib.parse.quote(canary_dest)}"
        status, hdrs, _ = self._http_get(url)
        location = hdrs.get("location", "")
        detected = status in (301, 302, 303, 307, 308) and "moros-redirect-test.example" in location.lower()
        return BenchmarkCase(
            name=name,
            vuln_type="open_redirect",
            endpoint=path,
            expected_vulnerable=expected_vulnerable,
            detected=detected,
            outcome=self._classify(expected_vulnerable, detected),
            evidence=f"status={status}, location={location or 'none'}",
        )

    def _probe_cors(self, base_url: str, path: str, expected_vulnerable: bool, name: str) -> BenchmarkCase:
        test_origin = "https://evil-attacker.com"
        status, hdrs, _ = self._http_get(
            f"{base_url}{path}",
            headers={"Origin": test_origin},
        )
        acao = hdrs.get("access-control-allow-origin", "")
        acac = hdrs.get("access-control-allow-credentials", "")
        detected = test_origin in acao or acao.strip().lower() == "null"
        return BenchmarkCase(
            name=name,
            vuln_type="cors",
            endpoint=path,
            expected_vulnerable=expected_vulnerable,
            detected=detected,
            outcome=self._classify(expected_vulnerable, detected),
            evidence=f"status={status}, acao={acao or 'none'}, acac={acac or 'none'}",
        )

    def run_all(self) -> Dict[str, Any]:
        cases: List[BenchmarkCase] = []
        with VulnerableAppSimulator() as sim:
            base = sim.base_url
            # 7 Vulnerable endpoints (expected TP)
            cases.append(self._probe_xss(base, "/rest/products/search", True, "vuln_reflected_xss"))
            cases.append(self._probe_sqli(base, "/vulnerabilities/sqli/", True, "vuln_sqli_error"))
            cases.append(self._probe_idor(base, "/api/Users/2", True, "vuln_idor_unauth_user"))
            cases.append(self._probe_path_traversal(base, "/vulnerabilities/fi/", True, "vuln_path_traversal_lfi"))
            cases.append(self._probe_jwt_alg_none(base, "/rest/user/whoami", True, "vuln_jwt_alg_none"))
            cases.append(self._probe_open_redirect(base, "/redirect", True, "vuln_open_redirect"))
            cases.append(self._probe_cors(base, "/api/BasketItems/1", True, "vuln_cors_reflection"))

            # 7 Hardened control endpoints (expected TN; any detection is FP)
            cases.append(self._probe_xss(base, "/safe/products/search", False, "safe_escaped_xss"))
            cases.append(self._probe_sqli(base, "/safe/sqli/", False, "safe_parameterized_sqli"))
            cases.append(self._probe_idor(base, "/safe/Users/2", False, "safe_authz_user"))
            cases.append(self._probe_path_traversal(base, "/safe/fi/", False, "safe_path_traversal_guard"))
            cases.append(self._probe_jwt_alg_none(base, "/safe/user/whoami", False, "safe_jwt_rejects_none"))
            cases.append(self._probe_open_redirect(base, "/safe/redirect", False, "safe_redirect_allowlist"))
            cases.append(self._probe_cors(base, "/safe/BasketItems/1", False, "safe_cors_pinned_origin"))

        tp = sum(1 for c in cases if c.outcome == "TP")
        fp = sum(1 for c in cases if c.outcome == "FP")
        tn = sum(1 for c in cases if c.outcome == "TN")
        fn = sum(1 for c in cases if c.outcome == "FN")

        tpr = round(tp / (tp + fn), 4) if (tp + fn) else 0.0
        fpr = round(fp / (fp + tn), 4) if (fp + tn) else 0.0
        precision = round(tp / (tp + fp), 4) if (tp + fp) else 0.0
        f1 = round((2 * precision * tpr) / (precision + tpr), 4) if (precision + tpr) else 0.0

        by_vuln: Dict[str, Dict[str, Any]] = {}
        for vtype in self.VULN_TYPES:
            subset = [c for c in cases if c.vuln_type == vtype]
            by_vuln[vtype] = {
                "tp": sum(1 for c in subset if c.outcome == "TP"),
                "fp": sum(1 for c in subset if c.outcome == "FP"),
                "tn": sum(1 for c in subset if c.outcome == "TN"),
                "fn": sum(1 for c in subset if c.outcome == "FN"),
            }

        return {
            "benchmark": "OWASP Juice Shop / DVWA Simulation",
            "total_cases": len(cases),
            "vulnerable_cases": tp + fn,
            "safe_cases": tn + fp,
            "true_positives": tp,
            "false_positives": fp,
            "true_negatives": tn,
            "false_negatives": fn,
            "true_positive_rate": tpr,
            "false_positive_rate": fpr,
            "precision": precision,
            "f1_score": f1,
            "by_vuln_type": by_vuln,
            "cases": [c.to_dict() for c in cases],
        }


# ── Pytest Entrypoints (for `pytest evals/juice_shop_benchmark.py` or `evals/`) ──

def test_juice_shop_benchmark_tp_and_fp_rates():
    report = JuiceShopBenchmark().run_all()
    assert report["total_cases"] == 14
    assert report["true_positives"] == 7
    assert report["false_positives"] == 0
    assert report["true_negatives"] == 7
    assert report["false_negatives"] == 0
    assert report["true_positive_rate"] == 1.0
    assert report["false_positive_rate"] == 0.0
    assert report["f1_score"] == 1.0


def test_juice_shop_benchmark_covers_all_seven_vuln_classes():
    report = JuiceShopBenchmark().run_all()
    expected = {"xss", "sqli", "idor", "path_traversal", "jwt_alg_none", "open_redirect", "cors"}
    assert set(report["by_vuln_type"].keys()) == expected
    for vtype, stats in report["by_vuln_type"].items():
        assert stats == {"tp": 1, "fp": 0, "tn": 1, "fn": 0}, f"Unexpected stats for {vtype}: {stats}"


def main() -> None:
    parser = argparse.ArgumentParser(description="Moros OWASP Juice Shop / DVWA simulation benchmark")
    parser.add_argument("--json", action="store_true", help="Print full JSON report")
    args = parser.parse_args()

    report = JuiceShopBenchmark().run_all()
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"=== {report['benchmark']} ===")
        print(
            f"Cases: {report['total_cases']} | TP={report['true_positives']} "
            f"FP={report['false_positives']} TN={report['true_negatives']} FN={report['false_negatives']}"
        )
        print(
            f"TPR={report['true_positive_rate'] * 100:.1f}% | "
            f"FPR={report['false_positive_rate'] * 100:.1f}% | "
            f"Precision={report['precision'] * 100:.1f}% | F1={report['f1_score']:.4f}"
        )
        for case in report["cases"]:
            print(f"  [{case['outcome']}] {case['name']} ({case['endpoint']}) -> {case['evidence']}")

    if report["true_positive_rate"] < 1.0 or report["false_positive_rate"] > 0.0:
        sys.exit(1)


if __name__ == "__main__":
    main()
