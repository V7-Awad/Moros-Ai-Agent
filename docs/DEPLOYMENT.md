# Moros AI — Deployment & Operations Guide

This guide covers deploying and operating Moros AI across local workstations, TLS-secured remote/team hosts, containers, and CI/CD pipelines.

---

## 1. Prerequisites & Local Launch

### Requirements
- **Python 3.10+**
- **Git**
- **Dependencies:**
  ```bash
  pip install -r requirements.txt
  playwright install chromium   # Required for headless browser JS discovery/DOM analysis
  ```

### Verify Environment
```bash
python run.py --check
python run.py --list-skills
```

### Initialize a Target & Scope Policy
Active offensive skills require a readable `scope-of-work.*` (`.md`, `.txt`, `.yaml`, `.yml`, `.json`) file inside `targets/<domain>/` referencing the target domain and authorization wording:

```bash
python setup.py init-target --domain app.example.com
# Edit targets/app.example.com/scope-of-work.md with signed Rules of Engagement
python run.py --target app.example.com --dry-run
```

### Launch Dashboard Locally (Loopback)
```bash
# Via standalone launcher
python dashboard.py --port 8080

# Or via run.py
python run.py --dashboard --port 8080

# Or directly via server module (supports --ssl-cert / --ssl-key / --rate-limit)
python dashboard/server.py --host 127.0.0.1 --port 8080 --no-open
```

When bound to a loopback address (`127.0.0.1`, `localhost`, `::1`) without `MOROS_DASHBOARD_TOKEN`, the local dashboard operates without an API token prompt for single-operator convenience.

---

## 2. Non-Loopback Binding & Token Authentication (`MOROS_DASHBOARD_TOKEN`)

Whenever the dashboard is exposed beyond loopback (for example `--host 0.0.0.0`), API authentication is **mandatory** on all `/api/*` endpoints:

1. **Recommended — Explicit Persistent Token:**
   ```bash
   # Linux/macOS
   export MOROS_DASHBOARD_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
   python dashboard/server.py --host 0.0.0.0 --port 8080 --no-open
   ```
   ```powershell
   # Windows PowerShell
   $env:MOROS_DASHBOARD_TOKEN = python -c "import secrets; print(secrets.token_urlsafe(32))"
   python dashboard/server.py --host 0.0.0.0 --port 8080 --no-open
   ```
2. **Automatic Fallback Token:**
   If `--host` is non-loopback and `MOROS_DASHBOARD_TOKEN` is unset, `run_dashboard()` logs a warning and auto-generates an ephemeral 32-byte URL-safe token printed once to server stdout (never exposed in HTTP responses).
3. **Client Usage:**
   - **Browser UI:** Prompts for the token and stores it in `sessionStorage` (`Authorization: Bearer <token>`).
   - **API / CLI Clients:** Send either `Authorization: Bearer <token>` or `X-Moros-Token: <token>`.
4. **Rate Limiting & CSRF Hardening:**
   - Set `MOROS_DASHBOARD_RATE_LIMIT` (or `--rate-limit`) to control per-client `/api/*` requests per minute (default: `600`; `0` disables). Exceeding the cap returns `429 Too Many Requests` with `Retry-After`.
   - State-changing browser requests (`POST`, `PUT`, `DELETE`) carrying `Origin` or `Referer` must match the server `Host` (hostname + port) or receive `403`.

---

## 3. HTTPS / TLS Certificate Setup

Encrypt dashboard traffic whenever binding to non-loopback interfaces or traversing untrusted networks.

### Option A: Self-Signed Certificate (Internal / Lab)
```bash
mkdir -p certs
openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes \
  -keyout certs/dashboard.key \
  -out certs/dashboard.crt \
  -subj "/CN=moros.local" \
  -addext "subjectAltName=DNS:localhost,DNS:moros.local,IP:127.0.0.1"
```

### Option B: Launch with CLI Flags or Environment Variables
```bash
# Via CLI flags
python dashboard/server.py \
  --host 0.0.0.0 \
  --port 8443 \
  --ssl-cert certs/dashboard.crt \
  --ssl-key certs/dashboard.key \
  --no-open

# Or via environment variables
export MOROS_DASHBOARD_SSL_CERT=/path/to/fullchain.pem
export MOROS_DASHBOARD_SSL_KEY=/path/to/privkey.pem
python dashboard/server.py --host 0.0.0.0 --port 8443 --no-open
```

- **TLS Validation Rules:**
  - Supplying only one of `--ssl-cert` / `--ssl-key` (or only one env var) raises `ValueError`.
  - Missing certificate or key files raise `FileNotFoundError` before binding the socket.
  - Enforces TLSv1.2+ via `ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)`.
- **Behind a Reverse Proxy (Nginx / Caddy / Traefik):**
  If TLS is terminated at a reverse proxy, bind Moros to `127.0.0.1:8080`, set `MOROS_DASHBOARD_TOKEN`, and ensure the proxy forwards the external `Host` header faithfully so browser `Origin` checks match `Host`.

---

## 4. Docker & Docker Compose

### Recommended Container Practices
- Run as an unprivileged non-root user inside the container (`Python 3.10+` base image).
- Persist target workspaces by bind-mounting `./targets:/app/targets` so runs, findings, checkpoints, and reports survive container restarts.
- Never bake `.env` or TLS private keys into container images; inject secrets via runtime environment variables or read-only volume mounts.
- Keep dashboard ports bound to localhost (`127.0.0.1:8080:8080`) unless fronting with TLS + `MOROS_DASHBOARD_TOKEN`.

### Example Usage with Docker Compose
```bash
# Start the operations dashboard (binds 127.0.0.1:8080 -> container 0.0.0.0:8080)
MOROS_DASHBOARD_TOKEN="replace-with-strong-token" docker compose up -d dashboard

# Run an ad-hoc CLI assessment sharing the ./targets volume
docker compose --profile cli run --rm scanner \
  --target app.example.com --scan-mode quick
```

### Custom Skill Execution Sandbox (`MOROS_SANDBOX_MODE` / `--sandbox`)
When running untrusted or custom skills (`skills/*/run.py`):
- `--sandbox local` (default): Executes inside an isolated temporary workspace with `build_scrubbed_env()`, stripping LLM/cloud API keys (`OPENAI_*`, `ANTHROPIC_*`, `GEMINI_*`, `DEEPSEEK_*`, `AWS_*`, `MOROS_DASHBOARD_TOKEN`, etc.) while keeping target scope variables (`MOROS_IN_SCOPE`, `MOROS_OUT_OF_SCOPE`, `MOROS_HTTP_REQUESTS_REMAINING`).
- `--sandbox docker`: Executes custom skill commands inside an ephemeral `--read-only --network none` Docker container (`DockerSandbox`).
- `--sandbox none`: Disables sandbox isolation (use only for trusted local development).

---

## 5. HITL Checkpoints & State-Changing HTTP Controls

Moros enforces default-deny safety on state-changing HTTP methods (`POST`, `PUT`, `PATCH`, `DELETE`) in [`tools/scoped_http.py`](../tools/scoped_http.py):

| Environment Variable | Default | Behavior |
|:---|:---|:---|
| `MOROS_ALLOW_GATED_POST` | Unset (`false`) | Must be `1`, `true`, or `yes` to permit supported skills (`graphql-audit`, `xxe-detect`, `rate-limit-test`, `idor-audit`, etc.) to request HITL approval for bounded `POST` probes. Otherwise, skills remain strictly `GET`/`HEAD` or passive. |
| `MOROS_HITL_BLOCKING` | Unset (`false`) | When `1`, `true`, or `yes` (alongside `MOROS_ALLOW_GATED_POST=1`), worker threads pause and block waiting for an operator `APPROVED` decision via the Dashboard Checkpoints tab or `POST /api/checkpoints/action` (up to timeout). When unset, unapproved checkpoints register as `WAITING_APPROVAL` and immediately deny the `POST` without hanging unattended/CI runs. |

**Example — Interactive Assessment with Blocking HITL Approval:**
```bash
export MOROS_ALLOW_GATED_POST=1
export MOROS_HITL_BLOCKING=1
python run.py --target app.example.com --scan-mode full
```

**Example — Unattended / Pre-Approved Run (Non-Blocking):**
```bash
export MOROS_ALLOW_GATED_POST=1
unset MOROS_HITL_BLOCKING
python run.py --target app.example.com --scan-mode quick
```

---

## 6. Outbound HTTP Proxy (`MOROS_PROXY`)

Route Moros HTTP traffic through an intercepting proxy (Burp Suite, mitmproxy, OWASP ZAP) or corporate egress proxy:

```bash
export MOROS_PROXY="http://127.0.0.1:8081"
python run.py --target app.example.com --scan-mode quick
```

- Supported proxy URL schemes: `http://`, `https://`, `socks5://` (or `host:port`).
- Proxy credentials (if included in the URL) are redacted from `ScopedHttpClient.request_logs`.
- `ScopeValidator` and `_SafeRedirectHandler` remain active at all times so out-of-scope targets and cross-host redirects are still blocked before leaving the client.

---

## 7. CI/CD Security Gate & Reusable GitHub Action

Moros provides both a standalone policy evaluator ([`tools/ci_gate.py`](../tools/ci_gate.py) / `run.py --ci-gate`) and a reusable composite GitHub Action ([`.github/actions/moros-scan/action.yml`](../.github/actions/moros-scan/action.yml)).

### CLI Gate & Lifecycle Commands (`run.py` / `tools/ci_gate.py`)

```bash
# 1. Run quick assessment with deterministic Phase 1 validation, then evaluate CI gate
python setup.py init-target --domain staging.example.com
python run.py \
  --target staging.example.com \
  --scan-mode quick \
  --https-only \
  --max-http-requests 80 \
  --no-trace \
  --validate \
  --ci-gate \
  --min-severity high \
  --fail-on-confirmed true \
  --pr-summary-out /tmp/moros-pr-summary.md

# 2. Evaluate CI policy gate directly against existing target artifacts
python tools/ci_gate.py \
  --output-dir targets/staging.example.com/output \
  --target staging.example.com \
  --min-severity high \
  --fail-on-confirmed true \
  --fail-on-candidate false \
  --summary-out /tmp/moros-pr-summary.md

# 3. Legacy candidate-only gate
python run.py --target staging.example.com --scan-mode quick --fail-on-candidate

# 4. Generate isolated remediation proposal (never auto-commits) or run deterministic retest
python run.py --target staging.example.com --remediate fnd-9a3f1c2b8e04 --repo-dir /path/to/app
python run.py --target staging.example.com --retest fnd-9a3f1c2b8e04
```

### Exit Codes
| Code | Meaning |
|:---|:---|
| `0` | Scan or CI policy gate passed |
| `1` | Scan, remediation, or retest execution failed |
| `2` | Policy gate triggered (`--fail-on-candidate`, `--ci-gate` / `tools/ci_gate.py`), or missing LLM preflight on active scan |
| `3` | `BLOCKED_SCOPE`: request, redirect, or missing `scope-of-work.*` authorization violated scope policy |
| `4` | Invalid gate configuration, missing/malformed scan artifacts, or failed scan step in composite action |
| `130` | Interrupted by operator (`SIGINT`) |

### Composite GitHub Action (`.github/actions/moros-scan`)

The composite action validates explicit target authorization (`tools/ci_gate.py --check-scope`) before running `run.py`, evaluates policy thresholds, writes a secret-redacted Markdown PR summary, and optionally uploads OASIS SARIF 2.1.0 using a SHA-pinned `github/codeql-action/upload-sarif` step.

- **Key Inputs:** `target` (required), `scan-mode` (`quick`), `budget` (`5.0`), `min-severity` (`high`), `fail-on-candidate` (`false`), `fail-on-confirmed` (`true`), `upload-sarif` (`true`), `config-path`, `min-confidence` (`0.0`), `require-validation` (`false`), `max-http-requests` (`80`).
- **Outputs:** `exit-code`, `sarif-path`, `summary-markdown`, `confirmed-count`, `candidate-count`.
- **Example Workflows:** See [`.github/workflows/moros-dast-example.yml`](../.github/workflows/moros-dast-example.yml) and [`.github/workflows/moros-retest-example.yml`](../.github/workflows/moros-retest-example.yml) for SHA-pinned configurations with `vars.MOROS_AUTHORIZED_TARGET` verification and fork-PR active-scan protection.

### Uploading SARIF 2.1.0 Results
Moros writes OASIS SARIF 2.1.0 output to `targets/<domain>/output/report/findings.sarif` (also downloadable from `GET /api/targets/<domain>/sarif`), validateable offline via `python tools/ci_gate.py --validate-sarif <path>`:

```yaml
- name: Upload Moros SARIF
  uses: github/codeql-action/upload-sarif@ff0a06e83cb2de871e5a09832bc6a81e7276941f # v3.28.18
  if: always()
  with:
    sarif_file: targets/staging.example.com/output/report/findings.sarif
```
