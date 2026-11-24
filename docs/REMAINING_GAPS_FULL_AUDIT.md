# Moros AI — Comprehensive Remaining Gaps Audit

**Audit Date:** 2026-11-23  
**Auditor:** Deep Codebase Review  
**Repository:** `d:\Moros Ai` → `https://github.com/V7-Awad/Moros-Ai-Agent.git` (branch `main`)  
**Current State:** 47/47 tests passing • Commit `1f5f0df` on `origin/main`  

> [!IMPORTANT]
> This document lists **every remaining gap, bug, and improvement** needed. Each item includes exact file paths, the problem description, the exact fix required, and verification commands. An executing agent should process items in the numbered order within each priority section.

---

## Table of Contents

1. [P0 — Critical Bugs (Broken Functionality)](#p0--critical-bugs-broken-functionality)
2. [P1 — Core Feature Gaps](#p1--core-feature-gaps)
3. [P2 — Missing Skills (Attack Surface)](#p2--missing-skills-attack-surface)
4. [P3 — Dashboard & UI Gaps](#p3--dashboard--ui-gaps)
5. [P4 — Documentation & README](#p4--documentation--readme)
6. [P5 — Testing Gaps](#p5--testing-gaps)
7. [P6 — Configuration & Build System](#p6--configuration--build-system)
8. [P7 — Performance & Architecture](#p7--performance--architecture)
9. [Verification Commands](#verification-commands)

---

## P0 — Critical Bugs (Broken Functionality)

### P0-1. `ScopedHttpClient` missing `.get()` method — custom skill `run.py` scripts crash

**Files:**  
- `tools/scoped_http.py` (line 78 — only has `.request()`)
- `skills/cors-audit/run.py` (line 48 — calls `client.get(...)`)

**Problem:** The `ScopedHttpClient` class has only a `request()` method, but `cors-audit/run.py` line 48 calls `client.get(full_url, headers={"Origin": test_origin})`. This will raise `AttributeError: 'ScopedHttpClient' object has no attribute 'get'`. Same issue may exist in other custom skill `run.py` files.

**Fix:** Add convenience methods to `ScopedHttpClient`:

```python
# Add after the request() method in tools/scoped_http.py

def get(self, url_or_path: str, headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Convenience GET wrapper with optional extra headers."""
    if headers:
        # Temporarily inject extra headers for this request
        saved = dict(self.auth_headers)
        self.auth_headers.update(headers)
        result = self.request(url_or_path, method="GET", params=params)
        self.auth_headers = saved
        return result
    return self.request(url_or_path, method="GET", params=params)

def head(self, url_or_path: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Convenience HEAD wrapper."""
    return self.request(url_or_path, method="HEAD", params=params)
```

**Verify:** `python -c "from tools.scoped_http import ScopedHttpClient; c = ScopedHttpClient('example.com'); print(hasattr(c, 'get'), hasattr(c, 'head'))"`

---

### P0-2. `allowed_headers` whitelist blocks CORS/security audit headers

**File:** `tools/scoped_http.py` (lines 153-157)

**Problem:** `_response_result()` only captures 7 headers:
```python
allowed_headers = {
    "content-type", "server", "strict-transport-security",
    "content-security-policy", "x-content-type-options",
    "x-frame-options", "referrer-policy",
}
```

Missing critical headers needed by CORS audit, open-redirect, and JWT skills:
- `access-control-allow-origin`
- `access-control-allow-credentials`
- `access-control-allow-methods`
- `access-control-allow-headers`
- `access-control-expose-headers`
- `access-control-max-age`
- `location` (for redirect analysis)
- `set-cookie` (for session analysis)
- `www-authenticate` (for auth analysis)
- `x-powered-by` (for tech fingerprinting)
- `x-xss-protection`
- `permissions-policy`
- `cross-origin-opener-policy`
- `cross-origin-embedder-policy`
- `cross-origin-resource-policy`

**Fix:** Replace the `allowed_headers` set at line 153:

```python
allowed_headers = {
    "content-type", "server", "strict-transport-security",
    "content-security-policy", "x-content-type-options",
    "x-frame-options", "referrer-policy",
    # CORS audit headers
    "access-control-allow-origin", "access-control-allow-credentials",
    "access-control-allow-methods", "access-control-allow-headers",
    "access-control-expose-headers", "access-control-max-age",
    # Redirect & auth
    "location", "www-authenticate",
    # Session & cookies (value truncated by existing [:500])
    "set-cookie",
    # Security & fingerprinting
    "x-powered-by", "x-xss-protection", "permissions-policy",
    "cross-origin-opener-policy", "cross-origin-embedder-policy",
    "cross-origin-resource-policy",
}
```

**Verify:** Run `cors-audit` skill and check that `access-control-allow-origin` appears in response headers.

---

### P0-3. `http_get` tool inside `agent_runtime.py` calls non-existent `.get()` method

**File:** `tools/agent_runtime.py` (line 360)

**Problem:** `build_default_agent_tools()` → `http_get()` function calls `client.get(url, headers=headers or {})` but `ScopedHttpClient` has no `.get()` method.

**Fix:** After P0-1 is fixed, this will work. If P0-1 is NOT done, change line 360 to `client.request(url, method="GET")`.

---

### P0-4. `--in-scope` / `--out-of-scope` CLI flags are set as env vars but never read by `ScopeValidator`

**Files:**
- `run.py` (lines 187-190) — sets `MOROS_IN_SCOPE` and `MOROS_OUT_OF_SCOPE` env vars
- `tools/scope_validator.py` (lines 19-36) — `__init__` never reads these env vars

**Problem:** User runs `python run.py --target x.com --in-scope "*.x.com,api.x.com" --out-of-scope "blog.x.com"` — these get stored in env vars but `ScopeValidator` ignores them. The scope is effectively only the defaults.

**Fix:** Add env var reading in `ScopeValidator.__init__`, after `_load_from_target_dir()`:

```python
# Add after line 31: self._load_from_target_dir(Path(target_dir))

# Also read from env vars set by --in-scope / --out-of-scope CLI flags
env_in = os.environ.get("MOROS_IN_SCOPE", "").strip()
if env_in:
    for s in env_in.split(","):
        s_clean = s.strip().lower()
        if s_clean and s_clean not in self.in_scope:
            self.in_scope.append(s_clean)

env_out = os.environ.get("MOROS_OUT_OF_SCOPE", "").strip()
if env_out:
    for s in env_out.split(","):
        s_clean = s.strip().lower()
        if s_clean and s_clean not in self.out_of_scope:
            self.out_of_scope.append(s_clean)
```

Also add `import os` at the top of `scope_validator.py` (currently missing).

**Verify:** `python -c "import os; os.environ['MOROS_IN_SCOPE']='*.test.com'; from tools.scope_validator import ScopeValidator; sv = ScopeValidator('test.com'); print(sv.in_scope)"`

---

### P0-5. `ollama` appears twice in `--provider` choices

**File:** `run.py` (line 115)

**Problem:** 
```python
parser.add_argument("--provider", choices=list(KNOWN_PROVIDERS.keys()) + ["ollama"], ...)
```
`KNOWN_PROVIDERS` already contains `"ollama"` (see `llm_client.py` line 139), so `ollama` appears twice in the choices list. While argparse may not crash, `--help` shows it twice.

**Fix:** Change line 115 to:
```python
parser.add_argument("--provider", choices=list(KNOWN_PROVIDERS.keys()), default=None,
```

---

### P0-6. `scan-mode` CLI help says "14-skill" but there are 22+ skills

**File:** `run.py` (line 90)

**Problem:** Help text says `deep/full (full 14-skill exploit suite)` — now there are 22 skills.

**Fix:** Change to: `help="Scan profile: quick (surface recon & discovery), deep/full (full exploit suite), passive (zero active probes)"`

---

## P1 — Core Feature Gaps

### P1-1. `scope.json` auto-generation during `init-target`

**File:** `setup.py` → `init_target()` function (line 34)

**Problem:** No `scope.json` template is generated when initializing a target. Users must create it manually.

**Fix:** Add after line 103 (before the print statements):

```python
# Create scope.json template
scope_json = target_dir / "scope.json"
if not scope_json.exists():
    scope_template = {
        "target": domain,
        "in_scope": [domain, f"*.{domain}"],
        "out_of_scope": [],
        "notes": "Edit this file to define precise scope boundaries"
    }
    scope_json.write_text(
        json.dumps(scope_template, indent=2) + "\n",
        encoding="utf-8"
    )
```

Also add `import json` at the top of `setup.py` (currently missing).

**Verify:** `python setup.py init-target --domain test123.com` then check `targets/test123.com/scope.json` exists.

---

### P1-2. `scope-of-work.md` template auto-generation

**File:** `setup.py` → `init_target()` function

**Problem:** Only a `.txt` placeholder is created (`PLACE_SCOPE_OF_WORK_HERE.txt`). Should also create a `scope-of-work.md` template so scope verification passes.

**Fix:** Add after the `scope.json` creation:

```python
# Create scope-of-work.md template
scope_md = target_dir / "scope-of-work.md"
if not scope_md.exists():
    scope_md.write_text(
        f"# Scope of Work — {domain}\n\n"
        f"## Authorization\n"
        f"This assessment of `{domain}` is authorized under:\n"
        f"- [ ] Bug Bounty Program\n"
        f"- [ ] Penetration Testing Agreement\n"
        f"- [ ] Written Authorization\n\n"
        f"## In Scope\n"
        f"- `{domain}`\n"
        f"- `*.{domain}`\n\n"
        f"## Out of Scope\n"
        f"- (add excluded hosts here)\n\n"
        f"## Rules of Engagement\n"
        f"- Non-destructive testing only\n"
        f"- No denial of service\n"
        f"- No data exfiltration\n",
        encoding="utf-8"
    )
```

---

### P1-3. Agent budget limits too small for real pentesting

**File:** `tools/agent_runtime.py`

**Problem:** 
- `AgentContext` default budget (line 44): `max_steps=6, max_tokens=4000, timeout_seconds=180` — far too small for real ReAct loops with LLMs like DeepSeek.
- Subagent budget (line 498): `max_steps=5, max_tokens=4000, timeout_seconds=120` — also too small.

**Fix:**
- Line 44: Change to `"max_steps": 25, "max_tokens": 8192, "timeout_seconds": 600`
- Line 498: Change to `"max_steps": 15, "max_tokens": 8192, "timeout_seconds": 300`

---

### P1-4. Rate-limit budget not shared across skills

**Files:**
- `tools/skill_runner.py` (line 52): Each `SkillRunner` creates its own `ScopedHttpClient`
- `tools/hackbot_orchestrator.py` (line 127-129): Orchestrator creates one `SkillRunner` with one client

**Problem:** The `--max-http-requests` budget is per-`ScopedHttpClient` instance. If skills internally create new clients (like custom skill `run.py` scripts do — see `cors-audit/run.py` line 43), they get their own separate budget.

**Fix:** Pass the orchestrator's `ScopedHttpClient` instance to custom skill scripts via environment variable:
```python
# In hackbot_orchestrator.py _execute_skill(), for custom skills:
os.environ["MOROS_HTTP_REQUESTS_REMAINING"] = str(
    self.runner.http.max_requests - self.runner.http.request_count
)
```

And in custom skill `run.py` scripts, read this:
```python
budget = int(os.environ.get("MOROS_HTTP_REQUESTS_REMAINING", "50"))
client = ScopedHttpClient(target=args.target, max_requests=budget, ...)
```

---

### P1-5. No `--verbose` / `--quiet` / `--log-level` flags

**File:** `run.py`

**Problem:** No way to control output verbosity.

**Fix:** Add CLI flags:
```python
parser.add_argument("--verbose", "-v", action="store_true",
                    help="Enable verbose debug output")
parser.add_argument("--quiet", "-q", action="store_true",
                    help="Suppress informational output, show only errors and results")
parser.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                    default="INFO", help="Set logging verbosity")
```

Then after `load_dotenv_if_present()`:
```python
if args.verbose:
    logging.basicConfig(level=logging.DEBUG)
elif args.quiet:
    logging.basicConfig(level=logging.ERROR)
else:
    logging.basicConfig(level=getattr(logging, args.log_level, logging.INFO))
```

---

### P1-6. SARIF export doesn't include PoC file paths

**File:** `tools/sarif_exporter.py`

**Problem:** The SARIF exporter generates rules and results but doesn't include PoC script paths (`poc_sh`, `poc_py`) from findings in the SARIF `relatedLocations` or `properties`.

**Fix:** In the SARIF result builder, add:
```python
if finding.get("poc_sh"):
    result["properties"] = result.get("properties", {})
    result["properties"]["poc_scripts"] = {
        "bash": finding["poc_sh"],
        "python": finding.get("poc_py", ""),
    }
```

---

### P1-7. `generate_operator_guide.py` outdated

**File:** `tools/generate_operator_guide.py`

**Problem:** Likely references old 14-skill architecture, missing new features (dynamic skills, multi-LLM, auth scanning, PoC generation, webhooks, scope rules).

**Fix:** Regenerate the operator guide to reflect the full current feature set, or mark it deprecated and point to README.md.

---

### P1-8. No parallel skill execution

**File:** `tools/hackbot_orchestrator.py` (lines 268-316)

**Problem:** Skills run sequentially. After `js-analyze` completes, all vulnerability skills (`xss-*`, `ssrf-*`, custom skills) could run in parallel since they're independent of each other.

**Fix:** Add a `--parallel` CLI flag and implement using `concurrent.futures.ThreadPoolExecutor`:

```python
# In hackbot_orchestrator.py run() method, after Step 4:
if parallel_mode:
    from concurrent.futures import ThreadPoolExecutor, as_completed
    
    # Group skills: serial_prereqs run first, then parallel_independents, then serial_finalizers
    serial_prereqs = [s for s in ordered_skills if s in {"recon-subdomain", "api-spec-discovery", "js-discover", "js-analyze", "content-discovery"}]
    serial_finalizers = [s for s in ordered_skills if s in {"review-skill", "report-conglomeration"}]
    parallel_independents = [s for s in ordered_skills if s not in serial_prereqs and s not in serial_finalizers]
    
    # Run prereqs serially
    for skill in serial_prereqs:
        self._execute_skill(skill, model, 1)
    
    # Run independents in parallel
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {executor.submit(self._execute_skill, s, model, 1): s for s in parallel_independents}
        for future in as_completed(futures):
            skill_name = futures[future]
            result = future.result()
            # ... handle result
    
    # Run finalizers serially
    for skill in serial_finalizers:
        self._execute_skill(skill, model, 1)
```

---

## P2 — Missing Skills (Attack Surface)

> These skills significantly expand Moros's offensive security coverage. Each needs a `skills/<name>/SKILL.md` and optionally a `run.py`.

### P2-1. IDOR Skill (`skills/idor-audit/`)

Create `SKILL.md` and `run.py`:
- Scan API endpoints for numeric/UUID resource IDs
- Test for horizontal privilege escalation (changing ID values)
- Check for missing authorization on direct object references
- CWE: CWE-639

### P2-2. SSTI Skill (`skills/ssti-detect/`)

Create `SKILL.md` and `run.py`:
- Inject template syntax (` {{7*7}}`, `${7*7}`, `<%= 7*7 %>`) into input parameters
- Detect math evaluation in responses (49)
- Identify template engine from error messages
- CWE: CWE-1336

### P2-3. CRLF Injection Skill (`skills/crlf-injection/`)

Create `SKILL.md` and `run.py`:
- Inject `%0d%0a` sequences in URL parameters and headers
- Check for header injection in responses
- Detect HTTP response splitting
- CWE: CWE-93

### P2-4. HTTP Request Smuggling Skill (`skills/http-smuggling/`)

Create `SKILL.md` and `run.py`:
- Test CL.TE and TE.CL desync patterns
- Detect front-end/back-end server discrepancies
- Requires careful non-destructive probing
- CWE: CWE-444

### P2-5. Subdomain Takeover Skill (`skills/subdomain-takeover/`)

Create `SKILL.md` and `run.py`:
- Cross-reference discovered subdomains with known takeover fingerprints (GitHub Pages, Heroku, AWS S3, Azure, etc.)
- Check for dangling CNAME records pointing to unclaimed services
- CWE: CWE-284

### P2-6. Host Header Injection Skill (`skills/host-header-injection/`)

Create `SKILL.md` and `run.py`:
- Inject alternate `Host` header values
- Test `X-Forwarded-Host`, `X-Forwarded-For` abuse
- Check password reset poisoning via Host header
- CWE: CWE-20

### P2-7. Path Traversal Skill (`skills/path-traversal/`)

Create `SKILL.md` and `run.py`:
- Test file download endpoints for `../` traversal
- Check URL-encoded variants (`%2e%2e%2f`)
- CWE: CWE-22

### P2-8. XXE Injection Skill (`skills/xxe-detect/`)

Create `SKILL.md` and `run.py`:
- Test XML-accepting endpoints for XXE
- Inject DTD payloads for external entity resolution
- CWE: CWE-611

### P2-9. Business Logic Skill (`skills/business-logic/`)

Create `SKILL.md` (agent-driven, no `run.py`):
- LLM-powered analysis of application flow
- Identifies price manipulation, coupon reuse, rate-limit bypass vectors
- CWE: CWE-840

### P2-10. Rate Limiting Skill (`skills/rate-limit-test/`)

Create `SKILL.md` and `run.py`:
- Test for missing rate limits on login, signup, password reset endpoints
- Measure response times and status codes across rapid requests
- CWE: CWE-770

---

## P3 — Dashboard & UI Gaps

### P3-1. Hardcoded `ALL_SKILLS` list in dashboard

**File:** `dashboard/server.py` (lines 48-65)

**Problem:** `ALL_SKILLS` is hardcoded with only 15 core skills. While `get_skills_meta()` (line 763) correctly uses `SkillRegistry().list_skills()`, the hardcoded list at the top of the file is referenced elsewhere and may confuse maintainers.

**Fix:** Remove the `ALL_SKILLS` constant entirely (lines 48-65). Replace any references to it with `SkillRegistry().list_skills()` or `[s["id"] for s in SkillRegistry().list_skills()]`.

---

### P3-2. Dashboard `index.html` missing new features

**File:** `dashboard/static/index.html`

**Problem:** The dashboard HTML may not include UI controls for:
- Custom skill creation modal complete with `run.py` file upload
- Authentication settings (cookie, auth-header, auth-file)
- Scope rules editor (in-scope, out-of-scope patterns)
- Notification settings for Telegram and Slack (only Discord exists)
- Display of PoC scripts in finding cards
- Display of SARIF download link

**Fix:** Audit `dashboard/static/index.html` and add missing UI sections.

---

### P3-3. Dashboard scan mode options

**File:** `dashboard/server.py` → `start_scan_job()` and dashboard HTML

**Problem:** Dashboard may not offer scan mode selection or only offers "quick" by default (line 416).

**Fix:** Ensure the dashboard scan start UI includes a dropdown for `quick`, `deep`, `full`, `passive` modes.

---

## P4 — Documentation & README

### P4-1. README test count outdated

**File:** `README.md` (line 14, 262-290)

**Problem:** 
- Badge says "32 passed (100%)" but actual count is 47
- Test output section shows only 22 tests

**Fix:** Update the badge to `47%20passed%20(100%25)` and replace the test output section with the actual current output showing all 47 tests.

---

### P4-2. README missing advanced features documentation

**File:** `README.md`

Missing sections for:
- Multi-LLM provider configuration (all 14+ providers with env vars)
- Authenticated scanning (`--cookie`, `--auth-header`, `--auth-file`)
- Scope rules engine (`--in-scope`, `--out-of-scope`, `scope.json`)
- PoC auto-generation explanation
- Webhook alerts (Discord, Telegram, Slack)
- Agent runtime architecture details
- Custom skill `run.py` authoring guide
- Subagent spawning explanation

**Fix:** Add these sections to README.md with examples and code snippets.

---

### P4-3. Missing CONTRIBUTING.md

**Problem:** No contributor guidelines exist.

**Fix:** Create `CONTRIBUTING.md` with:
- How to add a new skill (folder structure, SKILL.md format, optional run.py)
- How to add a new LLM provider
- Testing requirements
- Code style guidelines

---

### P4-4. Missing CHANGELOG.md

**Problem:** No changelog exists.

**Fix:** Create `CHANGELOG.md` with entries for each Git commit.

---

## P5 — Testing Gaps

### P5-1. No integration test for `run.py`

**Problem:** No test runs `run.py --dry-run` or `run.py --list-skills` end-to-end.

**Fix:** Create `tests/test_integration.py`:

```python
import subprocess
import sys

def test_dry_run_exits_cleanly(tmp_path):
    """Test that --dry-run shows plan and exits 0."""
    # Create a fake target dir
    target_dir = tmp_path / "targets" / "test.local"
    target_dir.mkdir(parents=True)
    (target_dir / "scope-of-work.md").write_text(
        "# Scope\nAuthorized testing of test.local\n## In Scope\n- test.local"
    )
    (target_dir / "output").mkdir()
    
    result = subprocess.run(
        [sys.executable, "run.py", "--target", "test.local",
         "--target-dir", str(target_dir), "--dry-run"],
        capture_output=True, text=True, cwd="d:/Moros Ai"
    )
    assert result.returncode == 0
    assert "DRY RUN" in result.stdout

def test_list_skills():
    result = subprocess.run(
        [sys.executable, "run.py", "--list-skills"],
        capture_output=True, text=True, cwd="d:/Moros Ai"
    )
    assert result.returncode == 0
    assert "recon-subdomain" in result.stdout

def test_check_prerequisites():
    result = subprocess.run(
        [sys.executable, "run.py", "--check"],
        capture_output=True, text=True, cwd="d:/Moros Ai"
    )
    assert result.returncode in (0, 1)  # 0 = all met, 1 = some missing
```

---

### P5-2. No test for `ScopedHttpClient.get()` convenience method

After P0-1 is implemented, add:

```python
def test_scoped_http_get_method():
    from tools.scoped_http import ScopedHttpClient
    client = ScopedHttpClient("example.com", max_requests=5)
    assert hasattr(client, "get")
    assert hasattr(client, "head")
```

---

### P5-3. No test for scope env var reading

After P0-4 is implemented, add:

```python
def test_scope_validator_reads_env_vars(monkeypatch):
    monkeypatch.setenv("MOROS_IN_SCOPE", "api.test.com,*.cdn.test.com")
    monkeypatch.setenv("MOROS_OUT_OF_SCOPE", "blog.test.com")
    from tools.scope_validator import ScopeValidator
    sv = ScopeValidator("test.com")
    assert "api.test.com" in sv.in_scope
    assert "blog.test.com" in sv.out_of_scope
    allowed, _ = sv.is_allowed("api.test.com")
    assert allowed
    allowed, _ = sv.is_allowed("blog.test.com")
    assert not allowed
```

---

### P5-4. `test_scan_modes.py` has only 1 test

**File:** `tests/test_scan_modes.py`

**Problem:** Only tests skill resolution, not actual scan execution behavior.

**Fix:** Add tests for each scan mode's skill list:
```python
def test_quick_mode_skills():
    # Verify quick mode selects correct subset
    ...

def test_passive_mode_skills():
    # Verify passive mode excludes active skills
    ...

def test_full_mode_includes_custom_skills():
    # Verify full mode includes dynamically discovered custom skills
    ...
```

---

### P5-5. No test for `PoCGenerator` with custom headers

Add:
```python
def test_poc_generator_with_auth_headers(tmp_path):
    from tools.poc_generator import PoCGenerator
    gen = PoCGenerator("test.com", tmp_path / "output")
    finding = {"title": "SQLi", "url": "https://test.com/api", "severity": "HIGH"}
    result = gen.generate_poc(finding, custom_headers={"Authorization": "Bearer xxx"})
    sh_content = (tmp_path / "output" / "pocs" / Path(result["poc_sh"]).name).read_text()
    assert "Bearer xxx" in sh_content
```

---

### P5-6. No test for `AlertDispatcher` Telegram and Slack

Currently only tests Discord. Add mock tests for Telegram and Slack channels.

---

### P5-7. No test for `setup.py init-target`

```python
def test_init_target_creates_structure(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    # ... test that init_target creates all expected directories and files
```

---

## P6 — Configuration & Build System

### P6-1. `requirements.txt` has phantom dependencies

**File:** `requirements.txt`

**Problem:** Lists packages not actually used in the codebase:
- `aiohttp` — not imported anywhere (all HTTP is sync `urllib`)
- `asyncio-extra` — not imported anywhere
- `urllib3` — not imported (uses stdlib `urllib`)
- `lxml` — not imported
- `requests` — not imported (uses stdlib `urllib`)
- `beautifulsoup4` / `bs4` — not imported in core code
- `rich` — not imported in core code
- `click` — not imported in core code
- `python-dateutil` — not imported
- `tqdm` — not imported

Actual runtime dependencies:
- `playwright` — used in `browser-crawl.py`
- `jsbeautifier` — used in `js-beautifier.py`
- `PyYAML` — used in `openapi_import.py`

**Fix:** Replace `requirements.txt` with:
```
# Core runtime
playwright>=1.40.0
jsbeautifier>=1.14.0
PyYAML>=6.0

# Dev / testing
pytest>=7.0
```

Optionally keep `rich` and `tqdm` if future UI enhancements will use them.

---

### P6-2. Missing `pyproject.toml`

**Problem:** No modern Python project metadata file.

**Fix:** Create `pyproject.toml`:
```toml
[project]
name = "moros-ai"
version = "1.0.0"
description = "Autonomous Agentic Web Penetration Testing System"
requires-python = ">=3.10"
license = {text = "MIT"}

[project.scripts]
moros = "run:main"

[tool.pytest.ini_options]
testpaths = ["tests"]
```

---

### P6-3. `.gitignore` excludes `.env` but `__pycache__/` dirs are in repo

**File:** `.gitignore` (line 11)

**Problem:** `.env` is correctly excluded, but verify `.env.example` is tracked (it is — good). However, `__pycache__/` directories inside `tools/` and `dashboard/` are present in the repo (visible in file listing).

**Fix:** Run `git rm -r --cached **/__pycache__/` to remove cached pycache from git.

---

### P6-4. `setup.py` missing `import json`

**File:** `setup.py`

**Problem:** If P1-1 (scope.json generation) is added, `json` import is needed. Currently `json` is not imported.

**Fix:** Add `import json` to the imports at line 11-16.

---

## P7 — Performance & Architecture

### P7-1. Custom skill `run.py` import path is fragile

**Files:** All `skills/*/run.py` files

**Problem:** Each `run.py` does:
```python
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "tools"))
```
This breaks if the skill folder depth changes.

**Fix:** Use a more robust approach:
```python
# Find project root by locating run.py or tools/ directory
_skill_dir = Path(__file__).parent.resolve()
_project_root = _skill_dir
while _project_root != _project_root.parent:
    if (_project_root / "tools").is_dir() and (_project_root / "run.py").is_file():
        break
    _project_root = _project_root.parent
sys.path.insert(0, str(_project_root / "tools"))
```

Apply to all 7 custom skill `run.py` files:
- `skills/cors-audit/run.py`
- `skills/graphql-audit/run.py`
- `skills/jwt-analysis/run.py`
- `skills/open-redirect/run.py`
- `skills/prototype-pollution/run.py`
- `skills/sqli-heuristic/run.py`
- `skills/websocket-audit/run.py`

---

### P7-2. No graceful Playwright skip

**Files:** `tools/browser-crawl.py`, `run.py`

**Problem:** If Playwright is not installed, `browser-crawl.py` fails with an import error. The error is caught by `subprocess` timeout in `skill_runner.py` but the error message is confusing.

**Fix:** Add a graceful check at the top of `browser-crawl.py`:
```python
try:
    from playwright.sync_api import sync_playwright
except ImportError:
    print(json.dumps({"status": "SKIPPED", "reason": "playwright not installed"}))
    sys.exit(0)
```

---

### P7-3. `hackbot_orchestrator.py` SKILL_DEPENDENCIES doesn't include custom skills

**File:** `tools/hackbot_orchestrator.py` (lines 71-84)

**Problem:** `SKILL_DEPENDENCIES` is hardcoded with only core skills. Custom skills (like `cors-audit`, `jwt-analysis`) have no dependency entries, so they never benefit from dependency validation.

**Fix:** Read dependencies from `SKILL.md` metadata. Add a `## Dependencies` section to SKILL.md format:
```markdown
## Dependencies
- js-analyze
```

And modify `SkillRegistry` to parse this:
```python
# In _parse_skill_md(), add:
m_deps = re.search(r"## Dependencies\s*\n(.*?)(?=\n##|\Z)", text, re.DOTALL)
if m_deps:
    deps = re.findall(r"-\s*`?([a-zA-Z0-9_-]+)`?", m_deps.group(1))
```

---

### P7-4. Dashboard `start_scan_job()` runs scan in subprocess with no max-subagents control

**File:** `dashboard/server.py`

**Problem:** When a scan is started from the dashboard, the `--max-subagents` flag is not passed to the subprocess.

**Fix:** Add `max_subagents` parameter to `start_scan_job()` and pass it through.

---

### P7-5. No progress streaming / SSE endpoint for real-time dashboard updates

**File:** `dashboard/server.py`

**Problem:** Dashboard must poll `/api/scan/status` repeatedly. No Server-Sent Events (SSE) endpoint for real-time updates.

**Fix:** Add an SSE endpoint `/api/scan/stream` that streams skill progress events:
```python
def handle_sse_stream(self, target):
    self.send_response(200)
    self.send_header("Content-Type", "text/event-stream")
    self.send_header("Cache-Control", "no-cache")
    self.end_headers()
    # Stream events from RunManager...
```

---

### P7-6. Conversation history truncation

**File:** `tools/agent_runtime.py` (line 200-201)

**Problem:** Agent history is truncated to `[-40:]` items and `[-48000:]` chars. For complex multi-step analyses, this may cause the agent to lose context.

**Fix:** Make these configurable via `AgentContext.budget`:
```python
max_history_items = context.budget.get("max_history_items", 40)
max_prompt_chars = context.budget.get("max_prompt_chars", 48000)
```

---

### P7-7. No retry mechanism in `_call_openai_compatible`

**File:** `tools/llm_client.py` (line 274)

**Problem:** The OpenAI-compatible endpoint call has no retry logic. Only Gemini has retry/backoff (line 372). If DeepSeek or OpenAI returns 503/429, the call fails immediately.

**Fix:** Add retry logic similar to Gemini's:
```python
def _call_openai_compatible(self, prompt, system_prompt, temperature, max_tokens):
    # ... existing setup ...
    for attempt in range(3):
        try:
            req = urllib.request.Request(url, ...)
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            return data["choices"][0]["message"]["content"]
        except urllib.error.HTTPError as exc:
            if exc.code in (429, 503) and attempt < 2:
                wait = (attempt + 1) * 2
                logger.warning(f"{self.provider}/{self.model} HTTP {exc.code}; retrying in {wait}s...")
                time.sleep(wait)
                continue
            raise
```

---

## Verification Commands

After implementing all fixes, run these commands to verify:

```bash
# 1. Run full test suite (must stay at 47+ tests, all passing)
python -m pytest tests/ -v

# 2. List skills (should show 22+ skills including custom)
python run.py --list-skills

# 3. Dry run
python run.py --target example.com --target-dir targets/example.com --dry-run

# 4. Check prerequisites
python run.py --check
python setup.py check

# 5. Init a new target (verify scope.json + scope-of-work.md are created)
python setup.py init-target --domain verification-test.local
dir targets\verification-test.local\

# 6. Help text (verify no duplicate "ollama", scan-mode text updated)
python run.py --help

# 7. Verify .get() method exists
python -c "from tools.scoped_http import ScopedHttpClient; c = ScopedHttpClient('example.com'); print(hasattr(c, 'get'))"

# 8. Verify scope env vars work
python -c "import os; os.environ['MOROS_IN_SCOPE']='*.test.com'; from tools.scope_validator import ScopeValidator; sv = ScopeValidator('test.com'); print(sv.in_scope)"

# 9. Git commit and push
git add -A
git commit -m "fix: resolve all remaining gaps from full codebase audit"
git push origin main
```

---

## Summary

| Priority | Count | Description |
|----------|-------|-------------|
| P0 (Critical Bugs) | 6 | Broken functionality that causes crashes or silent failures |
| P1 (Core Gaps) | 8 | Missing features that limit real-world usage |
| P2 (Missing Skills) | 10 | Core offensive attack categories |
| P3 (Dashboard) | 3 | UI/UX gaps in the web dashboard |
| P4 (Documentation) | 4 | README, CONTRIBUTING, CHANGELOG |
| P5 (Testing) | 7 | Missing test coverage |
| P6 (Build System) | 4 | requirements.txt, pyproject.toml, .gitignore |
| P7 (Architecture) | 7 | Performance, retry logic, parallelism |
| **Total** | **49** | |
