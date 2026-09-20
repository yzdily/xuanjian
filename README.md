# XuanJian — Agentic Security Scanner

> An autonomous penetration testing agent that drives a real browser, intercepts traffic, follows methodology, validates findings, and writes its own report — without ever forgetting a test step.

**v2.0 Stable** — XuanJian is an actively maintained open-source agentic security scanner.
The AI-native security testing platform (LLM / Agent / RAG security) builds on the XuanJian engine at [**JianWei**](https://github.com/yzdily/jianwei).
See [ARCHITECTURE.md](ARCHITECTURE.md) · [CHANGELOG.md](CHANGELOG.md) · [中文文档](README.zh.md)

<p>
  <a href="#platform-support">Platform Support</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#features">Features</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#knowledge-base">Knowledge Base</a> •
  <a href="#contributing">Contributing</a>
</p>

---

> ⚠️ **Legal notice**: This tool is for **legally authorized** security testing only. You must obtain **explicit written permission** from the target system owner before any use, and you must comply with all applicable local and international laws. **Unauthorized use is a crime**, and you bear full legal responsibility for your actions. By using this tool you confirm that you have read, understood, and accepted all risks. See [DISCLAIMER.md](DISCLAIMER.md) for the full legal terms.

> **Not a signature scanner.** XuanJian behaves like a human pentester — drives the browser, intercepts and rewrites traffic, reasons about business logic, crafts payloads, validates vulnerabilities, and suppresses false positives — but never forgets a test step.

---

## Platform Support

XuanJian runs natively on the three major desktop platforms. Pick the launcher that matches your OS:

| OS | Recommended launcher | Alternative | Notes |
|---|---|---|---|
| **Windows 10/11** | `.\start.ps1` (PowerShell 5.1+) or `scripts\launch.bat` | `python start.py` | PowerShell is bundled with Windows; `launch.bat` is the legacy entry point. |
| **macOS 12+** | `./start.sh` or **double-click `start.command`** in Finder | `python3 start.py` | `start.command` opens Terminal.app and runs the same command. |
| **Linux (Ubuntu/Debian/Fedora/Arch)** | `./start.sh` | `python3 start.py` | Tested on Ubuntu 22.04+; other distros should work but are not CI-tested. |
| **Docker (any host)** | `docker compose up -d` | `make docker-up` | Multi-arch image (`linux/amd64`, `linux/arm64`). Web UI: `http://localhost:7788`. |

> **Why three launchers?** `start.py` already does platform detection (handles macOS Python.framework paths, Windows venv `Scripts\`, Linux `~/.local/bin`). The wrappers just pick the right Python interpreter on each OS, so users don't have to remember whether to type `python` or `python3`.

All three launchers are functionally equivalent — they ultimately call `python start.py` with whatever arguments you pass.

---

## Quick Start

### Option 1: One-liner per platform

```bash
# --- macOS / Linux (bash) ---
git clone https://github.com/yzdily/xuanjian.git
cd xuanjian
./start.sh

# --- Windows (PowerShell) ---
git clone https://github.com/yzdily/xuanjian.git
cd xuanjian
.\start.ps1

# --- Windows (cmd, legacy) ---
git clone https://github.com/yzdily/xuanjian.git
cd xuanjian
scripts\launch.bat
```

The launcher runs a 5-step environment check (Python version, dependencies, `.env`, browser, port availability) before starting the Web UI. If something is missing, it tells you exactly what to install and how.

### Option 2: Manual step-by-step

> **Requirements**: Python **>= 3.10**, Git, ~500 MB free disk for Playwright Chromium.

```bash
# 1. Clone the repository
git clone https://github.com/yzdily/xuanjian.git
cd xuanjian

# 2. Install Python dependencies
python -m pip install -r requirements.txt

# 3. Download the browser engine
python -m playwright install chromium

# 4. Configure your LLM provider
cp .env.example .env        # then edit .env to add your API key
#   (alternatively, you can configure the model later inside the Web UI)

# 5. Start XuanJian
python start.py
```

> Slow Chromium download? Set a mirror:
> ```bash
> export PLAYWRIGHT_DOWNLOAD_HOST=https://npmmirror.com/mirrors/playwright   # macOS/Linux
> $env:PLAYWRIGHT_DOWNLOAD_HOST = "https://npmmirror.com/mirrors/playwright" # PowerShell
> ```

### Option 3: Docker (no Python install required)

```bash
git clone https://github.com/yzdily/xuanjian.git
cd xuanjian
docker compose up -d
```

Open `http://localhost:7788` to access the Web UI. The container runs as a non-root user, drops all capabilities, and binds the Web/proxy ports to `127.0.0.1` only. See [docker-compose.yml](docker-compose.yml) for the full hardening list.

### Open the Web UI

After launch, open **http://localhost:7788** in your browser. On first run the system will prompt you to add an LLM API key in **Settings → Models** if you skipped step 4.

### Make commands (cross-platform)

If you have GNU make (Git Bash on Windows, or any Unix shell):

```bash
make help         # show all commands
make install      # pip install -r requirements.txt
make browser      # playwright install chromium
make run          # python start.py
make doctor       # environment self-check
make test         # pytest
make docker-up    # docker compose up -d
make docker-down  # docker compose down
make clean        # remove __pycache__ / .pytest_cache / .coverage
```

### Burp Suite integration

```bash
cd burp-plugin && ./gradlew jar
# Burp → Extender → Add → select build/libs/pentestagent-burp-1.0.0.jar
```

### Screenshots

**Auto login & attack surface discovery**:

<img alt="Homepage breakthrough" src="image/首页.png" />

**Multi-target parallel testing**:

<img alt="Multi-system parallel test" src="image/系统.png" />

---

## Features

### Core capabilities

| Capability | Description |
|---|---|
| **URL end-to-end pentest** | Input a target URL — crawler → analysis → testing → report, fully automatic. |
| **Credential-based pentest** | Input username/password + URL — auto-login then test. |
| **Credential injection** | Input Cookie / JWT / Header — bypass login and test directly. |
| **Manual login capture** | Playwright headed mode; capture Cookie/Token/Authorization interactively, with optional captcha support. |
| **SPA intelligent degradation** | Auto-detect Vue / React / Angular; switch to manual-browse + traffic-recording when links are insufficient. |
| **Captcha OCR** | Integrated OCR for image captchas; complex captchas support manual intervention. |
| **Custom SKILLs** | Encode your own pentest experience as a methodology; the agent grows with you. |

### Scan modes (two orthogonal dimensions)

The XuanJian "scan mode" is determined by **two orthogonal dimensions**, avoiding muddled semantics.

**Dimension 1 — scan depth** (controls LLM usage, concurrency, timeouts, skipped phases)

| Depth | LLM | When to use |
|---|---|---|
| **FAST** | None (local rules only) | Quick sweep; false-positive suppression is enforced by the detection layer's hard rules. |
| **STANDARD** | Partial (lightweight calls) | Day-to-day pentest, balanced speed vs. depth. |
| **DEEP** | Full pipeline | Maximum LLM-driven analysis + harm validation. |
| **SMART** | Adaptive | Analyze the target first, then choose FAST / STANDARD / DEEP automatically. |

**Dimension 2 — orchestration** (controls how tasks are scheduled)

| Orchestration | Flow | When to use |
|---|---|---|
| **Batch** | Crawl → analyze → parallel test → report | Whole-site pentest, fully automatic. |
| **Realtime** | Discover-and-test as you click | Quick validation. |
| **Packet** | Single HTTP packet runs the full vuln checklist | Burp integration, targeted testing. |

> The two dimensions are independent. `FAST × Batch` = no-LLM whole-site parallel scan; `DEEP × Realtime` = full-LLM crawl-and-test. In code, depth maps to `ScanMode` / `session.user_scan_mode`; orchestration maps to `session.scan_mode`.

### Engineering features

| Feature | Description |
|---|---|
| **Multi-session management** | Run multiple pentest tasks concurrently (with concurrency limits). |
| **Traffic management** | View, search, replay all mitmproxy traffic. |
| **Decision replay** | Step back through the LLM decision chain for any pentest action. |
| **Log traceability** | Complete LLM call and agent behavior logs. |
| **Experience accumulation** | Auto-learn from historical findings; reuse on similar targets. |
| **Custom report templates** | Customizable report output formats. |
| **Compliance reports** | Built-in compliance templates with vuln statistics and fix tracking. |
| **Hot model switching** | 10+ LLM providers, switchable from the Web UI. |
| **Usage telemetry** | LLM call counts, token consumption, cost — live in the UI. |

### Vulnerability coverage

Browser-driven + traffic-intercepted + LLM-deep analysis. Auto-detect and validate:

- **Web injection**: SQL injection (built-in Fuzz engine), XSS (reflected / stored / DOM — 13-step dedicated engine)
- **Auth/authz**: IDOR, auth bypass, unauthorized access
- **Server-side**: SSRF (with OOB out-of-band validation + harm proof), info disclosure, race conditions
- **Business logic**: Captcha bypass, user enumeration, business-logic analysis
- **Other**: CSRF, XXE, SSTI, file upload, path traversal, command injection

Highlights:
- **Harm validation**: an independent LLM auditor verifies real-world impact and suppresses false positives to SRC standards.
- **Detection-layer FP iron rules**: FastScanner enforces deterministic hard rules at detection time, not after the fact — so even FAST mode (which skips harm validation) stays clean.
- **Supplemental testing**: scans full traffic; newly discovered APIs are auto-tested.
- **Auto PoC generation**: generates runnable PoC scripts for every finding.
- **Extensible**: drop in your own SKILL files; any vuln type is supported.

### False-positive protection

Borrowing the **FP judgment iron rules** framework from [api-pentest-extension](https://github.com/yzdily/api-pentest-extension), the detection layer (not post-hoc LLM arbitration) enforces deterministic filtering:

| Layer | Mechanism | Coverage |
|---|---|---|
| **Business error code parsing** | HTTP 200 with `code:500`/`message:未登录` → not flagged as unauthorized | Unauthorized access, CORS, info disclosure |
| **Empty data detection** | 200 with `data:null`/`data:[]` → no data leak reported | Unauthorized access, CORS |
| **WAF block-page recognition** | 403/418/429/503 + `blocked`/`firewall`/`拦截` keywords → skip | Path traversal, command injection, SSRF |
| **Response normalization** | Strip dynamic content (timestamp/JWT/CSRF/hash) before boolean blind comparison | SQL injection |
| **SQL boolean blind — 3-layer check** | True≈baseline + False=WAF/error → skip; True≈baseline + False≈baseline → param ignored | SQL injection |
| **Time-based blind — 2nd reproduction** | Delay ≥ 3.5 s **and** reproducible — single hit is a flake | SQL injection |
| **XSS executable context** | Probe lands in HTML comment / plain JSON / `<textarea>` → downgrade to weak evidence | XSS |
| **Evidence quality grading** | All findings tagged `body_confirmed` / `header_only` for secondary review | All |
| **Command injection tightening** | Drop generic words like `whoami`/`total`; require output signature + exclude payload reflection | Command injection |
| **SSRF tightening** | Weak evidence path requires internal-service signature (Apache/nginx banner); OOB supported | SSRF |
| **Login-endpoint whitelist** | Auth endpoints skip the unauthorized-access check | Unauthorized access |
| **Expanded CSRF token names** | Broader CSRF token recognition | CSRF |

### Multiple entry points

- **Web UI** — chat-style interaction, multi-session, real-time reports, credential injection login
- **Burp Suite plugin** — right-click send + passive scan + SSE feedback
- **REST API** — third-party integration and CI/CD pipelines

---

## Architecture

Eight phases, no human in the loop:

| Phase | What happens | Who runs it |
|---|---|---|
| **Phase 0** | Site exploration (crawl + JS analysis + traffic capture + SPA fallback) | AutoCrawler |
| **Phase 0.5** | Business understanding (semantic analysis → attack hypotheses) | BusinessUnderstanding |
| **Phase 1** | Feature analysis (identify functionality → Checklist) | AnalyzeWorker |
| **Phase 1.5** | Business reconciliation (Checklist × business-understanding cross-verify) | Main Agent |
| **Phase 2a** | HTTP vulnerability tests (SQLi / IDOR / Unauthorized …) | 3 sub-agents in parallel |
| **Phase 2b** | Browser vulnerability tests (XSS / CSRF …) | Main Agent |
| **Phase 2.55** | Supplemental test (newly discovered APIs) | SupplementalTestAgent |
| **Phase 2.6** | Harm validation (FP suppression: detection-layer iron rules + LLM auditor) | HarmValidator |
| **Phase 3** | Report aggregation (coverage matrix + vuln details + remediation + PoC) | Main Agent |

> **Scan modes** are an orthogonal 2-D model (depth × orchestration) — see the *Scan modes* section above. Code-wise: `ScanMode` / `session.user_scan_mode` for depth; `session.scan_mode` for orchestration.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full module-level architecture diagram.

---

## Knowledge base

XuanJian is not driven by a built-in signature library — it's driven by **SKILL methodologies**. Each vulnerability class maps to a battle-tested methodology that the agent loads and follows step by step. Users can extend the library freely.

```
skills_my/
├── discovery/                # Vulnerability discovery methodologies
│   ├── builtin/
│   │   ├── _core/       (9)  Pentest philosophy / entry-point mapping / attack-surface / auth bypass …
│   │   ├── _phase/     (10)  Crawl strategy / JS extraction / passive recon / business analysis …
│   │   └── tech-stack/  (1)  Chinese tech-stack fingerprinting
│   └── personal/
│       ├── auth/        (2)  IDOR / captcha bypass
│       ├── csrf/        (1)  CSRF methodology
│       └── sqli/        (1)  SQL injection methodology
├── exploit/                  # Vulnerability exploitation methodologies
│   ├── exploit-ssrf/    (1)  SSRF harm proof
│   └── spring-jndi-exploit/ (1) Spring JNDI injection
└── wooyun-legacy-main/       # Wooyun historical vulnerability knowledge
    ├── categories/     (15)  SQLi / XSS / SSRF / command execution / logic flaws …
    ├── knowledge/       (8)  Category-level reference
    └── examples/        (2)  Banking / telecom pentest case studies
```

> ⚠️ **License note**: `skills_my/wooyun-legacy-main/` is **CC-BY-NC-SA-4.0 (non-commercial)**
> third-party content, which conflicts with the project's MIT License — **commercial use is prohibited**.
> The main SKILL library (`discovery/`, `exploit/`) is MIT and may be used commercially. See
> [skills_my/wooyun-legacy-main/LICENSE_NOTICE.md](skills_my/wooyun-legacy-main/LICENSE_NOTICE.md).

> 📖 Encode your own pentest experience as a SKILL — see [CONTRIBUTING_SKILLS.md](CONTRIBUTING_SKILLS.md).

---

## Comparison with similar tools

| Capability | XuanJian | Traditional scanner<br>(AWVS / Xray) | AI-assisted analyzer<br>(burp-ai-agent) |
|---|:---:|:---:|:---:|
| Business-logic understanding | ✅ LLM-deep | ❌ | 🟡 suggestions only |
| Auto payload crafting | ✅ | ✅ high FP | ❌ |
| Detection-layer FP iron rules | ✅ hard-rule filter | ❌ | ❌ |
| Harm validation | ✅ independent auditor | ❌ | ❌ |
| Browser interaction | ✅ Playwright | ❌ | ❌ |
| SPA intelligent fallback | ✅ manual + traffic record | ❌ | ❌ |
| Frontend crypto bypass | ✅ CryptoHook | ❌ | ❌ |
| Methodology-driven | ✅ SKILL engine | ❌ | ❌ |
| Experience learning | ✅ Memory | ❌ | ❌ |
| Auto PoC generation | ✅ | ❌ | ❌ |
| Report quality | flexible templates + compliance | manual | no report |

---

## Project layout

```
├── core/              # Agent core engine
│   ├── session/       #   Phased state machine (base + per-phase mixins)
│   ├── crawler/       #   Playwright crawler (crawler_core + SPA/form/login mixins + _blocklist)
│   ├── xss/           #   XSS dedicated engine (13-step: DOM/OOB/upload/CSP …)
│   ├── parallel/      #   Parallel scheduler (orchestrator + helpers + batch_test)
│   ├── harm_validation/ # Harm validation + FP filter (validator + render + _render_helpers)
│   ├── sitemap/       #   Sitemap + Checklist + path filter
│   ├── fast_scanner/  #   Fast scan engine (11 submodules: _engine + FP hard rules _fp_filters + _checks_*)
│   ├── llm/           #   LLM client (10 submodules: _client + _pool + _response_cache + _tokens)
│   ├── js_analyzer/   #   JS deep analysis (9 submodules: _extractors + _patterns + _cache + _llm)
│   ├── browse_worker/ #   Browser browse worker (5 submodules: _menu_parser + _menu_grouper + _ledger + _worker)
│   ├── dir_scanner/   #   Directory scan (5 submodules: _constants + _wordlist + _models + _scanner)
│   ├── supplemental_test_agent/ # Supplemental test agent (5 submodules: _discovery + _attach + _runner)
│   ├── worker_agent/  #   Pentest worker agent (3 submodules: _agent + _helpers mixin)
│   ├── fuzz/          #   Fuzz engine (sqli + race_condition + waf_bypass)
│   ├── crypto_replay/ #   Frontend crypto replay (learner + applier + store)
│   ├── scripted_scan/ #   Scripted scan (OpenAPI export + runner)
│   ├── credential_injector.py   # Standalone credential injector (manual login)
│   ├── false_positive_manager.py # False-positive tracking
│   ├── poc_generator.py # PoC auto-generation
│   ├── compliance_report.py # Compliance reporting
│   └── port_scanner.py   # Port scan
├── web/               # Web UI + FastAPI
│   └── api/           #   REST API (incl. credential-injection API)
├── mcp_servers/       # MCP tool services
├── burp-plugin/       # Burp Suite plugin (Java)
├── crypto_hook/       # Frida frontend-encryption hook
├── skills_my/         # Methodology knowledge base + Wooyun historical vuln library
├── image/             # README screenshots
├── docs/              # Project documentation
├── tests/             # Unit tests (incl. FP protection, SPA, race conditions …)
├── scripts/           # Helper scripts (ci_gate, build, knowledge sync …)
├── data/              # Runtime data (gitignored)
├── Makefile           # Cross-platform commands (make install / run / doctor / test …)
├── start.sh           # macOS / Linux launcher
├── start.command      # macOS Finder double-click launcher
├── start.ps1          # Windows PowerShell launcher
└── start.py           # Core launcher (cross-platform, 5-step env check)
```

> **Package split note**: Modules marked "N submodules" were split out of single-file god files (e.g. `fast_scanner.py` 3991 lines → `fast_scanner/` 11 submodules). Public/private names are re-exported through `__init__.py` for backward compatibility — `from core.fast_scanner import FastScanner` still works.

---

## Troubleshooting

### Windows: Web UI fails to start with `WinError 10013` (permission denied on the socket)

XuanJian's default Web UI port is **7788**. On Windows the OS can reserve entire port ranges (via Hyper-V / WinNAT / Docker) that no application is allowed to bind. If `7788` falls inside such a reserved range, `uvicorn` fails with `[WinError 10013]` even though `netstat` shows nothing listening on it.

Check the reserved ranges on your machine:

```bash
netsh interface ipv4 show excludedportrange protocol=tcp
```

Fix — start on a different port via the `WEB_PORT` environment variable (pick any port **outside** the excluded ranges, e.g. `8000`, `8080`, `9000`):

```bash
WEB_PORT=8000 python start.py     # then open http://localhost:8000
```

> Docker / Linux / macOS are unaffected — `7788` only fails when the Windows host reserves it, so the default stays `7788` and container deployments keep working unchanged.

### Windows: `PROXY_PORT` (18080) already in use

This is **not** an error. XuanJian automatically reuses an existing `mitmproxy` instance on `18080` (the log says "端口 18080 已有 mitmproxy 运行中，将复用现有实例"). To force a fresh instance instead, kill the old one first:

```powershell
# find the PID with: netstat -ano | findstr :18080
taskkill /PID <pid>          # graceful
taskkill /F /PID <pid>       # force
```

### Environment variables (all platforms)

| Variable | Default | Purpose |
|---|---|---|
| `WEB_PORT` | `7788` | Web UI listen port |
| `PROXY_PORT` | `18080` | mitmproxy proxy port |

---

## Contributing

Contributions of any kind are welcome:

- 🐛 **Open an issue** — bug reports or feature suggestions
- 📖 **[Contribute a methodology](CONTRIBUTING_SKILLS.md)** — encode your finding experience as a reusable SKILL
- 🔧 **Open a pull request** — code improvements, doc fixes
- ⭐ **Star the repo** — help others find it

> Methodology contributions via `skills_my/discovery/` or `skills_my/exploit/` are always welcome.

---

## ⚠️ Legal notice and disclaimer

> **This tool is for legally authorized security testing only. Unauthorized use is a crime.**

XuanJian is a **security testing** tool, **not an attack tool**. Unauthorized use against any system, network, or application may violate the **Cybersecurity Law of the People's Republic of China** and other applicable laws.

Users must:
1. Obtain **explicit written permission** from the target system owner.
2. Comply with all applicable local and international laws.
3. **Bear full legal responsibility** for their own actions.

**The developers disclaim all liability for any direct or indirect damages arising from use of this tool.**

Read the full legal terms in [DISCLAIMER.md](DISCLAIMER.md).

---

## 📄 License

[MIT](LICENSE)

## 🙏 Acknowledgements

This project is forked from [ScareAISec](https://github.com/haibo3434358/ScareAISec) (MIT License, Copyright © 2026 游刃AISec). On top of the original, XuanJian adds:

- Critical bug fixes in the scan pipeline (strategy config, vuln validation chain)
- Vulnerability UI and data-source consistency improvements
- Docker containerization + multi-arch automated image builds
- Open-source infrastructure (requirements.txt, CI/CD, docs)
- Cross-platform launchers (`Makefile`, `start.sh`, `start.command`, `start.ps1`)

Per the MIT License, the original copyright and license are preserved. All modifications in this project are also released under MIT.

---

<p align="center">
  <sub>If you like this project, please ⭐ star it!</sub>
</p>
