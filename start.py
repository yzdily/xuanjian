#!/usr/bin/env python3
"""
start.py — 跨平台一键启动 GapHunter（Windows / macOS / Linux）

用法:
    python start.py
    python3 start.py
"""

import argparse
import os
import sys
import time
import shutil
import signal
import socket
import subprocess
import importlib
import threading
from pathlib import Path

# ============================================================
# 生产模式 / 打包环境检测
# ============================================================

_IS_BUNDLED = getattr(sys, '_MEIPASS', None) is not None


def resolve_project_dir(force_production: bool = False) -> Path:
    """返回持久化项目目录。生产模式/打包环境下使用 exe 所在目录。"""
    if force_production or _IS_BUNDLED:
        return Path(sys.executable).parent.resolve()
    return Path(__file__).parent.resolve()


# ============================================================
# 配置
# ============================================================

WEB_PORT = int(os.getenv("WEB_PORT", "7788"))
# ★ O1 安全收口：Web 默认绑 127.0.0.1（XJ-02 补偿），避免裸暴露 0.0.0.0。
# 容器/需对外暴露时显式设 WEB_HOST=0.0.0.0（docker-compose 已设）。
WEB_HOST = os.getenv("WEB_HOST", "127.0.0.1")
PROXY_PORT = int(os.getenv("PROXY_PORT", "18080"))
IS_WINDOWS = sys.platform == "win32"
PROJECT_DIR = resolve_project_dir()
FLOW_FILE = Path(os.getenv("PROXY_FLOW_FILE", str(PROJECT_DIR / "data" / "pentest_agent_flows.jsonl")))

os.chdir(PROJECT_DIR)

# 优先从 .env 加载环境变量，确保各模块 load_dotenv() 能找到
from dotenv import load_dotenv
load_dotenv(PROJECT_DIR / ".env")

# ============================================================
# 颜色输出（Windows 也支持）
# ============================================================

if IS_WINDOWS:
    os.system("")  # 启用 Windows ANSI 转义序列支持
    os.environ["PYTHONIOENCODING"] = "utf-8"

RED = "\033[0;31m"
GREEN = "\033[0;32m"
YELLOW = "\033[0;33m"
CYAN = "\033[0;36m"
NC = "\033[0m"
BOLD = "\033[1m"


def ok(msg):
    print(f"  {GREEN}[OK]{NC} {msg}")

def warn(msg):
    print(f"  {YELLOW}[!]{NC} {msg}")

def fail(msg):
    print(f"  {RED}[x]{NC} {msg}")

def title(msg):
    print(f"{BOLD}{msg}{NC}")


# ============================================================
# 检查函数
# ============================================================

errors = 0


def check_python_version():
    global errors
    title("[0/5] 检查 Python 版本...")
    v = sys.version_info
    if v.major >= 3 and v.minor >= 10:
        ok(f"Python {v.major}.{v.minor}.{v.micro}")
    else:
        fail(f"Python {v.major}.{v.minor} — 需要 >= 3.10")
        print(f"  {YELLOW}下载地址:{NC} {CYAN}https://www.python.org/downloads/{NC}")
        sys.exit(1)


def check_dep(mod_name: str, pip_name: str):
    global errors
    try:
        importlib.import_module(mod_name)
        ok(pip_name)
    except ImportError:
        # ★ O10 禁运行时 pip install：生产环境（XUANJIAN_AUTO_INSTALL 未设或=0）
        # 缺失依赖直接 fail，不静默 pip install（构建期应预装，运行时安装有供应链风险）。
        # 开发态显式设 XUANJIAN_AUTO_INSTALL=1 保留自动安装行为。
        if os.getenv("XUANJIAN_AUTO_INSTALL", "0") != "1":
            fail(f"{pip_name} — 未安装（生产模式禁止运行时安装）")
            print(f"    请在构建期预装: {CYAN}{sys.executable} -m pip install {pip_name}{NC}")
            print(f"    开发态自动安装: 设环境变量 {CYAN}XUANJIAN_AUTO_INSTALL=1{NC}")
            errors += 1
            return
        warn(f"{pip_name} — 未安装，正在安装（XUANJIAN_AUTO_INSTALL=1）...")
        ret = subprocess.run(
            [sys.executable, "-m", "pip", "install", pip_name, "-q"],
            capture_output=True, text=True
        )
        try:
            importlib.import_module(mod_name)
            ok(f"{pip_name} — 已安装")
        except ImportError:
            fail(f"{pip_name} — 安装失败")
            print(f"    尝试: {CYAN}{sys.executable} -m pip install {pip_name}{NC}")
            if ret.stderr:
                print(f"    {ret.stderr.strip()[-200:]}")
            errors += 1


def check_dependencies():
    global errors
    print()
    title("[1/5] 检查 Python 依赖...")
    deps = [
        ("openai", "openai"),
        ("httpx", "httpx"),
        ("pydantic", "pydantic"),
        ("mcp", "mcp"),
        ("fastmcp", "fastmcp"),
        ("yaml", "pyyaml"),
        ("dotenv", "python-dotenv"),
        ("rich", "rich"),
        ("typer", "typer"),
        ("playwright", "playwright"),
        ("mitmproxy", "mitmproxy"),
        ("fastapi", "fastapi"),
        ("uvicorn", "uvicorn"),
    ]
    for mod, pip in deps:
        check_dep(mod, pip)
    # OCR / 验证码 — 可选依赖，不影响启动
    for mod_name, pip_name, label in [
        ("ddddocr", "ddddocr", "验证码自动识别"),
        ("rapidocr_onnxruntime", "rapidocr-onnxruntime", "OCR文字识别"),
    ]:
        try:
            importlib.import_module(mod_name)
            ok(f"{pip_name} — {label}可用")
        except ImportError:
            warn(f"{pip_name} — 未安装。{label}不可用，安装: pip install {pip_name}")


def check_env():
    global errors
    print()
    title("[2/5] 检查配置文件...")
    env_file = PROJECT_DIR / ".env"
    example_file = PROJECT_DIR / ".env.example"

    if env_file.exists():
        content = env_file.read_text(encoding="utf-8")
        if "LLM_1_API_KEY=sk-" in content and "LLM_1_API_KEY=sk-xxx" not in content and "LLM_1_API_KEY=sk-your" not in content:
            # 提取模型名
            for line in content.splitlines():
                if line.startswith("LLM_1_MODEL="):
                    model = line.split("=", 1)[1].strip()
                    ok(f".env 已配置 (模型: {model})")
                    _warn_wrong_model_names()
                    return
            ok(".env 已配置")
            _warn_wrong_model_names()
        else:
            warn(".env 中未检测到有效 API Key，启动后可到 WebUI 系统设置中添加模型")
            print(f"    访问 http://localhost:{WEB_PORT} 后配置即可")
    else:
        if example_file.exists():
            shutil.copy(example_file, env_file)
            warn(".env 不存在，已从模板创建")
        warn("请编辑 .env 文件并填入 LLM API Key，或在启动后到 WebUI 中配置模型")
        print(f"    .env 文件：{env_file}")


# ★ 2026-08-05：启动时校验 LLM 模型名，发现常见错误（kimi2 / kimi-k2 /
# deepseek-vN 等）立刻提示正确名称，避免扫描中途才暴露 404。
# 与 core/llm.py 的 _normalize_model_name 保持同步，这里只做提示不自动改文件。
_WRONG_MODEL_FIXES = {
    # (base_url 子串小写, 错误模型名小写) → 正确模型名
    ("moonshot.cn", "kimi2"): "kimi-k3",
    ("moonshot.cn", "kimi"): "kimi-k3",
    ("moonshot.cn", "kimi-k2"): "kimi-k3",
    ("moonshot.cn", "kimi-k1.5"): "moonshot-v1-8k",
    ("moonshot.cn", "kimi-latest"): "kimi-k3",
    ("moonshot.cn", "kimi-k2-0905-preview"): "kimi-k3",
    ("moonshot.cn", "kimi-k2-0711-preview"): "kimi-k3",
    ("moonshot.cn", "kimi-k2-turbo-preview"): "kimi-k3",
    ("moonshot.cn", "kimi-k2-thinking"): "kimi-k3",
    ("moonshot.cn", "kimi-k2-thinking-turbo"): "kimi-k3",
    ("moonshot.cn", "kimi-thinking-preview"): "kimi-k3",
    ("deepseek.com", "deepseek-v4-pro"): "deepseek-chat",
    ("deepseek.com", "deepseek-v3"): "deepseek-chat",
    ("deepseek.com", "deepseek-v4"): "deepseek-chat",
    ("deepseek.com", "deepseek-v5-pro"): "deepseek-chat",
    ("deepseek.com", "deepseek-v5"): "deepseek-chat",
    ("deepseek.com", "deepseek-v6-pro"): "deepseek-chat",
    ("deepseek.com", "deepseek-v6"): "deepseek-chat",
    ("deepseek.com", "deepseek-reasoner-v4"): "deepseek-reasoner",
    ("deepseek.com", "deepseek-reasoner-v5"): "deepseek-reasoner",
    ("bigmodel.cn", "glm-4-pro"): "glm-4-plus",
    ("bigmodel.cn", "glm-4.6"): "glm-4-plus",
}
# 不依赖 base_url 的全局错误模型名（任意 provider 都算错）
_GLOBAL_WRONG_MODELS = {
    "kimi2": "kimi-k3",
    "kimi": "kimi-k3",
    "kimi-k2": "kimi-k3",
    "kimi-k1.5": "moonshot-v1-8k",
    "kimi-latest": "kimi-k3",
}


def _check_one_model(base_url: str, model: str) -> str | None:
    """返回正确模型名；若模型名无误返回 None。"""
    if not model:
        return None
    base_lower = (base_url or "").lower()
    model_lower = model.lower().strip()
    for (url_sub, wrong), right in _WRONG_MODEL_FIXES.items():
        if url_sub in base_lower and model_lower == wrong:
            return right
    if model_lower in _GLOBAL_WRONG_MODELS:
        return _GLOBAL_WRONG_MODELS[model_lower]
    # DeepSeek 通用兜底：deepseek-vN(-xxx)?
    if "deepseek.com" in base_lower:
        import re as _re
        if _re.match(r"^deepseek-v\d+(-.*)?$", model_lower):
            return "deepseek-chat"
    # Moonshot 已下线 kimi-k2-*-preview / kimi-k2-thinking* 等
    if "moonshot.cn" in base_lower:
        import re as _re
        if _re.match(r"^kimi-k2-(0905|0711|turbo)-preview$|^kimi-k2-thinking(-turbo)?$|^kimi-thinking-preview$", model_lower):
            return "kimi-k3"
    return None


def _warn_wrong_model_names():
    """扫描 .env 与 data/llm_configs.json，发现错误模型名立刻醒目提示。"""
    seen: list[tuple[str, str, str, str]] = []  # (来源, name, 错误模型, 正确模型)

    # 1) .env
    env_file = PROJECT_DIR / ".env"
    if env_file.exists():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            if not line.startswith("LLM_") or "_MODEL=" not in line:
                continue
            try:
                key, model = line.split("=", 1)
                model = model.strip().strip('"').strip("'")
            except ValueError:
                continue
            if not model:
                continue
            idx = key.split("_")[1]
            base_url = ""
            for bl in env_file.read_text(encoding="utf-8").splitlines():
                if bl.startswith(f"LLM_{idx}_BASE_URL="):
                    base_url = bl.split("=", 1)[1].strip()
                    break
            right = _check_one_model(base_url, model)
            if right:
                seen.append((f".env LLM_{idx}", model, model, right))

    # 2) data/llm_configs.json（优先级高于 .env，覆盖上面的结果）
    json_path = PROJECT_DIR / "data" / "llm_configs.json"
    if json_path.exists():
        try:
            import json as _json
            data = _json.loads(json_path.read_text(encoding="utf-8"))
            seen = []  # json 优先，清空 .env 结果
            for item in data.get("models", []):
                base_url = item.get("base_url", "")
                model = item.get("model", "")
                name = item.get("name", "?")
                right = _check_one_model(base_url, model)
                if right:
                    seen.append((f"WebUI {name}", name, model, right))
        except Exception:
            pass

    if not seen:
        return
    print()
    warn(f"⚠️ 检测到 {len(seen)} 个模型名可能有误（启动后会自动纠正，但建议在 WebUI 修正）：")
    for src, name, wrong, right in seen:
        print(f"    {YELLOW}{src}{NC} ({name}): {RED}{wrong}{NC} → 应为 {GREEN}{right}{NC}")


def check_browser():
    global errors
    print()
    title("[3/5] 检查浏览器...")
    # 检测系统已安装的浏览器
    system_browsers = []
    for exe, name in [
        ("C:/Program Files/Google/Chrome/Application/chrome.exe", "Chrome"),
        ("C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe", "Edge"),
    ]:
        if Path(exe).exists():
            system_browsers.append(name)
    if system_browsers:
        ok(f"系统浏览器已就绪（{' + '.join(system_browsers)}）")
        return

    # 检查打包内/安装目录的 Playwright Chromium
    for playwright_dir in [
        PROJECT_DIR / "ms-playwright",
        Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local"))) / "ms-playwright",
    ]:
        if playwright_dir.exists():
            chrome_exe = list(playwright_dir.glob("chromium-*/chrome-win64/chrome.exe"))
            if chrome_exe:
                ok(f"Playwright Chromium 已就绪（{chrome_exe[0].parent.parent.name}）")
                return

    warn("未检测到 Chrome/Edge/Chromium（不影响 Web UI 启动，仅浏览器自动抓包功能不可用）")
    warn(f"    安装 Chromium: {CYAN}{sys.executable} -m playwright install chromium{NC}")
    # ★ 尝试自动安装（非交互，失败不阻塞启动）
    try:
        import subprocess
        info("正在尝试自动安装 Playwright Chromium...")
        result = subprocess.run(
            [sys.executable, "-m", "playwright", "install", "chromium"],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode == 0:
            ok("Playwright Chromium 自动安装完成")
        else:
            warn(f"自动安装失败（退出码 {result.returncode}），请手动执行上述命令")
    except Exception as e:
        warn(f"自动安装失败: {e}，请手动执行上述命令")


def is_port_in_use(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(("127.0.0.1", port)) == 0


def _is_mitmproxy_port(port: int) -> bool:
    """检测端口上监听的是否是 mitmproxy 代理（通过发送 HTTP CONNECT 探测）。"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2.0)
            s.connect(("127.0.0.1", port))
            # mitmproxy 对普通 HTTP GET 会返回代理错误页（而非 connection refused）
            s.send(b"GET http://mitmproxy-check/ HTTP/1.1\r\nHost: mitmproxy-check\r\n\r\n")
            data = s.recv(256)
            return b"mitmproxy" in data or b"Proxy" in data or b"502" in data or b"503" in data
    except Exception:
        return False


def check_ports():
    global errors
    print()
    title("[4/5] 检查端口...")
    for port, name in [(WEB_PORT, "Web UI"), (PROXY_PORT, "mitmproxy")]:
        if is_port_in_use(port):
            # ★ 代理端口被占用时检测是否已有 mitmproxy 在运行，是则复用
            if port == PROXY_PORT and _is_mitmproxy_port(port):
                ok(f"端口 {port} ({name}) 已有 mitmproxy 运行中，将复用现有实例")
                continue
            fail(f"端口 {port} ({name}) 被占用")
            if IS_WINDOWS:
                print(f"    查看占用: {CYAN}netstat -ano | findstr :{port}{NC}")
                print(f"    释放端口: {CYAN}taskkill /PID <pid> /F{NC}")
            else:
                print(f"    查看占用: {CYAN}lsof -i :{port}{NC}")
                print(f"    释放端口: {CYAN}kill $(lsof -ti :{port}){NC}")
            errors += 1
        else:
            ok(f"端口 {port} ({name}) 可用")


def check_skills():
    print()
    title("[5/5] 检查知识库...")
    count = 0
    for d in ["skills_my"]:
        p = PROJECT_DIR / d
        if p.exists():
            count += len(list(p.rglob("SKILL.md")))
    ok(f"已加载 {count} 个方法论")
    return count


# ============================================================
# 启动服务
# ============================================================

mitm_process = None
_mitm_stderr_lines: list[str] = []  # 收集 stderr 输出供降级日志使用


def _drain_mitm_stderr(proc: subprocess.Popen):
    """后台线程持续读取 mitmproxy stderr，防止管道缓冲区满导致进程阻塞。

    同时把前 50 行存入 _mitm_stderr_lines 供启动失败时诊断，
    并**全量落盘**到 ``data/logs/mitm_stderr_<ts>.log`` 供下次扫描前复盘
    （D17：原仅内存，进程退出即丢）。
    """
    global _mitm_stderr_lines
    collected = []
    # D17: 落盘 stderr 到 data/logs/mitm_stderr_<ts>.log
    logs_dir = PROJECT_DIR / "data" / "logs"
    try:
        logs_dir.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    log_path = logs_dir / f"mitm_stderr_{int(time.time())}.log"
    log_file = None
    try:
        log_file = open(log_path, "w", encoding="utf-8", errors="replace")
    except Exception:
        pass
    try:
        for line in iter(proc.stderr.readline, b""):
            text = line.decode("utf-8", errors="replace").rstrip()
            if text:
                collected.append(text)
                if len(collected) <= 50:
                    _mitm_stderr_lines.append(text)
                if log_file:
                    try:
                        log_file.write(text + "\n")
                        log_file.flush()
                    except Exception:
                        pass
    except Exception:
        pass
    finally:
        if log_file:
            try:
                log_file.close()
            except Exception:
                pass


def cleanup(signum=None, frame=None):
    global mitm_process
    print(f"\n{CYAN}正在关闭服务...{NC}")
    if mitm_process and mitm_process.poll() is None:
        mitm_process.terminate()
        try:
            mitm_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            mitm_process.kill()
    print(f"{GREEN}已退出{NC}")
    sys.exit(0)


def _print_mitmproxy_diagnosis(exit_code: int | None, stderr_text: str):
    """根据退出码和 stderr 输出给出具体诊断提示。"""
    stderr_lower = stderr_text.lower() if stderr_text else ""

    if "address already in use" in stderr_lower or "errno 98" in stderr_lower:
        warn("  诊断: 端口被占用 — 请检查是否有残留的 mitmdump 进程")
        warn(f"    查找: {CYAN}{'tasklist | findstr mitmdump' if IS_WINDOWS else 'pgrep -af mitmdump'}{NC}")
    elif "no module named" in stderr_lower or "importerror" in stderr_lower:
        warn("  诊断: mitmproxy 依赖缺失 — 请重新安装")
        warn(f"    安装: {CYAN}{sys.executable} -m pip install --force-reinstall mitmproxy{NC}")
    elif "permission denied" in stderr_lower or "errno 13" in stderr_lower:
        warn("  诊断: 权限不足 — 请以管理员身份运行或更换端口")
        warn(f"    更换端口: {CYAN}set PROXY_PORT=18081{NC}")
    elif "cert" in stderr_lower or "ca" in stderr_lower:
        warn("  诊断: CA 证书问题 — 首次使用需安装 mitmproxy 证书")
        warn(f"    安装证书: {CYAN}mitmdump --certs{NC} 然后手动信任 ~/.mitmproxy/mitmproxy-ca-cert.pem")
    elif exit_code == 1 and not stderr_text:
        warn("  诊断: mitmproxy 静默退出（可能是 addon 脚本加载失败）")
        warn(f"    手动调试: {CYAN}mitmdump -s mcp_servers/mitm_addon.py -p {PROXY_PORT}{NC}")
    elif exit_code is not None and exit_code < 0:
        warn(f"  诊断: mitmproxy 被信号 {-exit_code} 终止 — 可能被系统或杀毒软件拦截")


def start_mitmproxy():
    global mitm_process
    print(f"{CYAN}启动 mitmproxy 代理 (端口 {PROXY_PORT})...{NC}")

    # 确保流量文件目录存在并清空
    FLOW_FILE.parent.mkdir(parents=True, exist_ok=True)
    FLOW_FILE.write_text("")

    env = os.environ.copy()
    env["PROXY_FLOW_FILE"] = str(FLOW_FILE)

    try:
        # ★ 智能查找 mitmdump 路径
        # macOS Python.framework 下：sys.executable 是 .app/Contents/MacOS/Python
        # 而 mitmdump 实际在 Versions/X.Y/bin/mitmdump，不在 sys.executable 同级目录
        mitmdump_path = None
        candidates = [
            Path(sys.executable).parent / "mitmdump",  # 普通 Python: bin/python + bin/mitmdump
            Path(sys.executable).parent / "Scripts" / "mitmdump.exe",  # Windows venv
            # macOS Python.framework: ../../../bin/mitmdump
            Path(sys.executable).parent.parent.parent.parent / "bin" / "mitmdump",
            # 通用 sysconfig
        ]
        try:
            import sysconfig
            scripts_dir = sysconfig.get_path("scripts")
            if scripts_dir:
                candidates.append(Path(scripts_dir) / "mitmdump")
                # Windows 上 sysconfig 返回的 scripts_dir 下是 mitmdump.exe
                if IS_WINDOWS:
                    candidates.append(Path(scripts_dir) / "mitmdump.exe")
        except Exception:
            pass

        # ★ conda 环境：conda 的 Scripts 目录
        conda_prefix = os.getenv("CONDA_PREFIX")
        if conda_prefix:
            candidates.append(Path(conda_prefix) / "Scripts" / "mitmdump.exe" if IS_WINDOWS else Path(conda_prefix) / "bin" / "mitmdump")

        # ★ 用户级 pip 安装：~/.local/bin
        candidates.append(Path.home() / ".local" / "bin" / "mitmdump")

        for cand in candidates:
            if cand and cand.exists():
                mitmdump_path = cand
                break

        addon_path = PROJECT_DIR / "mcp_servers" / "mitm_addon.py"

        if mitmdump_path:
            mitm_cmd = [
                str(mitmdump_path),
                "-s", str(addon_path),
                "-p", str(PROXY_PORT),
                "--listen-host", "127.0.0.1",  # ★ XJ-02: 仅绑定本地，不暴露 0.0.0.0
                "--set", "stream_large_bodies=10m",
                "--set", "connection_strategy=lazy",
                "--quiet",
            ]
        elif shutil.which("mitmdump"):
            mitm_cmd = [
                "mitmdump",
                "-s", str(addon_path),
                "-p", str(PROXY_PORT),
                "--listen-host", "127.0.0.1",  # ★ XJ-02: 仅绑定本地
                "--set", "stream_large_bodies=10m",
                "--set", "connection_strategy=lazy",
                "--quiet",
            ]
        else:
            # 最后兜底：用 python 调用 mitmdump 入口函数
            # 先验证 mitmproxy 包是否已安装
            try:
                importlib.import_module("mitmproxy")
            except ImportError:
                warn("mitmproxy 未安装，将以直连模式运行（无流量抓包）")
                warn(f"  安装命令: {CYAN}{sys.executable} -m pip install mitmproxy{NC}")
                return
            mitm_cmd = [
                sys.executable, "-c",
                "from mitmproxy.tools.main import mitmdump; mitmdump()",
                "-s", str(addon_path),
                "-p", str(PROXY_PORT),
                "--listen-host", "127.0.0.1",  # ★ XJ-02: 仅绑定本地
                "--set", "stream_large_bodies=10m",
                "--set", "connection_strategy=lazy",
                "--quiet",
            ]

        # ★ 检查 addon 脚本是否存在
        if not addon_path.exists():
            warn(f"mitmproxy addon 脚本不存在: {addon_path}")
            warn("流量记录功能将不可用，但代理本身仍可运行")

        # ★ stderr 暂存到 PIPE + 后台线程持续读取（防管道缓冲区满导致进程阻塞）
        kwargs = {"env": env, "stderr": subprocess.PIPE, "stdout": subprocess.DEVNULL}
        if IS_WINDOWS:
            kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP

        mitm_process = subprocess.Popen(mitm_cmd, **kwargs)

        # ★ 启动 stderr 消费线程，防止管道满阻塞 mitmproxy 进程
        _drain_thread = threading.Thread(
            target=_drain_mitm_stderr, args=(mitm_process,), daemon=True
        )
        _drain_thread.start()

        # ★ 健康检查轮询：最多等 30 秒（30 次，每次 sleep 1s）
        # 仅检测端口监听 + 进程存活，不依赖外部网络（如 httpbin.org），避免因外网波动误判；
        # 代理实际转发能力将在浏览器/爬虫使用时验证，
        # 若代理不可用，由 core/crawler/crawler_core.py 的降级逻辑处理（自动切换直连模式）。
        proxy_ok = False
        for attempt in range(30):
            # 进程已退出
            if mitm_process.poll() is not None:
                break
            time.sleep(1)
            # 检测端口是否开始监听（TCP 连接成功即代表 mitmproxy 已就绪接受请求）
            if is_port_in_use(PROXY_PORT):
                proxy_ok = True
                break

        if proxy_ok:
            ok(f"mitmproxy 已启动并验证可用 (PID: {mitm_process.pid}, 端口: {PROXY_PORT})")
        elif mitm_process.poll() is None:
            warn(f"mitmproxy 进程在运行 (PID: {mitm_process.pid})，但代理端口 {PROXY_PORT} 未就绪")
            warn("浏览器可能无法走代理，流量抓包功能可能不可用")
            warn("后续将由 core/crawler/crawler_core.py 的降级逻辑处理（自动切换直连模式）")
            # ★ 输出 stderr 前 5 行帮助诊断
            if _mitm_stderr_lines:
                warn(f"mitmproxy stderr (前 5 行):")
                for line in _mitm_stderr_lines[:5]:
                    print(f"    {line}")
        else:
            # 读取 stderr 看失败原因
            stderr_out = "\n".join(_mitm_stderr_lines[:10]) if _mitm_stderr_lines else ""
            warn(f"mitmproxy 启动失败（退出码 {mitm_process.returncode}），将以直连模式运行（无流量抓包）")
            if stderr_out:
                warn(f"mitmproxy 错误日志:")
                for line in stderr_out.split("\n"):
                    print(f"    {line}")
            # ★ 诊断提示
            _print_mitmproxy_diagnosis(mitm_process.returncode, stderr_out)
    except FileNotFoundError as e:
        warn(f"mitmproxy 启动失败: mitmdump 可执行文件未找到 — {e}")
        warn("将以直连模式运行（无流量抓包）")
        warn(f"  安装命令: {CYAN}{sys.executable} -m pip install mitmproxy{NC}")
    except PermissionError as e:
        warn(f"mitmproxy 启动失败: 权限不足 — {e}")
        if IS_WINDOWS:
            warn("  请尝试以管理员身份运行，或更换端口号 (set PROXY_PORT=18081)")
        warn("将以直连模式运行（无流量抓包）")
    except Exception as e:
        warn(f"mitmproxy 启动失败: {type(e).__name__}: {e}")
        warn("将以直连模式运行（无流量抓包）")


def start_mitmproxy_production():
    """生产模式：在后台线程中直接运行 mitmdump，避免 subprocess 调用 PyInstaller exe 的问题。"""
    print(f"{CYAN}启动 mitmproxy 代理 (端口 {PROXY_PORT})...{NC}")

    FLOW_FILE.parent.mkdir(parents=True, exist_ok=True)
    FLOW_FILE.write_text("")

    os.environ["PROXY_FLOW_FILE"] = str(FLOW_FILE)

    # 解析 mitm_addon.py 路径：优先 exe 同级目录（用户可覆盖），否则回退到打包内资源
    bundle_dir = Path(getattr(sys, '_MEIPASS', PROJECT_DIR))
    addon_path = PROJECT_DIR / "mcp_servers" / "mitm_addon.py"
    if not addon_path.exists():
        addon_path = bundle_dir / "mcp_servers" / "mitm_addon.py"

    _mitm_exc: list[str] = []

    def _run_mitm():
        try:
            from mitmproxy.tools.main import mitmdump
            mitmdump([
                "-s", str(addon_path),
                "-p", str(PROXY_PORT),
                "--set", "stream_large_bodies=10m",
                "--set", "connection_strategy=lazy",
                "--quiet",
            ])
        except ImportError as exc:
            _mitm_exc.append(f"mitmproxy 包未安装: {exc}")
            print(f"  {YELLOW}[!]{NC} mitmproxy 包未安装: {exc}")
        except Exception as exc:
            _mitm_exc.append(f"mitmproxy 运行异常: {exc}")
            print(f"  {YELLOW}[!]{NC} mitmproxy 运行异常: {exc}")

    t = threading.Thread(target=_run_mitm, daemon=True)
    t.start()

    # ★ 健康检查轮询替代固定 sleep，最多等 20 秒（原 15 秒在慢速机器上不够）
    proxy_ready = False
    for _ in range(20):
        time.sleep(1)
        if is_port_in_use(PROXY_PORT):
            proxy_ready = True
            break

    if proxy_ready:
        ok(f"mitmproxy 已启动 (端口: {PROXY_PORT})")
    else:
        warn("mitmproxy 可能未正常启动（20秒内端口未就绪），将以直连模式运行")
        if _mitm_exc:
            warn(f"mitmproxy 异常原因: {_mitm_exc[0]}")
        warn("流量记录将依赖 Playwright 降级写入（flows.jsonl 可能不完整）")


def start_web():
    global mitm_process
    skill_count = check_skills()

    print()
    print(f"{CYAN}启动 Web UI (端口 {WEB_PORT})...{NC}")
    print()
    print(f"{BOLD}============================================{NC}")
    print(f"{BOLD}{GREEN}  XuanJian 已就绪！{NC}")
    print(f"{BOLD}============================================{NC}")
    print()
    print(f"  {BOLD}打开浏览器访问:{NC}  {CYAN}http://localhost:{WEB_PORT}{NC}")
    print()
    print(f"  Web UI:    http://localhost:{WEB_PORT}")
    print(f"  代理端口:   127.0.0.1:{PROXY_PORT}")
    print(f"  方法论:     {skill_count} 个")
    print(f"  流量文件:   {FLOW_FILE}")
    print()
    print(f"  按 {BOLD}Ctrl+C{NC} 停止所有服务")
    print()

    # 注册退出清理
    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    # 设置环境变量让 proxy_mcp 能找到流量文件
    os.environ["PROXY_FLOW_FILE"] = str(FLOW_FILE)

    try:
        import uvicorn
        # ★ 添加 timeout_keep_alive 和 limit_concurrency，防止僵尸 SSE 连接
        # 占满 worker 导致服务无响应（之前 13 个连接卡死整个服务）
        uvicorn.run(
            "web.server:app",
            host=WEB_HOST,
            port=WEB_PORT,
            log_level="info",
            timeout_keep_alive=30,       # keep-alive 30 秒超时，避免僵尸连接
            limit_concurrency=20,        # 最多 20 个并发连接
            timeout_graceful_shutdown=5, # 优雅关闭超时 5 秒
        )
    except KeyboardInterrupt:
        cleanup()


# ============================================================
# 生产模式资源初始化
# ============================================================

def init_production_resources():
    """首次运行时将打包内的只读资源复制到持久化目录。"""
    bundle_dir = Path(getattr(sys, '_MEIPASS', PROJECT_DIR))
    # skills_my
    if not (PROJECT_DIR / "skills_my").exists() and (bundle_dir / "skills_my").exists():
        shutil.copytree(bundle_dir / "skills_my", PROJECT_DIR / "skills_my")
        ok("已释放 skills_my 到安装目录")
    # .env
    env_file = PROJECT_DIR / ".env"
    example_file = bundle_dir / ".env.example"
    if not env_file.exists() and example_file.exists():
        shutil.copy(example_file, env_file)
        warn(".env 不存在，已从模板创建，请到 WebUI 配置模型")
    # data 子目录
    for sub in ["logs", "notes", "reports", "tasks"]:
        (PROJECT_DIR / "data" / sub).mkdir(parents=True, exist_ok=True)


# ============================================================
# 主流程
# ============================================================

def main():
    global errors, PROJECT_DIR, FLOW_FILE

    parser = argparse.ArgumentParser(description="XuanJian 启动器")
    parser.add_argument("--production", action="store_true", help="生产模式（打包后运行，跳过环境检查）")
    args = parser.parse_args()

    IS_PRODUCTION = args.production or _IS_BUNDLED

    if IS_PRODUCTION:
        # 强制使用 exe 所在目录作为项目根（支持 --production 开发测试）
        PROJECT_DIR = resolve_project_dir(force_production=True)
        os.chdir(PROJECT_DIR)
        FLOW_FILE = Path(os.getenv("PROXY_FLOW_FILE", str(PROJECT_DIR / "data" / "pentest_agent_flows.jsonl")))
        load_dotenv(PROJECT_DIR / ".env")
        # 设置 Playwright 浏览器路径优先指向安装目录
        pw_dir = PROJECT_DIR / "ms-playwright"
        if pw_dir.exists():
            os.environ["PLAYWRIGHT_BROWSERS_PATH"] = str(pw_dir)

    print()
    print(f"{BOLD}{CYAN}============================================{NC}")
    print(f"{BOLD}{CYAN}  XuanJian — 环境检查与启动{NC}")
    platform_info = f"{'Windows' if IS_WINDOWS else 'macOS' if sys.platform == 'darwin' else 'Linux'}"
    mode_str = "生产模式" if IS_PRODUCTION else "开发模式"
    print(f"{BOLD}{CYAN}  平台: {platform_info} | {mode_str} | Python {sys.version_info.major}.{sys.version_info.minor}{NC}")
    print(f"{BOLD}{CYAN}============================================{NC}")
    print()

    if IS_PRODUCTION:
        init_production_resources()
        check_env()
        check_ports()
    else:
        check_python_version()
        check_dependencies()
        check_env()
        check_browser()
        check_ports()

    print()
    if errors > 0:
        print(f"{RED}{BOLD}有 {errors} 个问题需要解决，请先修复后重新启动。{NC}")
        sys.exit(1)

    print(f"{GREEN}{BOLD}环境检查通过！{NC}")
    print()

    if IS_PRODUCTION:
        start_mitmproxy_production()
    else:
        start_mitmproxy()
    start_web()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        import traceback
        print(f"[FATAL] {e}", flush=True)
        traceback.print_exc()
        sys.exit(1)
