# ============================================================
# XuanJian Dockerfile — 多阶段构建
# 推荐用法: docker build -t xuanjian .
# ============================================================

# ---------- 阶段 1: 基础镜像 + 依赖 ----------
FROM python:3.11-slim-bookworm AS base

# 避免 Python 写 .pyc、强制 unbuffered 日志
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    DEBIAN_FRONTEND=noninteractive \
    TZ=Asia/Shanghai

# 安装系统依赖（playwright/mitmproxy 运行所需的共享库 + 中文字体）
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates \
        # playwright chromium 运行依赖
        libnss3 libnspr4 libdbus-1-3 libatk1.0-0 libatk-bridge2.0-0 \
        libcups2 libdrm2 libxkbcommon0 libxcomposite1 libxdamage1 \
        libxfixes3 libxrandr2 libgbm1 libpango-1.0-0 libcairo2 libasound2 \
        libatspi2.0-0 libxshmfence1 \
        # 中文字体（避免 OCR/截图乱码）
        fonts-noto-cjk fonts-noto-cjk-extra \
        # 杂项
        fonts-liberation libgtk-3-0 tini \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 先装依赖（利用 Docker 层缓存）
COPY requirements.txt .
RUN pip install -r requirements.txt \
    && python -m playwright install chromium --with-deps

# ---------- 阶段 2: 应用代码 ----------
FROM base AS app

WORKDIR /app

# 拷贝源码
COPY core/ ./core/
COPY web/ ./web/
COPY mcp_servers/ ./mcp_servers/
COPY scripts/ ./scripts/
COPY skills_my/ ./skills_my/
COPY rules/ ./rules/
COPY templates/ ./templates/
COPY burp-plugin/ ./burp-plugin/
COPY start.py pyproject.toml .env.example README.md DISCLAIMER.md LICENSE ./

# 持久化数据目录（扫描结果/报告/日志/流量）
RUN mkdir -p /app/data/logs /app/data/notes /app/data/reports /app/data/tasks \
    && cp .env.example .env 2>/dev/null || true

# Web UI 7788, mitmproxy 18080, mitmproxy web 18081
EXPOSE 7788 18080 18081

# 容器内以非 root 运行（playwright chromium 需要 --no-sandbox，已在启动参数处理）
RUN useradd -m -u 1000 xuanjian && chown -R xuanjian:xuanjian /app
USER xuanjian

# 健康检查：Web UI 是否响应
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
    CMD curl -fsS http://localhost:7788/ || exit 1

# 容器内浏览器必须无头 + no-sandbox
ENV BROWSER_HEADLESS=true \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python", "start.py"]
