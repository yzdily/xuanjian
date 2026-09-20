# ============================================================
# XuanJian Makefile
# 跨平台等价命令: Windows (Git Bash/WSL) / macOS / Linux
# 每个 target 内部都用 python 调度，不依赖 GNU vs BSD make 的差异
#
# 用法:
#   make help           # 显示所有命令
#   make install        # 安装 Python 依赖
#   make browser        # 安装 Playwright Chromium
#   make run            # 启动开发模式 (python start.py)
#   make prod           # 启动生产模式 (python start.py --production)
#   make doctor         # 跑环境自检 (python -m cli.main doctor)
#   make scan URL=https://example.com  # 跑一次扫描
#   make test           # 跑单元测试
#   make docker-up      # 拉起 Docker 容器
#   make docker-down    # 停止 Docker 容器
#   make clean          # 清理 __pycache__ / .pytest_cache
# ============================================================

PY        ?= python
PIP       := $(PY) -m pip
PLAYWRIGHT := $(PY) -m playwright
URL       ?=

.PHONY: help install browser run prod doctor scan report test \
        docker-build docker-up docker-down docker-logs docker-shell \
        clean env doctor-cli

help: ## 显示帮助
	@echo "XuanJian — 跨平台命令清单"
	@echo ""
	@echo "  make install         安装 Python 依赖 (pip install -r requirements.txt)"
	@echo "  make browser         安装 Playwright Chromium 浏览器内核"
	@echo "  make env             从 .env.example 复制出 .env"
	@echo "  make run             开发模式启动 (默认: ./start.sh 等价)"
	@echo "  make prod            生产模式启动 (python start.py --production)"
	@echo "  make doctor          环境自检 (cli.main doctor)"
	@echo "  make scan URL=<u>    启动一次扫描 (cli.main run --url <u>)"
	@echo "  make report          渲染报告"
	@echo "  make test            跑 pytest 单元测试"
	@echo "  make docker-up       docker compose up -d"
	@echo "  make docker-down     docker compose down"
	@echo "  make clean           清理缓存 (__pycache__ / .pytest_cache / .coverage)"
	@echo ""
	@echo "环境变量覆盖: PY=python3.11 URL=https://target make scan"

# ---------- 安装 / 准备 ----------

install: ## 安装 Python 依赖
	$(PIP) install -r requirements.txt

browser: ## 安装 Playwright Chromium
	$(PLAYWRIGHT) install chromium

env: ## 从模板创建 .env (若不存在)
	@if [ ! -f .env ]; then cp .env.example .env && echo "[OK] 已生成 .env，请编辑后填入 API Key"; \
	else echo "[!] .env 已存在，未覆盖"; fi

# ---------- 运行 ----------

run: ## 启动开发模式
	$(PY) start.py

prod: ## 启动生产模式
	$(PY) start.py --production

doctor: ## 环境/依赖/权限自检
	$(PY) -m cli.main doctor

scan: ## 启动一次扫描: make scan URL=https://target
ifndef URL
	$(error 请指定 URL，例如: make scan URL=https://example.com)
endif
	$(PY) -m cli.main run --url "$(URL)"

report: ## 渲染报告
	$(PY) -m cli.main report

doctor-cli: doctor

# ---------- 测试 ----------

test: ## 跑单元测试
	$(PY) -m pytest -o addopts="" -p no:cacheprovider

# ---------- Docker ----------

docker-build: ## 本地构建镜像
	docker compose build

docker-up: ## 拉起容器 (后台)
	docker compose up -d

docker-down: ## 停止容器
	docker compose down

docker-logs: ## 查看容器日志
	docker compose logs -f

docker-shell: ## 进入容器 shell
	docker compose exec xuanjian /bin/bash

# ---------- 清理 ----------

clean: ## 清理 __pycache__ / .pytest_cache / .coverage
	@find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	@find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	@rm -f .coverage coverage.xml
	@echo "[OK] 清理完成"
