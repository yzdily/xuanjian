#!/usr/bin/env bash
# ============================================================
# start.sh — XuanJian 一键启动 (macOS / Linux)
# 与 Windows 的 launch.bat / start.ps1 行为一致：
#   1) 解析项目根目录 (本脚本所在目录的父级)
#   2) 选择 Python 解释器 (venv > python3 > python)
#   3) 转发所有参数到 python start.py
# 用法:
#   ./start.sh                    # 等价 python start.py
#   ./start.sh --production       # 生产模式
#   PROXY_PORT=18081 ./start.sh   # 自定义环境变量
# ============================================================

set -e

# 切到项目根 (start.sh 位于仓库根)
cd "$(dirname "$0")"

# 选 Python：优先 venv，再 python3，最后 python
PY=""
if [ -x "./.venv/bin/python" ]; then
    PY="./.venv/bin/python"
elif [ -x "./venv/bin/python" ]; then
    PY="./venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
    PY="python3"
elif command -v python >/dev/null 2>&1; then
    PY="python"
else
    echo "[x] 未找到 Python (>=3.10)。请先安装 Python 3.10+"
    echo "    macOS:  brew install python@3.11"
    echo "    Linux:  发行版包管理器安装 python3 (例: sudo apt install python3 python3-venv python3-pip)"
    exit 1
fi

# 强制 UTF-8 (与 Windows 行为一致)
export PYTHONIOENCODING="${PYTHONIOENCODING:-utf-8}"
export PYTHONDONTWRITEBYTECODE=1
export PYTHONUNBUFFERED=1

echo "[$(date '+%F %T')] start.sh  平台=$(uname -s)  Python=$(${PY} --version 2>&1)"

exec "$PY" start.py "$@"
