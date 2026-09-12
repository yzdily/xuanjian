#!/usr/bin/env bash
# ============================================================
# start.command — macOS Finder 双击启动 XuanJian
# 行为完全等价于 ./start.sh，但被 Finder 识别为可执行 GUI 启动器
# 放置在仓库根，用户双击即可在 Terminal 中启动
# ============================================================

# 切到脚本所在目录
cd "$(dirname "$0")"

# 用 Terminal.app 打开自身，保证窗口常驻、关闭时一并退出
if [ -n "${TERM_PROGRAM}" ] || [ "${TERM_PROGRAM}" = "Apple_Terminal" ]; then
    # 已在终端中：直接 exec start.sh
    exec ./start.sh "$@"
else
    # 双击启动：通过 osascript 拉起 Terminal 并执行本脚本
    osascript <<EOF
tell application "Terminal"
    activate
    do script "cd '$(pwd)' && exec ./start.sh $*"
end tell
EOF
fi
