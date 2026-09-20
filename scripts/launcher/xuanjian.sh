#!/usr/bin/env bash
# scripts/launcher/xuanjian.sh — Linux/macOS 启动器（短期 S3）
# pip install -e . 后可改用 `xuanjian` 命令；本脚本给直接用本仓库的开发者。
set -e
cd "$(dirname "$0")/../.."
exec python -m cli.main "$@"
