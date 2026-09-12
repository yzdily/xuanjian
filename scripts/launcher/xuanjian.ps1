# scripts/launcher/xuanjian.ps1 — Windows PowerShell 启动器（短期 S3）
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..\..")
python -m cli.main @args
