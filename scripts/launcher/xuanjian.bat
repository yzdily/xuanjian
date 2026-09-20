@echo off
REM scripts/launcher/xuanjian.bat — Windows cmd 备选启动器（短期 S3）
cd /d "%~dp0\..\.."
python -m cli.main %*
