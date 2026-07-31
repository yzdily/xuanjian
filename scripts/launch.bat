@echo off
chcp 65001 >nul
title XuanJian 开发模式
cd /d "%~dp0.."
echo ============================================
echo   玄鉴 XuanJian - 开发模式启动
echo ============================================
echo.
python start.py %*
if errorlevel 1 (
    echo.
    echo [x] 启动失败，按任意键退出...
    pause >nul
)
