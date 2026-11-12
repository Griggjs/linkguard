@echo off
rem 1-start-server.bat —— 双击启动「链接体检」网页，手机连同一个 WiFi 就能用
chcp 65001 >nul
title 护链 - 链接体检
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0run.ps1" serve --port 8088
echo.
echo 服务已停止。按任意键关闭窗口。
pause >nul
