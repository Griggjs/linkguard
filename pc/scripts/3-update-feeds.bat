@echo off
rem 3-update-feeds.bat —— 双击更新恶意域名名单（需要联网）
chcp 65001 >nul
title 护链 - 更新名单
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0run.ps1" feeds --update
echo.
pause >nul
