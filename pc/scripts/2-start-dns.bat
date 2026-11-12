@echo off
rem 2-start-dns.bat —— 双击启动 DNS 过滤，把手机/路由器的 DNS 指向本机就能全局拦截
rem
rem 如果提示端口被占用，先关掉 Windows 的「Internet 连接共享」，
rem 或者换一个端口：把下面 --port 53 改成 --port 5353，
rem 然后在路由器里把 DNS 设成 本机IP:5353（部分路由器支持自定义端口）。
chcp 65001 >nul
title 护链 - DNS 过滤
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0run.ps1" dns --port 53 --log-all
echo.
echo 服务已停止。按任意键关闭窗口。
pause >nul
