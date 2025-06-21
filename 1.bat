@echo off
chcp 65001 > nul
title 同时运行HTTP服务器和App

:: 启动Python HTTP服务器（8080端口）
start "HTTP Server" cmd /k python -m http.server 8080

:: 启动Python应用
start "Python App" cmd /k python app.py

echo 已启动HTTP服务器(8080)和App应用
pause