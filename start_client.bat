@echo off
title Secure Proxy Client
color 0B
chcp 65001 >nul

echo Сборка клиента...
go build -o client.exe client.go
if %errorlevel% neq 0 (
    echo.
    echo Ошибка: Не удалось скомпилировать client.go
    pause
    exit /b %errorlevel%
)

echo Запуск клиента...
echo.
client.exe

pause
