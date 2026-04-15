#!/bin/bash
# Скрипт для удобного запуска сервера Secure Proxy
# Дайте права на выполнение: chmod +x start_server.sh

echo "======================================="
echo "📦 Сборка сервера Secure Proxy..."
echo "======================================="

# Проверяем установлен ли Go
if ! command -v go &> /dev/null
then
    echo "❌ Ошибка: Go не установлен. Пожалуйста, установите Go для компиляции."
    echo "Инструкция: https://go.dev/doc/install"
    exit 1
fi

go build -o server server.go
if [ $? -ne 0 ]; then
    echo "❌ Ошибка компиляции server.go."
    exit 1
fi

echo "✅ Сборка успешна!"
echo ""
echo "🚀 Запускаем сервер..."
echo ""
# Вы можете менять порты здесь, если они заняты
./server -port 8080 -canary1 8079 -canary2 8081
