#!/usr/bin/env bash
# ==============================================================================
# TLS Fingerprint Lab — اسکریپت اجرای یکپارچه
# سازگار با macOS و Linux (Ubuntu / Debian / Fedora)
# ==============================================================================

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT"

echo "=========================================================="
echo "  🔬 TLS Fingerprint Lab — آزمایشگاه تعاملی JA3 و JA4"
echo "=========================================================="

# ۱. بررسی پیش‌نیازها
if ! command -v node >/dev/null 2>&1; then
    echo "❌ خطا: Node.js روی سیستم یافت نشد. لطفاً Node.js را نصب کنید."
    exit 1
fi

if ! command -v npm >/dev/null 2>&1; then
    echo "❌ خطا: npm روی سیستم یافت نشد."
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "❌ خطا: Python 3 روی سیستم یافت نشد."
    exit 1
fi

# ۲. راه‌اندازی بک‌اند پایتون
echo "⚙️ در حال بررسی محیط بک‌اند..."
if [ ! -d "backend/venv" ]; then
    echo "📦 ساخت محیط مجازی Python venv..."
    python3 -m venv backend/venv
    backend/venv/bin/pip install --upgrade pip
    backend/venv/bin/pip install -r backend/requirements.txt
fi

# ۳. راه‌اندازی فرانت‌اند
echo "⚙️ در حال بررسی وابستگی‌های فرانت‌اند..."
if [ ! -d "frontend/node_modules" ]; then
    echo "📦 نصب بسته‌های فرانت‌اند..."
    (cd frontend && npm install)
fi

# تمیزکاری هنگام خروج (Ctrl+C)
cleanup() {
    echo ""
    echo "🛑 در حال توقف سرویس‌ها..."
    kill $(jobs -p) 2>/dev/null || true
    echo "👋 آزمایشگاه با موفقیت متوقف شد."
    exit 0
}
trap cleanup SIGINT SIGTERM EXIT

# ۴. اجرای بک‌اند و فرانت‌اند در پس‌زمینه
echo "🚀 در حال راه‌اندازی بک‌اند FastAPI روی پورت 3085..."
backend/venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 3085 --app-dir backend &
BACKEND_PID=$!

sleep 1

echo "🚀 در حال راه‌اندازی فرانت‌اند Vite روی پورت 3084..."
(cd frontend && npm run dev -- --host 127.0.0.1 --port 3084) &
FRONTEND_PID=$!

sleep 1

echo ""
echo "=========================================================="
echo "✅ آزمایشگاه با موفقیت اجرا شد:"
echo "🌐 آدرس فرانت‌اند (رابط کاربری): http://127.0.0.1:3084"
echo "🔌 آدرس بک‌اند (مستندات Swagger):  http://127.0.0.1:3085/docs"
echo "=========================================================="
echo "💡 نکته برای ارائه در کلاس:"
echo "   - کلیدهای جهت‌نما (راست و چپ) در حالت Presentation Mode کار می‌کنند."
echo "   - برای پایان اجرا، کلیدهای Ctrl + C را فشار دهید."
echo "=========================================================="

wait
