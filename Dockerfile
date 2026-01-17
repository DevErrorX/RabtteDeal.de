# نستخدم نسخة Node كقاعدة
FROM node:18-slim

# تثبيت بايثون والأدوات اللازمة لنظام Linux
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# نسخ ملفات التعريف وتثبيت مكتبات Node
COPY package*.json ./
RUN npm install

# نسخ ملف المكتبات وتثبيت مكتبات بايثون
COPY requirements.txt ./
RUN pip3 install --no-cache-dir -r requirements.txt --break-system-packages

# نسخ باقي ملفات المشروع
COPY . .

# تشغيل البوت
CMD ["node", "bot.js"]
