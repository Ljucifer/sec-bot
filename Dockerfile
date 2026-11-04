# Минимальный образ с Python 3.11.
FROM python:3.11-slim

# Не буферизуем stdout/stderr — логи видны в `docker compose logs` сразу.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Сначала зависимости: слой кэшируется, пока не менялся requirements.txt.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Затем код приложения.
COPY app.py .

# Не работаем от root — хорошая практика для сетевых сервисов.
RUN useradd --create-home --uid 10001 bot \
    && chown -R bot:bot /app
USER bot

# Метка живости обновляется в конце каждого цикла; 8 ч — с запасом на 6-часовой
# сон плюс длинный цикл. Healthcheck не перезапускает контейнер, только статус.
HEALTHCHECK --interval=5m --timeout=10s --start-period=10m --retries=3 \
    CMD ["python", "-c", "import os,sys,time; p='/tmp/heartbeat'; sys.exit(0 if os.path.exists(p) and time.time()-os.path.getmtime(p) < 8*3600 else 1)"]

CMD ["python", "-u", "app.py"]
