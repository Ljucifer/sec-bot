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

CMD ["python", "-u", "app.py"]
