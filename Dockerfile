# WVS — Web Vulnerability Scanner (web console)
FROM python:3.12-slim

# Don't write .pyc, unbuffered stdout for clean container logs.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    WVS_HOST=0.0.0.0 \
    WVS_PORT=5000

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

# Bind to 0.0.0.0 inside the container (overridden by WVS_HOST above).
CMD ["python", "-m", "web.app"]
