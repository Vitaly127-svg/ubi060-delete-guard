FROM python:3.12-slim
WORKDIR /opt/ubi060
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && useradd --uid 10001 --create-home app
COPY app ./app
COPY scripts ./scripts
USER 10001
EXPOSE 8000 8001 8002 8003 8004
CMD ["sh", "-c", "exec uvicorn app.api:create_app --factory --host 0.0.0.0 --port ${PORT:-8002}"]
