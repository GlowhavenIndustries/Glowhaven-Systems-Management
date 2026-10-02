FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && useradd --create-home --uid 10001 atlas
COPY atlas ./atlas
COPY agent ./agent
RUN chown -R atlas:atlas /app
USER atlas
EXPOSE 8800
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8800/healthz', timeout=3)"
CMD ["uvicorn","atlas.main:app","--host","0.0.0.0","--port","8800"]
