FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN python3 -m pip install --no-cache-dir -r requirements.txt
COPY . .
RUN mkdir -p /app/data
EXPOSE 8899
VOLUME ["/app/data"]
CMD ["python3", "server.py", "--host", "0.0.0.0", "--port", "8899", "--ttl", "1800", "--usage-log", "/app/data/usage.jsonl"]