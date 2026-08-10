FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN python3 -m pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8899
CMD ["python3", "server.py", "--host", "0.0.0.0", "--port", "8899"]