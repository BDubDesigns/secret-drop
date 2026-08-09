FROM python:3.12-slim
WORKDIR /app
COPY . .
EXPOSE 8899
CMD ["python3", "server.py", "--host", "0.0.0.0", "--port", "8899"]