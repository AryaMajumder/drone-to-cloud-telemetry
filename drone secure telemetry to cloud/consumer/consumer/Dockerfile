FROM python:3.10-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY consumer.py /app/consumer.py
ENV PYTHONUNBUFFERED=1
CMD ["python", "/app/consumer.py"]
