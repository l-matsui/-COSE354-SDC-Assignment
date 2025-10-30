FROM python:3.8-slim

WORKDIR /app

RUN apt-get update && apt-get install -y iputils-ping

COPY . /app

RUN pip install --no-cache-dir Flask requests

EXPOSE 5000

CMD ["python", "app.py"]
