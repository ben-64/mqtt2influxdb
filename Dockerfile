FROM python:3.7-alpine

LABEL maintainer="ben64" description="MQTT/InfluxDB Bridge"

COPY requirements.txt /
RUN pip install -r /requirements.txt

COPY . /app
WORKDIR /app

CMD ["python3", "-u", "mqtt2influxdb.py","-c","config.txt"]
