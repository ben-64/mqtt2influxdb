# MQTT/InfluxDB Bridge

Python script use to send MQTT payloads to influxdb

## Build

```sh
$ docker build -t mqtt2influxdb .
```


## Run

```sh
$ docker run -d --name mqtt2influxdb mqtt2influxdb
```


## Dev

```sh
$ docker run -it --rm --name python mqtt2influxdb sh
```
