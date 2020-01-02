#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import re
import configparser
import requests
import time
import json
import traceback

from influxdb import InfluxDBClient
import paho.mqtt.client as mqtt


def parse_args():
    import argparse

    conf_parser = argparse.ArgumentParser(description=__doc__,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            add_help=False)
    conf_parser.add_argument("--config","-c",metavar="CONFIGURATION",help="Configuration file")
    args, remaining_argv = conf_parser.parse_known_args()

    defaults = {}
    if args.config:
        config = configparser.ConfigParser()
        config.read(args.config)
        defaults = dict(config.items("GENERAL"))
        defaults["config"] = args.config

    parser = argparse.ArgumentParser(description="MQTT to influxdb bridge")
    parser.add_argument("--config","-c",metavar="CONFIGURATION",help="Configuration file")
    parser.add_argument("--influxdb","-i",metavar="URL",default="localhost",help="Influxdb Server")
    parser.add_argument("--influxdb-port","-p",metavar="PORT",default=8086,type=int,help="Influxdb port")
    parser.add_argument("--influxdb-user","-u",metavar="USER",default="mqtt",help="Influxdb user")
    parser.add_argument("--influxdb-password","-k",metavar="PASSWORD",default="mqtt_password",help="Influxdb password")
    parser.add_argument("--mqtt","-m",metavar="URL",default="localhost",help="MQTT Server")
    parser.add_argument("--mqtt-port","-P",metavar="PORT",default=1883,type=int,help="MQTT port")
    parser.add_argument("--mqtt-user","-U",metavar="USER",default="mqtt",help="MQTT user")
    parser.add_argument("--mqtt-password","-K",metavar="PASSWORD",default="mqtt_password",help="MQTT password")
    parser.add_argument("--mqtt-client-id","-C",metavar="ID",default="domoticz_temperature",help="MQTT client id")

    parser.set_defaults(**defaults)

    return parser.parse_args(remaining_argv)


def load_config(path):
    res = {}
    config = configparser.ConfigParser()
    config.optionxform=str
    config.read_file(open(path))
    for section in config.sections():
        if section == "GENERAL": continue
        db = []
        for key in config[section]:
            db.append((key,config[section][key]))
        res[section] = db
    return res


def set_json(template,var):
    """ Take a json template and fill it with var """

    # Build template
    template = template.replace("{","{{").replace("}","}}") # Avoid uncessary formatting
    for k,v in var.items():
        template = template.replace("(*%s*)" % k,"{%s}" % k)
    output = [json.loads(template.format(**var))]
    return output


def extract_db_json(topic,payload):
    """ Extract db and compute json depending on topic """    
    # Find corresponding rule insite configuration
    for db,rules in CONFBRIDGE.items():
        for rule in rules:
            reg,template = rule
            match = re.match(reg,topic)
            if match:
                # First match is assumed correct
                var = match.groupdict()
                var["payload"] = payload
                return (db,set_json(template,var))

    print("Do not know how to handle this topic : (topic:%r,payload:%r)" % (topic,payload))
    return None


def on_message(client, userdata, msg):
    """The callback for when a PUBLISH message is received from the server."""

    try:
        res = extract_db_json(msg.topic,msg.payload.decode('utf-8'))
        if res is None:
            return
        db,json_body = res
        write_influxdb(db,json_body)
    except:
        traceback.print_exc()
        print("Ignoring topic:%r msg:%r" % (msg.topic,msg.payload))

def on_connect(client, userdata, flags, rc):
    """ The callback for when the client receives a CONNACK response from the server."""
    # Subscribe to all topics
    client.subscribe("#")


def write_influxdb(db,json_body):
    # First change database, then write informations
    while True:
        try:
            databases = influxdb_client.get_list_database()
            if len(list(filter(lambda x: x['name'] == db, databases))) == 0:
                influxdb_client.create_database(db)
            influxdb_client.switch_database(db)
            break
        except requests.exceptions.ConnectionError:
            print("Waiting for database...")
            time.sleep(1)

    influxdb_client.write_points(json_body)


def main():
    """ Entry Point Program """
    args = parse_args()
    global CONFBRIDGE,influxdb_client
    CONFBRIDGE = load_config(args.config)

    influxdb_client = InfluxDBClient(args.influxdb, args.influxdb_port, args.influxdb_user, args.influxdb_password, None)

    mqtt_client = mqtt.Client(args.mqtt_client_id)
    mqtt_client.username_pw_set(args.mqtt_user,args.mqtt_password)
    mqtt_client.on_connect = on_connect
    mqtt_client.on_message = on_message

    while True:
        try:
            mqtt_client.connect(args.mqtt,args.mqtt_port)
            break
        except ConnectionRefusedError:
            print("Waiting for MQTT server...")
            time.sleep(1)

    mqtt_client.loop_forever()

    return 0


if __name__ == "__main__":
   sys.exit(main())
