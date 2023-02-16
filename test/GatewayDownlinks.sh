#!/bin/sh

MQTT_HOST="192.168.2.249"
MQTT_TOPIC="ClasseC/in/CCCCAAAA"

echo "Publish to topic ${MQTT_TOPIC} on host ${MQTT_HOST}"
mosquitto_pub  -h ${MQTT_HOST} -m "{\"port\":1, \"time\":\"immediately\", \"confirmed\":true, \"data\":\"434F5059\"}" -t ${MQTT_TOPIC}
