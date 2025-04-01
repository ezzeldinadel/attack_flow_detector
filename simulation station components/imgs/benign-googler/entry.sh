#!/bin/bash

DIR=$(dirname $0)

# Add routes
sudo route add default gw $(ifconfig $(cat /etc/hostname)-eth0 | grep -oE "inet addr:([0-9].?)+" | grep -oE "([0-9]+\.)+")200
sudo route del default gw $(ifconfig eth0 | grep -oE "inet addr:([0-9].?)+" | grep -oE "([0-9]+\.)+")1

screen -dmSL pinger $DIR/pinger.sh
screen -dmSL pinger $DIR/fake-server.sh

# Run Googler
bash src/dispatch.sh google benign

