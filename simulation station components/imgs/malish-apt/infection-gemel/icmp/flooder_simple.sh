#!/usr/bin/env bash

#DIR=$(dirname $0)

#. $DIR/config.sh

apt-get install hping3

if [ $# -lt 1 ]
then
    echo "Usage: ./flooder.sh <dst ip>"
    exit 1
fi

dst_ip="$1"

#mkdir -p $DIR/$SERVE_DIR

# =======
hping3 -1 --fast --count 50 -p 80 "$dst_ip"

echo " ICMP"
#sleep 1

#screen -dmSL ig-flood-stats python syn-flood-stats.py "$dst_ip" "$dst_port"

#screen -dmSL ig-flood-server $DIR/server.sh


