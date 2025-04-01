#!/bin/bash

DIR=$(dirname $0)

source $DIR/src/config.sh

docker run --network=host -d -it --rm -p $SERVER_PORT:$SERVER_PORT iman/syn-attacker:1 bash dispatch.sh
