#!/bin/bash

DIR=$(dirname $0)

. $DIR/config.sh

mkdir -p $SERVE_DIR

cd $SERVE_DIR

port="$1"

if [[ -z ${1+x} ]]
then
    port=8001
fi

python -m http.server $port

