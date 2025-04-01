#!/bin/bash

source $(dirname $0)/src/config.sh

if [ -z ${1+x} ]
then
    echo script name missing
    exit 1
else
    script_name="$1"
fi

if [ -z ${2+x} ]
then
    outfile="out.pcap"
else
    outfile="$2"
fi


PORT_ARGS=""

if [[ "$SERVE_OUT_ENABLED" == "1" ]]
then
    PORT_ARGS="-p $SERVE_OUT_PORT:$SERVE_OUT_PORT"
fi

docker run -d -it --rm $PORT_ARGS \
    -v $(pwd)/src:/usr/src/app/src \
    -v $(pwd)/out:/usr/src/app/out \
    --cap-add=SYS_ADMIN iman/puppet-master:1 \
    bash src/dispatch.sh "$script_name" "$outfile"


