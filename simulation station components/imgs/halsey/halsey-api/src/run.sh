#!/usr/bin/env bash

DIR=$(dirname $0)

portnum() {
    echo $(cd $DIR && python3 -c "import config; print(config.PORT)")
}

start() {

    # kill previous instances
    ps aux | grep flask | grep -v grep | awk '{ print $2 }' | xargs kill

    # start server
    FLASK_APP=server.py flask run -p "$(portnum)" -h 0.0.0.0

}

start

while inotifywait -qqre modify $(pwd)
do
    start
done
