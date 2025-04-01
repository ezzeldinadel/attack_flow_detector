#!/usr/bin/env bash

DIR=$(dirname $0)

portnum() {
    cat $DIR/src/halsey.yml | grep port | grep -oE '[[:digit:]]+'
}

set -e

port=$(portnum)
daemon=""

if [[ "$1" == "daemon" ]]
then
    daemon="-d"
fi

src_path=$(realpath $DIR/src)

cont_name=$(cat $DIR/src/halsey.yml | grep container-name | cut -d":" -f2 | sed -e 's/\s//g')

[ -z "$cont_name" ] && {
    cont_name=halsey-server
}

echo $cont_name

docker run $daemon --name $cont_name -it --rm -p $port:$port -v $src_path:/root/halsey iman/halsey:1
