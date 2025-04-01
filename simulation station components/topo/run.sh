#!/bin/bash

set -e

DIR=$(dirname $0)

$DIR/../images/buildall.sh

echo ""
echo "Built all images."
echo ""

# configure Halsey
cp $DIR/../conf/halsey.yml $DIR/../images/halsey/halsey-api/src/

# Run Halsey
echo -e "\nRunning Halsey"
halsey_id=$($DIR/../images/halsey/halsey-api/run.sh daemon)

# Run mininet and launch simulations
echo -e "\nRunning mininet"
python3 $DIR/mytopo.py

docker kill $halsey_id

