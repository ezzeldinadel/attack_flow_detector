#!/bin/bash

DIR=$(dirname $0)

$DIR/setup-net.sh &> out.log

/bin/sh

