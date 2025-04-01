#!/usr/bin/env bash

port_num=$1

cd out

screen -dmSL benign-server python -m SimpleHTTPServer $1