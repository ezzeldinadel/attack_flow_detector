#!/bin/bash

while [ true ]
do
  # ping -c5 8.8.8.8
  hping3 -1 -c 11 --fast 8.8.8.8
  sleep 7
done
