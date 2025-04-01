#!/bin/bash

echo "config daq: nfq" >> /etc/snort/snort.conf
echo "config daq_mode: inline" >> /etc/snort/snort.conf
echo "config daq_var: queue=5" >> /etc/snort/snort.conf

