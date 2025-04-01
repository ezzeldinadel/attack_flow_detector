#!/bin/bash

# start MySQL
find /var/lib/mysql -type f -exec touch {} \; && service mysql start

# run snort
screen -d -m bash -c 'snort -Q -c /etc/snort/snort.conf '
# screen -d -m bash -c 'snort -c /etc/snort/snort.conf -i $(cat /etc/hostname)-eth0'

# run barnyard
screen -d -S barnyard -m bash -c 'sudo barnyard2 -c /etc/snort/barnyard2.conf -d /var/log/snort -f snort.u2 -w /var/log/snort/barnyard2.waldo'

# enable forwarding
sysctl -w net.ipv4.ip_forward=1

# enable forwarding
iptables -I FORWARD -i $(cat /etc/hostname)-eth0 -o eth1 -j NFQUEUE --queue-num=5

#iptables -A FORWARD -j ACCEPT
iptables -t nat -A POSTROUTING -o eth1 -j MASQUERADE

# add eth1 as default gateway
route add default gw $(ifconfig eth1 | grep -oE "inet addr:([0-9].?)+" | grep -oE "([0-9]+\.)+")1

# remove eth0 as default gateway
route del default gw $(ifconfig eth0 | grep -oE "inet addr:([0-9].?)+" | grep -oE "([0-9]+\.)+")1


