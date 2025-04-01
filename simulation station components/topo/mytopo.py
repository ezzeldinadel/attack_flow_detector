#!/usr/bin/env python

import time
import requests

from mininet.net import Containernet
from mininet.node import Controller, RemoteController
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import info, setLogLevel

from functools import partial

from vn import install_vns, init_vns


setLogLevel('info')

net = Containernet(controller=partial(RemoteController, ip='172.17.0.1', port=6633), autoSetMacs=True)

info('*** Adding controller\n')

net.addController('c0')

info('*** Adding gateways\n')

gw1 = net.addDocker('gw1', ip='210.0.0.200', mac="00:00:00:00:00:01", dimage="mg-ids", pubnet=True)
gw2 = net.addDocker('gw2', ip='210.0.0.200', mac="00:00:00:00:00:02", dimage="mg-ips", pubnet=True)

info('*** Adding simulations (benign)\n')

h1 = net.addDocker('h1', ip='210.0.0.101', mac="00:00:00:00:00:03", dimage="mg-benign-googler")
h2 = net.addDocker('h2', ip='210.0.0.102', mac="00:00:00:00:00:04", dimage="mg-benign-googler")
h3 = net.addDocker('h3', ip='210.0.0.103', mac="00:00:00:00:00:05", dimage="mg-benign-googler")
h4 = net.addDocker('h4', ip='210.0.0.104', mac="00:00:00:00:00:06", dimage="mg-benign-googler")
h5 = net.addDocker('h5', ip='210.0.0.105', mac="00:00:00:00:00:07", dimage="mg-benign-googler")

info('*** Adding simulations (malicious)\n')
m1 = net.addDocker('m1', ip='210.0.0.110', mac="00:00:00:00:00:10", dimage="mg-malish-apt")
m2 = net.addDocker('m2', ip='210.0.0.111', mac="00:00:00:00:00:11", dimage="mg-malish-apt")
m3 = net.addDocker('m3', ip='210.0.0.112', mac="00:00:00:00:00:12", dimage="mg-malish-apt")
m4 = net.addDocker('m4', ip='210.0.0.113', mac="00:00:00:00:00:13", dimage="mg-malish-apt")

info('*** Adding switches\n')

s1 = net.addSwitch('sw1')
s2 = net.addSwitch('sw2')

info('*** Creating links\n')

s1_hosts = (h1, h3, h5, m1, m3, gw1)
# s1_hosts = (h1, m1, gw1)
s2_hosts = (h2, h4, m2, m4, gw2)
# s2_hosts = (h2, gw2)

for x in s1_hosts:
    net.addLink(x, s1)

for x in s2_hosts:
    net.addLink(x, s2)

net.addLink(s1, s2)

info('*** Starting network\n')
net.start()

# info('*** Testing connectivity\n')
# net.ping([h1, h2])

info('*** Starting nodes\n')
for x in s1_hosts + s2_hosts:
    x.start()

info('*** Initiating virtual nets\n')
install_vns()
init_vns()

# # TOFF
# info('*** resetting vnet assignment\n')
# for i in range(1,7):
#     requests.get("http://localhost:8070/v1/vnet/set?host=00:00:00:00:00:%02d&vnet=vnet1" % i)
# requests.get("http://localhost:8070/v1/vnet/set?host=00:00:00:00:00:%02d&vnet=vnet1" % 10)
# requests.get("http://localhost:8070/v1/vnet/set?host=00:00:00:00:00:%02d&vnet=vnet2" % 11)

info('*** Running CLI\n')
CLI(net)

info('*** Stopping network')
net.stop()



