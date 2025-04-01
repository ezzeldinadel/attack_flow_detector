Make OVS:

```
apt-get update

apt-get install -y git automake autoconf gcc uml-utilities libtool build-essential git pkg-config linux-headers-`uname -r`


apt-get install -y python-simplejson python-qt4 python-twisted-conch automake autoconf gcc uml-utilities libtool build-essential git pkg-config

apt install -y iperf

wget https://www.openvswitch.org/releases/openvswitch-2.11.0.tar.gz
tar xvf openvswitch-2.11.0.tar.gz

cd openvswitch-2.11.0

./boot.sh
./configure --with-linux=/lib/modules/`uname -r`/build

make
make install
make modules_install

```

Run OVS:

```
modprobe openvswitch

mkdir -p /usr/local/etc/openvswitch

ovsdb-tool create /usr/local/etc/openvswitch/conf.db vswitchd/vswitch.ovsschema

mkdir -p $(dirname /usr/local/var/run/openvswitch/ovsdb-server.pid.tmp)
mkdir -p $(dirname /usr/local/var/run/openvswitch/ovsdb-server.pid.tmp)

ovsdb-server -v --log-file --pidfile --remote=punix:/usr/local/var/run/openvswitch/db.sock # --detach


ovs-vswitchd --pidfile # --detach

ovs-vsctl --no-wait init

ovs-vsctl show

```

Make internal and VXLAN interfaces:

```
ovs-vsctl add-br br0
ovs-vsctl add-port br0 br0-int -- set interface br0-int type=internal
ovs-vsctl add-port br0 vx1 -- set interface vx1 type=vxlan options:remote_ip=$peer_ip options:key=2001
ifconfig br0-int 210.0.0.101 mtu 1400 up
```

Restarting
-----------

In two tmux or screen windows, run:

```
ovsdb-server -v --log-file --pidfile --remote=punix:/usr/local/var/run/openvswitch/db.sock
```

For DB and the following for OVS daemon:

```
ovs-vswitchd --pidfile
```

Also ifconfig IP confs is lost with restart so:

```
ifconfig br0-int 210.0.0.101 mtu 1400 up
```

**Attention**
If the internal IP address is changed, you will have to re-install OVS VXLANs. Use `gemel-sdn/provision/scripts/connect.sh` to do that.

For the IPS machine, you also gotta turn on the in/eggress ifaces:

```
ifconfig ingress up
ifconfig egress up
```
