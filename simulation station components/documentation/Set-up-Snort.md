Install requirements:

```bash
sudo apt-get install -y build-essential libpcap-dev libpcre3-dev libdumbnet-dev bison flex zlib1g-dev liblzma-dev openssl libssl-dev libnghttp2-dev
```

get number of CPU cores (used later for faster makes)

```bash
threads=$(cat /proc/cpuinfo | grep -E '^processor' | wc -l)
```

make workspace directory

```bash
mkdir -p ~/snort_src
```

download and compile DAQ

```bash
cd ~/snort_src
wget https://snort.org/downloads/snort/daq-2.0.6.tar.gz
tar -xvzf daq-2.0.6.tar.gz
cd daq-2.0.6
./configure
make -j $threads
sudo make install
```

download and install nghttp2

```bash
cd ~/snort_src
wget https://github.com/nghttp2/nghttp2/releases/download/v1.17.0/nghttp2-1.17.0.tar.gz

tar -xzvf nghttp2-1.17.0.tar.gz
cd nghttp2-1.17.0
autoreconf -i --force
automake
autoconf
./configure --enable-lib-only
make -j $threads
sudo make install
```

download and install Snort

```bash
cd ~/snort_src
wget https://www.snort.org/downloads/archive/snort/snort-2.9.9.0.tar.gz
tar -xvzf snort-2.9.9.0.tar.gz
cd snort-2.9.9.0
./configure --enable-sourcefire
make -j $threads
sudo make install
```

run ldconfig and link snort directory
```bash
sudo ldconfig
sudo ln -s /usr/local/bin/snort /usr/sbin/snort
```

init snort files and directories

```bash
# Create the snort user and group:
sudo groupadd snort
sudo useradd snort -r -s /sbin/nologin -c SNORT_IDS -g snort
# Create the Snort directories:
sudo mkdir /etc/snort
sudo mkdir /etc/snort/rules
sudo mkdir /etc/snort/rules/iplists
sudo mkdir /etc/snort/preproc_rules
sudo mkdir /usr/local/lib/snort_dynamicrules
sudo mkdir /etc/snort/so_rules
# Create some files that stores rules and ip lists
sudo touch /etc/snort/rules/iplists/black_list.rules
sudo touch /etc/snort/rules/iplists/white_list.rules
sudo touch /etc/snort/rules/local.rules
sudo touch /etc/snort/sid-msg.map
# Create our logging directories:
sudo mkdir /var/log/snort
sudo mkdir /var/log/snort/archived_logs
# Adjust permissions:
sudo chmod -R 5775 /etc/snort
sudo chmod -R 5775 /var/log/snort
sudo chmod -R 5775 /var/log/snort/archived_logs
sudo chmod -R 5775 /etc/snort/so_rules
sudo chmod -R 5775 /usr/local/lib/snort_dynamicrules

# Change Ownership on folders:
sudo chown -R snort:snort /etc/snort
sudo chown -R snort:snort /var/log/snort
sudo chown -R snort:snort /usr/local/lib/snort_dynamicrules


cd ~/snort_src/snort-2.9.9.0/etc/
sudo cp *.conf* /etc/snort
sudo cp *.map /etc/snort
sudo cp *.dtd /etc/snort

cd ~/snort_src/snort-2.9.9.0/src/dynamic-preprocessors/build/usr/local/lib/snort_dynamicpreprocessor/

sudo cp * /usr/local/lib/snort_dynamicpreprocessor/
```

Update snort.conf
```bash
sudo sed -i "s/include \$RULE\_PATH/#include \$RULE\_PATH/" /etc/snort/snort.conf

sudo sed -i "s/ipvar HOME_NET any/ipvar HOME_NET 210.0.0.0\/24/" /etc/snort/snort.conf

sudo sed -i "s/_PATH ../_PATH \/etc\/snort/" /etc/snort/snort.conf

sudo sed -i "s/#include \$RULE_PATH\/local.rules/include \$RULE_PATH\/local.rules/" /etc/snort/snort.conf

sudo sed -i "s/_LIST_PATH \/etc\/snort\/rules/_LIST_PATH \/etc\/snort\/rules\/iplists/" /etc/snort/snort.conf
```

test configs:
```bash
sudo snort -T -i ens4 -c /etc/snort/snort.conf
```

enable afpacket for active filtering

```bash
echo "config daq: afpacket" >> /etc/snort/snort.conf
echo "config daq_mode: inline" >> /etc/snort/snort.conf
```

create internal interfaces 

```bash
ovs-vsctl add-port br0 ingress -- set interface ingress type=internal
ovs-vsctl add-port br0 egress -- set interface egress type=internal

ifconfig ingress up
ifconfig egress up
```

Then run `enable-gw.sh` and `set-gw.sh` on host and router respectively

run ofctl command:
```
# port number of the internal interface
# int=

# MAC address of the internal interface
# int_mac=

# port number of vx1
# vx1=

# port number of ingress
# ingress=

# port number of egress
# egress=

# overlay ip address of the gateway
# gw_overlay=

# ovs-ofctl add-flow br0 in_port=$egress,priority=10,actions=output:$int

# ovs-ofctl add-flow br0 in_port=$vx1,dl_dst=01:00:00:00:00:00/01:00:00:00:00:00,priority=4000,actions=output:$int

# ovs-ofctl add-flow br0 in_port=$vx1,dl_dst=$int_mac,dl_type=0x0800,nw_dst=$gw_overlay,priority=1000,actions:output=$int

# ovs-ofctl add-flow br0 in_port=$vx1,dl_type=0x0800,priority=900,actions:output=$ingress

# ovs-ofctl add-flow br0 in_port=$vx1,priority=800,actions:output=$int
```

Run snort in **active mode**:

```bash
snort -A console -Q -c /etc/snort/snort.conf -i ingress:egress -u snort -g snort
```

Or, remove `-A` to run it without log to console:
```bash
snort -Q -c /etc/snort/snort.conf -i ingress:egress -u snort -g snort
```

Run snort in **passive mode**:

```bash
snort -A console -u snort -g snort -c /etc/snort/snort.conf -i br0-int 
```

Run barnyard:
```bash
sudo barnyard2 -c /etc/snort/barnyard2.conf -d /var/log/snort -f snort.u2 -w /var/log/snort/barnyard2.waldo -g snort -u snort
```
