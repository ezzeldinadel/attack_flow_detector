## Commands to install Snort:

```
wget https://snort.org/downloads/archive/snort/snort-2.9.9.0.tar.gz
tar -xvzf snort-2.9.9.0.tar.gz
cd snort-2.9.9.0
./configure --enable-sourcefire
make
sudo make install
ldconfig

snort -v --daq-list | grep nfq
```
## Commands to install DAQ

```
wget https://www.snort.org/downloads/snort/daq-2.0.6.tar.gz
tar -xvzf daq-2.0.6.tar.gz
cd daq-2.0.6
./configure
make
sudo make install
```

## IPTABLES rules

```
iptables -I FORWARD -i br0-int -o ens4 -j NFQUEUE --queue-num=5
```

## snort commands

```
snort -Q -c ./snort.conf
```

## snort confs in `/etc/snort/snort.conf`

```
# Event thresholding or suppression commands. See threshold.conf 
include threshold.conf
var PREPROC_RULE /etc/snort/preproc_rules
config daq: nfq
config daq_mode: inline
config daq_var: queue=5
```

## reference

[This tutorial](http://sublimerobots.com/2017/06/snort-ips-with-nfq-routing-on-ubuntu/)