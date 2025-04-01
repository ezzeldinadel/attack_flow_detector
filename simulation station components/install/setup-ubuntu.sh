#!/bin/bash

# get current script dir
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

# install destination dir
BASE_DIR=/root

cd $BASE_DIR

apt install -y openjdk-8-java
apt install -y git

# install ODL
apt-add-repository ppa:ansible/ansible -y
apt-get update
apt-get install -y ansible
ansible-playbook $DIR/odl.yml

# install gemel-net
git clone https://github.com/ATMoS-Waterloo/gemelnet
ln -s containernet gemelnet
cd gemelnet/ansible
ansible-playbook -i "localhost," -c local install.yml
cd ../..

# add gemel-sdn to python path
echo "export PYTHONPATH=\"\$PYTHONPATH:$(realpath $DIR/../lib)\"" >> ~/.bashrc
echo "export PYTHONPATH=\"\$PYTHONPATH:$(realpath $BASE_DIR)/gemelnet\"" >> ~/.bashrc

# install Python 3.6 and environment for Jupyter and Machine Learning
sudo add-apt-repository ppa:jonathonf/python-3.6
apt update
apt-get install -y python3.6 python-pip
virtualenv -p /usr/bin/python3.6 jupenv
. jupenv/bin/activate
pip install tensorflow jupyter

# start ODL
/usr/local/vtn/bin/vtn_stop
/usr/local/vtn/bin/vtn_start
/usr/local/vtn/sbin/unc_dmctl status





