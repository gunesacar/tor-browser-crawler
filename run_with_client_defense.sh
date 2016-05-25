#!/bin/bash

# install dependencies
sudo apt-get update
sudo apt-get upgrade
sudo apt-get install python tcpdump wireshark Xvfb firefox python-dev python-setuptools libpcap-dev
sudo apt-get install nodejs nodejs-legacy npm
sudo npm install jpm --global

# permissions: capture capabilities
sudo setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' /usr/bin/dumpcap

# set offloads
sudo ifconfig eth0 mtu 1500
sudo ethtool -K eth0 tx off rx off tso off gso off gro off lro off

sudo easy_install pip
sudo pip install -r requirements.txt

# download gist
wget https://gist.github.com/mjuarezm/852eca0c5820eb7998432e39effcf73a/archive/a638f62d16f10ddc402d05e6772ba7ea5c8d760c.zip
unzip a638f62d16f10ddc402d05e6772ba7ea5c8d760c.zip
mv 852eca0c5820eb7998432e39effcf73a-a638f62d16f10ddc402d05e6772ba7ea5c8d760c/setup.py .
rm -rf a638f62d16f10ddc402d05e6772ba7ea5c8d760c.zip 852eca0c5820eb7998432e39effcf73a-a638f62d16f10ddc402d05e6772ba7ea5c8d760c
python setup.py

# pass defense
git clone https://mjuarezm@bitbucket.org/jhayes14/multitab-wf.git -b wf-client-defense ./addons/wf-client-defense
cd ./addons/wf-client-defense
jpm xpi
cd ../..

# TODO: how do we check if sawp is already there?
# sudo /bin/dd if=/dev/zero of=/var/swap.1 bs=1M count=1024
# sudo /sbin/mkswap /var/swap.1
# sudo /sbin/swapon /var/swap.1

# run
python bin/tbcrawler.py -u etc/hs_urls.list -c webfp_server -t WebFP -d eth0 -s
