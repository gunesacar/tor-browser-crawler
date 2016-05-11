#!/bin/bash

# install dependencies
sudo apt-get update
sudo apt-get upgrade
sudo apt-get install python tcpdump wireshark Xvfb firefox python-dev python-setuptools libpcap-dev
sudo apt-get install nodejs nodejs-legacy npm

# set offloads
sudo ifconfig eth0 mtu 1500
sudo ethtool -K eth0 tx off rx off tso off gso off gro off lro off

sudo easy_install pip
sudo pip install -r requirements.txt

# download gist
wget https://gist.github.com/mjuarezm/852eca0c5820eb7998432e39effcf73a/archive/a638f62d16f10ddc402d05e6772ba7ea5c8d760c.zip
unzip a638f62d16f10ddc402d05e6772ba7ea5c8d760c.zip
# TODO...

# pass defense
git clone https://mjuarezm@bitbucket.org/jhayes14/multitab-wf.git -b wf-client-defense ./addons/wf-client-defense
cd ./addons/wf-client-defense
jpm xpi
cd ../..

# run
python bin/tbcrawler.py -u etc/hs_urls.list
