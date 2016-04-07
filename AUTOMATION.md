Automating the Environment Setup
===============

Included in this repo is an Ansible playbook and Vagrantfile which will do most
of the work of setting up an Ubuntu 14.04 Docker container for you if you so
choose to use it. If you wish you can simply follow the instructions below and
then skip straight to step 2 in the README.

Requirements
---------------
* Linux packages: `vagrant ansible docker`

Note you can also install ansible with pip, but note pip does not sign packages
and you probably don't want to run unsigned code as root.

### 1. Configure the environment

* Be sure to add your user to the docker group according to [the instructions on
the Docker website](https://docs.docker.com/engine/installation/linux/) and
then log in and back out, so you don't have to run your containers as root.

* You'll still have disable offloads manually because doing so from within
Docker requires running it in privileged mode:
`sudo ethtool -K <interface> tx off rx off tso off gso off gro off lro off`

* Create and provision the container: `vagrant up --provider docker`

* SSH into the container: `vagrant ssh`
