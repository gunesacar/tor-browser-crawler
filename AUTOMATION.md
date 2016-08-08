Automating the Environment Setup
===============

Included in this repo is an Ansible playbook and Vagrantfile which will do most
of the work of setting up an Ubuntu 14.04 Docker container for you if you so
choose to use it. If you wish you can simply follow the instructions below and
then skip straight to step 2 in the README.

Requirements
---------------
* Linux packages: `vagrant ansible docker`
* For VirtualBox deployments: `virtualbox` and `virtualbox-guest-additions`.
* For Digital Ocean deployments: `vagrant plugin install vagrant-digitalocean`.

Note you can also install ansible with pip, but note pip does not sign packages
and you probably don't want to run unsigned code as root.

Usage
=====
* SSH into a machine: `vagrant ssh`.
If there are several machines, append the name of the one you want to use.

* Once authenticated, maybe you'll want to start tmux (if you're into that sort
of thing), and you'll definitely want to run `workon tb-crawler` to activate
the 'tb-crawler' environment (courtesy of virtualenvwrapper), which already
has all the pip dependencies for tor-browser-crawler installed.

General configuration
=======================
* You'll still have disable offloads manually:
`sudo ethtool -K <interface> tx off rx off tso off gso off gro off lro off`

Provider specific configurations
===================================

Docker configuration
----------------------

* Be sure to add your user to the docker group according to [the instructions on
the Docker website](https://docs.docker.com/engine/installation/linux/) and
then log in and back out, so you don't have to run your containers as root.

* Create and provision the container: `vagrant up --provider docker`

VirtualBox configuration
--------------------------
* `vagrant up --provider virtualbox` will create and provision the machines.

Digital Ocean configuration
------------------------------
* Define machine configurations in ./digital-ocean-machines.json
  following the template given in ./skel/.

* `vagrant up --provider digital_ocean` will create and provision the machines.

Compiling Tor from source
============================

* To compile Tor from source, put the Tor source top directory in ./
(either copying or symlinking it).

* The compilation in the remote machine will happen if there is a "~/tor" directory in there.
If you want to disable it, remove that directory both from the local repository dir
and the remote machine.

* It will be installed in /usr/local/bin.
