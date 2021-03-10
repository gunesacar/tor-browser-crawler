tor-browser-crawler [![Build Status](https://travis-ci.org/webfp/tor-browser-crawler.svg)](https://travis-ci.org/webfp/tor-browser-crawler)
===============
![DISCLAIMER](https://upload.wikimedia.org/wikipedia/commons/thumb/d/d7/Dialog-warning-orange.svg/40px-Dialog-warning-orange.svg.png "experimental")  **experimental - PLEASE BE CAREFUL. Intended for reasearch purposes.**

We have freezed the repository with the source code that we used to collect data for our paper in ACM CCS’14 [“A Critical Analysis of Website Fingerprinting Attacks”](http://homes.esat.kuleuven.be/~mjuarezm/index_files/pdf/ccs14.pdf) [1]. The [release](https://github.com/webfp/tor-browser-crawler/releases/tag/webfp-paper) is tagged in this repository.

The crawler can be used in the similar website fingerprinting studies. It uses [Selenium](https://selenium-python.readthedocs.org/) to drive the **Tor Browser** and [stem](https://stem.torproject.org/) to control the tor. Our implementation started as a fork of  [tor-browser-selenium](https://github.com/isislovecruft/tor-browser-selenium) (by  @isislovecruft).

For the crawl parameters such as `batch` and `instance` refer to the ACM WPES’13 paper by Wang and Goldberg[2].

Requirements
---------------
* Linux packages: ```python tcpdump wireshark Xvfb```
* Python packages: ```selenium requests stem psutil(version < 3) tld xvfbwrapper scapy```

# Getting started

### 1. Configure the environment

* We recommend running crawls in a VM or a container (e.g. LXC) to avoid perturbations introduced by the background network traffic and system level network settings. Please note that the crawler will not only store the Tor traffic but will capture all the network traffic generated during a visit to a website. That’s why it’s extremely important to disable all the automatic/background network traffic such as the auto-updates. See, for example the [instructions for disabling automatic connections for Ubuntu](https://help.ubuntu.com/community/AutomaticConnections).

* You’ll need to set capture capabilities to your user: `sudo setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' /usr/bin/dumpcap`

* [Download the TBB](https://www.torproject.org/download/download.html.en) and extract it to `./tbb/tor-browser-linux<arch>-<version>_<locale>/`.

* You might want to change the MTU of your network interface and disable NIC offloads that might make the traffic collected by tcpdump look different from how it would have been seen on the wire.

 * Change MTU to standard ethernet MTU (1500 bytes): `sudo ifconfig <interface> mtu 1500`

 * Disable offloads: `sudo ethtool -K <interface> tx off rx off tso off gso off gro off lro off`

 * See the [Wireshark Offloading page](https://wiki.wireshark.org/CaptureSetup/Offloading) for more info.



### 2. Run a crawl with the defaults

```
python tbcrawler/pytbcrawler.py -t WebFP -u ./etc/localized-urls-100-top.csv -c wang_and_goldberg
```

To get all the available command line parameters and the usage run:

```
python tbcrawler/pytbcrawler.py --help
```

### 3. Check out the results

The collected data can be found in the `results` folder:

    * Pcaps: `./results/latest`
    * Logs: `./results/latest_crawl_log`


Use Docker container
-------------------

1. Install docker and start it.

1. Clone repository and change directory into it.

1. `make build`

1. `make run` (or pass it the parameters, for example: `make run PARAMS="-t WebFP"`


Sample crawl data
-------------
You can download a sample of data collected using this crawler with the configuration used by Wang and Goldberg in their WPES'13 paper (namely 10 batches, 100 pages and 4 instances per page) from here:

* [Crawl `140203_042843`](https://mega.co.nz/#!ekIXBTbZ!1bn7zSPuV5r8fS0zpp2hrMvNc4Xrj6F2oUbjlyBb87o)
(SHA256: 06a007a41ca83bd24ad3f7e9f5e8f881bd81111a547cbfcf20f057be1b89d0dd)

The crawl names include a timestamp. The list of crawls used in our study can be found in the appendix of the paper [1].


Notes
-------
* Tested on *Xubuntu 14.04* and *Debian 7.8*.


References
-------------

[1] M. Juarez, S. Afroz, G. Acar, C. Diaz, R. Greenstadt, “A Critical Analysis of Website Fingerprinting Attacks”, in the proceedings of the ACM Conference on Computer and Communications Security (CCS), pp. 263-274, ACM, 2014.

[2] T. Wang and I. Goldberg. “Improved Website Fingerprinting on Tor”, in the proceedings of the ACM Workshop on Privacy in the Electronic Society (WPES), pp. 201–212. ACM, 2013.
