# Firejail DNS-over-HTTPS Proxy Server

fdns is a DNS-over-HTTPS proxy server targeted at small networks and Linux desktops.
To speed up the name resolution fdns caches the responses, and uses a configurable adblocker
and privacy filter to cut down unnecessary traffic.
The software is written in C, and is licensed under GPLv3.

* Project webpage: https://firejaildns.wordpress.com
* Documentation: (FDNS Handbook](https://github.com/netblue30/fdns/wiki/Introduction)
* FAQ: [wiki](https://github.com/netblue30/fdns/wiki/FAQ)

<div style="height:20px;">&nbsp;</div>


## Project Status

Release `0.9.62` is out. Download: https://github.com/netblue30/fdns/releases/tag/v0.9.62.

The current development version is `0.9.63`.


<div style="height:20px;">&nbsp;</div>

## Features

* Works out of the box with no configuration changes.
The defaults mentioned below can be overwritten using command line options.

* The proxy listens on local loopback address `127.1.1.1`, UDP port `53`.
This allows it to coexist peacefully with any other DNS server/proxy installed on the system.
Change this default with the --proxy-addr command line option.

* Using only DoH services from zero-logging providers, based on the privacy policy
posted on the provider's website. Print the list of supported servers with `--list`,
and use `--server=` to pick a specific server (`--server=powerdns`). You can also use a group,
in which case fdns will choose a random server from the group (`--server=Europe`). By default
we pick a random server from the anycast group (`--server=anycast`).
`````
$ fdns --list
42l - non-profit, France, Europe
  https://42l.fr
adguard - anycast, adblocker
  https://adguard.com/en/adguard-dns/overview.html
appliedprivacy - non-profit, Austria, Europe
  https://appliedprivacy.net
cleanbrowsing - anycast, security
  https://cleanbrowsing.org
cleanbrowsing-family - family
  https://cleanbrowsing.org
cloudflare - anycast
  https://www.cloudflare.com
digital-society - non-profit, Switzerland, Europe
   https://www.digitale-gesellschaft.ch
powerdns - Netherlands, Europe
  https://powerdns.org
quad9 - anycast, security
  https://quad9.net
seby.io - Australia, Asia-Pacific
  https://dns.seby.io
tiarapp - Singapore, Asia-Pacific
  https://doh.tiar.app
tiarapp-jp - Japan, Asia-Pacific
  https://jp.tiar.app/
`````

* DNS resolver cache with a fixed time to live of 180 seconds for DNS records.

* Default anti-tracker and adblocker based on EFF's [Privacy Badger](https://github.com/EFForg/privacybadger),
Steven Black's [hosts](https://github.com/StevenBlack/hosts) project, and ZeroDot1 [coninblocker](https://zerodot1.gitlab.io/CoinBlockerListsWeb/index.html) list.
For blocked domains we respond with `127.0.0.1`. Use `--nofilter` to disable.

The filter files are `/etc/fdns/adblocker`, `/etc/fdns/trackers` and `/etc/fdns/coinblocker`.
These are regular text files, you can modify them, or even delete them.
You can also add your own list in `/etc/fdns/hosts`.
Adblocker hosts files as published all over the net should work just fine.

* Blocking IPv6 requests by default and responding with `NXDOMAIN`.
Use `--ipv6` option to overwrite the default.

* DNS handles multiple categories of data: name resolution, email, internet telephony etc.
By default fdns forwards only domain name resolution queries `A` (and `AAAA` if `--ipv6` is requested).
All other queries are dropped, `NXDOMAIN` is returned.
Disable this functionality with `--allow-all-queries` if you are running an email server or some
other service that requires special DNS handling.

* Regular DNS over UDP fallback in case DoH service is unavailable. We use Quad9 for fallback.

* Live DNS request monitoring and statistics.

* Highly scalable multi-process design with a monitoring process and several independent worker processes.
The workers are chrooted into an empty filesystem and sandboxed
in separate Linux namespaces. The privileges are dropped, and
a whitelist seccomp filter is enabled. By default we start 3 workers.
An AppArmor profile is installed in `/etc/apparmor.d` directory.

* Seamless integration with [Firejail security sandbox](https://github.com/netblue30/firejail),
a graphical user interface is available in [Firetools](https://github.com/netblue30/firetools).

<div style="height:20px;">&nbsp;</div>

## Software compile and install

Dependencies: OpenSSL library and libseccomp.

* Debian/Ubuntu:
  * sudo apt-get install libseccomp-dev libssl-dev

* Fedora/CentOS:
  * sudo yum install libseccomp-devel openssl-devel

* Arch Linux:
  * the libraries are already included in the base package

`````
$ git clone https://github.com/netblue30/fdns
$ cd fdns
$ ./configure --prefix=/usr
$ make
$ sudo make install
`````
If AppArmor is present on the system, enable fdns profile by running
`````
# /sbin/apparmor_parser -r /etc/apparmor.d/usr.bin.fdns
`````

<div style="height:20px;">&nbsp;</div>

## Setup fdns on a workstation

Use [Firejail security sandbox](https://github.com/netblue30/firejaill)
to redirect all the DNS traffic to `127.1.1.1`, where fdns listens by default.
Firejail decouples the DNS functionality, allowing each sandbox to  have its own DNS setting.
Your system DNS configuration is not touched. If things go wrong, you won't lose your Internet connectivity.
Here are the steps:

 * Start fdns:
`````
$ sudo fdns
`````

 * Start your applications in Firejail:
`````
$ firejail --dns=127.1.1.1 firefox
$ firejail --dns=127.1.1.1 transmission-qt
`````
<div style="height:20px;">&nbsp;</div>

## Setup fdns on a network server

Set `"nameserver 127.0.0.1"` in `/etc/resolv.conf`.
Start fdns using `--proxy-addr-any`. The proxy will listen on all system interfaces, and `127.0.0.1` for loopback interface.
The default `127.1.1.1` is not used in this case, Firejail is not required to be installed on the system.
`````
$ sudo fdns --proxy-addr-any --daemonize
`````
You can also run the server only on a specific network interface. Example assuming `192.168.1.44` is the IP address of `eth0`:
`````
$ sudo fdns --proxy-addr=192.168.1.44 --daemonize
`````
When using `--daemonize`, errors and warnings are posted to syslog (`/var/log/syslog` on most systems).

<div style="height:20px;">&nbsp;</div>

## Monitoring the proxy

To monitor `fdns`, run as a regular user
`````
$ fdns --monitor
`````
![fdns --monitor](monitor1.png)

The connection status (encrypted/not encrypted) and the requests are posted live in the monitor.

<div style="height:20px;">&nbsp;</div>

