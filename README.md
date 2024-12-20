# Firejail DNS-over-HTTPS Proxy Server
<div style="height:20px;">&nbsp;</div>

<table>
<tr>
<td>
<a href="https://odysee.com/@netblue30:9/networking:5" target="_blank">
<img src="https://thumbs.odycdn.com/ab044dd53b47ff1a6355ecc11c27b9ec.webp"
alt="Network Security Introduction" width="240" height="142" border="10" />
<br/>Network Security Introduction
</a>
</td>
<td>
<a href="https://odysee.com/@netblue30:9/fdns:8" target="_blank">
<img src="https://thumbs.odycdn.com/d22e1d3084e6f03315e076f640d829ec.webp"
alt="Firejail Encrypted DNS HowTo" width="240" height="142" border="10" />
<br/>Firejail Encrypted DNS HowTo
</a>
</td>
</tr>
</table>

<div style="height:20px;">&nbsp;</div>

FDNS is an encrypted DNS proxy designed for small networks and Linux desktops. Lean and mean, it protects your computer from some of the most common cyber threats, while also improving privacy and the system performance.

FDNS is written in C and licensed under GPLv3. We use only DoH and DoT services from non-logging and non-censoring providers, while preferring small operators such as open-source enthusiasts and privacy-oriented non-profit organizations.

<div style="height:20px;">&nbsp;</div>

<table>
<tr>

<div style="height:20px;">&nbsp;</div>

<h2>Features</h2>
<ul>
<li>Network of 200+ non-logging/non-censoring service providers spread across the globe. Access to specialized services such as family filtering, adblocking, security, OpenNIC.</li>
<li>Blocking ads, trackers, coinminers, phishing.</li>
<li>DNS resolver cache and DNS firewall targeting various DNS attack techniques.</li>
<li>Highly scalable multi-process design and built-in support for various security technologies such as seccomp, Linux namespaces, and AppArmor.</li>
<li>Seamless integration with Firejail Security Sandbox.</li>
</ul>

![FDNS monitor](monitor1.png)

<div style="height:20px;">&nbsp;</div>


<h2>Build and Install</h2>

`````
sudo apt install build-essential make git
sudo apt install libseccomp-dev libssl-dev
git clone --recursive https://github.com/netblue30/fdns
cd fdns
./configure --prefix=/usr --enable-apparmor
make
sudo make install
(to uninstall) sudo make uninstall
`````

<div style="height:20px;">&nbsp;</div>
<h2>About us</h2>
<div style="height:20px;">&nbsp;</div>

FDNS is a community project. We are not affiliated with any company, and we don’t have any commercial goals. Our focus is the Linux desktop. Home users and Linux beginners are our target market. The software is built by a large international team of volunteers on GitHub. Expert or regular Linux user, you are welcome to join us!

Security bugs are taken seriously, please email them to netblue30 at protonmail.com.

<ul>
<li>Webpage: <a href="https://firejaildns.wordpress.com">https://firejaildns.wordpress.com</a></li>
<li>Development: <a href="https://github.com/netblue30/fdns">https://github.com/netblue30/fdns</a></li>
<li>Documentation: <a href="https://github.com/netblue30/fdns/wiki">https://github.com/netblue30/fdns/wiki</a> (wiki)</li>
<li>Download: <a href="https://github.com/netblue30/fdns/releases">https://github.com/netblue30/fdns/releases</a></li>
<li>Support: <a href="https://github.com/netblue30/fdns/issues">https://github.com/netblue30/fdns/issues</a> (GitHub)
<li>FAQ: <a href="https://github.com/netblue30/fdns/wiki/FAQ">https://github.com/netblue30/fdns/wiki/FAQ</a> (wiki)</li>
</ul>
<div style="height:20px;">&nbsp;</div>

<h2>Development release 0.9.75:</h2>

When you clone the project please run `````git clone --recursive https://github.com/netblue30/fdns`````

<div style="height:20px;">&nbsp;</div>
