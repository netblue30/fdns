# Firejail DNS-over-HTTPS Proxy Server
DNS over HTTPS (DoH) is a next-generation communication protocol on track on becoming a major Internet standard (<a href="https://datatracker.ietf.org/doc/rfc8484/">RFC 8484</a>). By adding strong encryption and authentication to the good old DNS protocol, DoH tries to eliminate some of the biggest problems DNS had from the beginning: censorship, surveillance, and man-in-the-middle attacks.

FDNS was designed to run as a local DoH proxy on a Linux desktop, or as a server for a small network. Lean and mean, it protects the computers against some of the most common cyber threats, all while improving the privacy and the system performance.

FDNS is written in C and licensed under GPLv3. The number one job is privacy. We use <b>only</b> DoH services from non-logging providers, while preferring small operators such as open-source enthusiasts and privacy-oriented non-profit organizations.

<div style="height:20px;">&nbsp;</div>

<h2>Features</h2>
<ul>
<li>Works out of the box with little or no configuration changes.</li>
<li>Network of 60+ non-logging DoH service providers spread around the globe. The servers are organized in several categories using a simple geographically-aware tagging system.</li>
<li>Access to specialized DoH services such as family filtering, adblocking, security, OpenNIC.</li>
<li>DNS resolver cache with a fixed TTL (default 40 minutes).</li>
<li>Blocking ads, first and third-party trackers, coinminers, etc. The filters are configurable, the user can add his own hosts filter.</li>
<li>Blocking IPv6 queries by default to reduce the DNS traffic on IPv4 networks.</li>
<li>Anti-tunneling technology: by default only A and AAAA queries are forwarded.</li>
<li>Conditional DNS forwarding support.</li>
<li>Whitelisting mode.</li>
<li>Regular DNS over UDP fallback in case the DoH service becomes unavailable.</li>
<li>Live DNS request monitoring and statistics.</li>
<li>Multiproxy support.</li>
<li>Scalable multi-process design with a frontend process and several independent resolver processes. Security technologies: chroot, seccomp, Linux namespaces, and AppArmor.</li>
<li>Seamless integration with <a href="https://firejail.wordpress.com">Firejail security sandbox</a>.</li>
</ul>
<div style="height:20px;">&nbsp;</div>

<h2>About us</h2>
<div style="height:20px;">&nbsp;</div>

FDNS is a community project. We are not affiliated with any company, and we don’t have any commercial goals. Our focus is the Linux desktop. Home users and Linux beginners are our target market. The software is built by a large international team of volunteers on GitHub. Expert or regular Linux user, you are welcome to join us!

<ul>
<li>Webpage: <a href="https://firejaildns.wordpress.com">https://firejaildns.wordpress.com</a></li>
<li>Development: <a href="https://github.com/netblue30/fdns">https://github.com/netblue30/fdns</a></li>
<li>Documentation: <a href="https://github.com/netblue30/fdns/wiki/Introduction">https://github.com/netblue30/fdns/wiki/Introduction</a> (wiki)</li>
<li>Download: <a href="https://github.com/netblue30/fdns/releases">https://github.com/netblue30/fdns/releases</a></li>
<li>Support: <a href="https://github.com/netblue30/fdns/issues">https://github.com/netblue30/fdns/issues</a> (GitHub)
<li>FAQ: <a href="https://github.com/netblue30/fdns/wiki/FAQ">https://github.com/netblue30/fdns/wiki/FAQ</a> (wiki)</li>
</ul>
<div style="height:20px;">&nbsp;</div>

## Project Status

Release `0.9.62.6` is out.

<div style="height:20px;">&nbsp;</div>

