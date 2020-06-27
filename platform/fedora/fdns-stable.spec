Name:           fdns
Version:        0.9.62.8
Release:        1%{?dist}
Summary:        Firejail DNS-over-HTTPS Proxy Server

License:        GPLv3+
URL:            https://github.com/netblue30/fdns
Source0:        https://github.com/netblue30/fdns/releases/download/v0.9.62.8/fdns-0.9.62.8.tar.xz
Patch0:         disable-apparmor.patch

BuildRequires:  libseccomp-devel
BuildRequires:  openssl-devel

%description
fdns is a DNS-over-HTTPS proxy server targeted at small networks and
Linux desktops. To speed up the name resolution fdns caches the responses,
and uses a configurable adblocker and privacy filter to cut down
unnecessary traffic. The software is written in C, and is licensed under GPLv3.


%prep
%autosetup -S git


%build
%configure
%make_build


%install
make install DESTDIR=$RPM_BUILD_ROOT


%files
%license COPYING
%doc COPYING README RELNOTES
%{_bindir}/fdns
%config %{_sysconfdir}/fdns
%{_libdir}/systemd/system/fdns.service
%{_datadir}/bash-completion/completions/fdns
%{_mandir}/man1/fdns.1.gz


%changelog
* v0.9.62.8
- HTTP1.1 removed and replaced with HTTP2
- Adding support for https://commons.host network
- Replaced --allow-local-doh with --disable-local-doh
- systemd support
- FDNS included in Arch Linux: https://aur.archlinux.org/packages/fdns
- forcing RD flag (recursion desired) to 1 on all outgoing packets
- setting rr TTL to 600 seconds on incoming and cached packets
- --qps (queries per second)
- --keepalive
- adding geocast and safe-for-work tags
- server list update
- lots of bugfixes

* v0.9.62.6
- gcov regression test coverage support
- lgtm.com security scanning
- whitelisting domains functionality (--whitelist, --whitelist-file)
- resizable monitor terminal window
- support for multiple fdns proxies running on the same system
- enforcing NXDOMAIN for blacklisted domains
- server list update
- lots of bugfixes

* v0.9.62.4
- rate limiting resolvers to 5 queries per second
- CNAME cloaking filter
- DNS rebinding protections
- disable DoH domains on the local network
- --allow-local-dns
- SNI cloaking when possible
- increase cache TTL to 40 minutes
- server list update
- lots of bugfixes

* v0.9.62.2
- feature complete!
- online documentation in github wiki
- automated test framework
- over 60 new DoH servers
- lots of bugfixes

* v0.9.62
- first release
