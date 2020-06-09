Name:           fdns
Version:        0.9.63
Release:        1%{?dist}
Summary:        Firejail DNS-over-HTTPS Proxy Server

License:        GPLv3+
URL:            https://github.com/netblue30/fdns
Source0:        https://github.com/netblue30/fdns/archive/master.tar.gz
Patch0:         disable-apparmor.patch

BuildRequires:  libseccomp-devel
BuildRequires:  openssl-devel

%description
fdns is a DNS-over-HTTPS proxy server targeted at small networks and
Linux desktops. To speed up the name resolution fdns caches the responses,
and uses a configurable adblocker and privacy filter to cut down
unnecessary traffic. The software is written in C, and is licensed under GPLv3.


%prep
%autosetup -n %{name}-master -S git


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



#TODO: %%changelog

