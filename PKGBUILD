# Maintainer: Helle Vaanzinn <glitsj16@riseup.net>

pkgname=fdns
pkgver=0.9.62.6
pkgrel=1
pkgdesc="Firejail DNS-over-HTTPS Proxy Server"
arch=(x86_64)
license=('GPL2')
url="https://github.com/netblue30/fdns"
depends=('libseccomp' 'openssl')
optdepends=('apparmor: support for apparmor profiles'
    'bash-completion: bash completion'
    'systemd: run fdns as a systemd service')
source=("https://github.com/netblue30/fdns/releases/download/v${pkgver}/${pkgname}-${pkgver}.tar.xz")
sha256sums=('886a1fe8fdd205961a570b6ada4b18edcadaaaaacf827f9f6f6728776d717cf1')

build() {
    cd "${srcdir}/${pkgname}-${pkgver}"
    ./configure --prefix=/usr
    make
}

package() {
    cd "${srcdir}/${pkgname}-${pkgver}"
    make DESTDIR="$pkgdir" install

    # systemd unit
    install -d 0755 "${pkgdir}/usr/lib/systemd/system"
    mv "${pkgdir}/etc/${pkgname}/${pkgname}.service" "${pkgdir}/usr/lib/systemd/system/"

    # license
    install -d 0755 "${pkgdir}/usr/share/licenses/${pkgname}"
    mv "${pkgdir}/usr/share/doc/${pkgname}/COPYING" \
        "${pkgdir}/usr/share/licenses/${pkgname}/LICENSE"
}
