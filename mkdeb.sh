#!/bin/sh
# based on http://tldp.org/HOWTO/html_single/Debian-Binary-Package-Building-HOWTO/
# a code archive should already be available

set -e

TOP=`pwd`
CODE_ARCHIVE="$1-$2.tar.xz"
CODE_DIR="$1-$2"
INSTALL_DIR="${INSTALL_DIR}${CODE_DIR}/debian"
DEBIAN_CTRL_DIR="${DEBIAN_CTRL_DIR}${CODE_DIR}/debian/DEBIAN"

echo "*****************************************"
echo "code archive: $CODE_ARCHIVE"
echo "code directory: $CODE_DIR"
echo "install directory: $INSTALL_DIR"
echo "debian control directory: $DEBIAN_CTRL_DIR"
echo "*****************************************"

tar -xJvf $CODE_ARCHIVE
#mkdir -p $INSTALL_DIR
cd $CODE_DIR
./configure --prefix=/usr --enable-apparmor
make -j2
mkdir debian
DESTDIR=debian make install-strip

cd ..
echo "*****************************************"
SIZE=`du -s $INSTALL_DIR`
echo "install size $SIZE"
echo "*****************************************"

pwd
mkdir -p $INSTALL_DIR/usr/lib/systemd/system
install -m644 $INSTALL_DIR/etc/fdns/fdns.service $INSTALL_DIR/usr/lib/systemd/system/fdns.service
mv $INSTALL_DIR/usr/share/doc/fdns/RELNOTES $INSTALL_DIR/usr/share/doc/fdns/changelog.Debian
gzip -9 -n $INSTALL_DIR/usr/share/doc/fdns/changelog.Debian
rm $INSTALL_DIR/usr/share/doc/fdns/COPYING
install -m644 platform/debian/copyright $INSTALL_DIR/usr/share/doc/fdns/.
mkdir -p $DEBIAN_CTRL_DIR
sed "s/FDNSVER/$2/g"  platform/debian/control.$(dpkg-architecture -qDEB_HOST_ARCH) > $DEBIAN_CTRL_DIR/control

find $INSTALL_DIR/etc -type f | sed "s,^$INSTALL_DIR,," | LC_ALL=C sort > $DEBIAN_CTRL_DIR/conffiles
chmod 644 $DEBIAN_CTRL_DIR/conffiles
find $INSTALL_DIR  -type d | xargs chmod 755
cd $CODE_DIR
fakeroot dpkg-deb --build debian
lintian debian.deb
mv debian.deb ../fdns_$2_1_$(dpkg-architecture -qDEB_HOST_ARCH).deb
cd ..
rm -fr $CODE_DIR
