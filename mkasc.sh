#!/bin/sh

echo "Calculating SHA256 for all files in /transfer - fdns version $1"

cd /transfer
sha256sum * > fdns-$1-unsigned
gpg --clearsign --digest-algo SHA256 < fdns-$1-unsigned > fdns-$1.asc
gpg --verify fdns-$1.asc
gpg --detach-sign --armor fdns-$1.tar.xz
rm fdns-$1-unsigned
