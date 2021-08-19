#!/bin/bash
# This file is part of Firejail project
# Copyright (C) 2014-2020 Firejail Authors
# License GPL v2

gcov_init() {
	USER=`whoami`
	fdns --help > /dev/null
	sudo chown $USER:$USER `find .`
}

generate() {
	lcov -q --capture -d src/fdns --output-file gcov-file-new
	lcov --add-tracefile gcov-file-old --add-tracefile gcov-file-new  --output-file gcov-file
	rm -fr gcov-dir
	genhtml -q gcov-file --output-directory gcov-dir
	sudo rm `find . -name *.gcda`
	cp gcov-file gcov-file-old
	gcov_init
}


# disable apparmor temporarily
sudo apparmor_parser -R /etc/apparmor.d/usr.bin.fdns 2>&1 > /dev/null
gcov_init
lcov -q --capture -d src/fdns --output-file gcov-file-old

sudo test/fdns/forwarder.exp
generate
sleep 2

sudo test/fdns/whitelist.exp
generate
sleep 2

sudo test/fdns/whitelist-file.exp
generate
sleep 2

sudo test/fdns/test-url-list.exp
generate
sleep 2

make test
generate
sleep 2

# enable apparmor back
sudo apparmor_parser -r /etc/apparmor.d/usr.bin.fdns 2>&1 > /dev/null


