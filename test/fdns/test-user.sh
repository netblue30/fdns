#!/bin/bash
# This file is part of fdns project
# Copyright (C) 2019-2021 FDNS Authors
# License GPL v2

export MALLOC_CHECK_=3
export MALLOC_PERTURB_=$(($RANDOM % 255 + 1))

echo "TESTING: help/man (test/fdns/help-man.exp)"
./help-man.exp
rm -f tmp

echo "TESTING: list (test/fdns/list.exp)"
./list.exp

echo "TESTING: unlisted (test/fdns/unlisted.exp)"
./test-url.exp

echo "TESTING: transport (test/fdns/transport.exp)"
./transport.exp

echo "TESTING: list=anycast (test/fdns/list-anycast.exp)"
./list-anycast.exp

echo "TESTING: list=all (test/fdns/list-all.exp)"
./list-all.exp

echo "TESTING: list=family (test/fdns/list-family.exp)"
./list-family.exp

echo "TESTING: list=security (test/fdns/list-security.exp)"
./list-security.exp

echo "TESTING: list=OpenNIC (test/fdns/list-opennic.exp)"
./list-opennic.exp

echo "TESTING: list=adblocker (test/fdns/list-adblocker.exp)"
./list-adblocker.exp

echo "TESTING: test-url (test/fdns/test-url.exp)"
./test-url.exp

echo "TESTING: test-url-list (test/fdns/test-url-list.exp)"
./test-url-list.exp

echo "TESTING: test-servers=anycast (test/fdns/test-servers-anycast.exp)"
./test-servers-anycast.exp

echo "TESTING: test-servers (test/fdns/test-servers.exp)"
./test-servers.exp

echo "TESTING: monitor (test/fdns/monitor.exp)"
./monitor.exp

# todo: fix it!
# echo "TESTING: LAN rx packet (test/fdns/ptest.exp)"
# ./ptest.exp
