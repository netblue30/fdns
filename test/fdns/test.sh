#!/bin/bash
# This file is part of fdns project
# Copyright (C) 2019-2020 FDNS Authors
# License GPL v2

# we are coming into this file as root user; by the end we will switch back to the regular $USER

export MALLOC_CHECK_=3
export MALLOC_PERTURB_=$(($RANDOM % 255 + 1))

echo "TESTING: ********************"
printf "TESTING: running as user "
whoami
echo "TESTING: ********************"


echo "TESTING: already running (test/fdns/already-running.exp)"
./already-running.exp

echo "TESTING: default wget (test/fdns/default-wget.exp)"
./default-wget.exp
rm -f /tmp/index.html

echo "TESTING: invalid server (test/fdns/invalid-server.exp)"
./invalid-server.exp

echo "TESTING: default ping (test/fdns/default-ping.exp)"
./default-ping.exp

echo "TESTING: default nslookup (test/fdns/default-nslookup.exp)"
./default-nslookup.exp

echo "TESTING: print-requests (test/fdns/print-requests.exp)"
./print-requests.exp

echo "TESTING: ipv6 (test/fdns/ipv6.exp)"
./ipv6.exp

echo "TESTING: filter (test/fdns/filter.exp)"
./filter.exp

echo "TESTING: filter doh (test/fdns/filter-doh.exp)"
./filter-doh.exp

echo "TESTING: nofilter (test/fdns/nofilter.exp)"
./nofilter.exp

echo "TESTING: server=non-profit (test/fdns/server-non-profit.exp)"
./server-non-profit.exp

echo "TESTING: server=anycast (test/fdns/server-anycast.exp)"
./server-anycast.exp

echo "TESTING: multiserver (test/fdns/multiserver.exp)"
./multiserver.exp

echo "TESTING: local doh (test/fdns/local-doh.exp)"
./local-doh.exp

echo "TESTING: forwarder (test/fdns/forwarder.exp)"
./forwarder.exp

echo "TESTING: whitelist (test/fdns/whitelist.exp)"
./whitelist.exp

echo "TESTING: whitelist-file (test/fdns/whitelist-file.exp)"
./whitelist-file.exp

echo "TESTING: restart worker (test/fdns/restart-worker.exp)"
./restart-worker.exp

echo "TESTING: workers (test/fdns/workers.exp)"
./workers.exp

echo "TESTING: restart workers (test/fdns/restart-workers.exp)"
./restart-workers.exp

#
# Start server and switch back to the regular user
#
echo "TESTING: starting user-level tests, please wait 5 seconds"

fdns --daemonize --server=cloudflare
sleep 5
sudo -u $USER ./test-user.sh

