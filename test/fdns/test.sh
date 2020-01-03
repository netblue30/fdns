#!/bin/bash
# This file is part of Firejail project
# Copyright (C) 2019-2020 Firejail Authors
# License GPL v2

# we are coming into this file as root user; by the end we will switch back to the regular $USER

export MALLOC_CHECK_=3
export MALLOC_PERTURB_=$(($RANDOM % 255 + 1))

echo "TESTING: ********************"
printf "TESTING: running as user "
whoami
echo "TESTING: ********************"

echo "TESTING: help/man (test/fdns/help-man.exp)"
./help-man.exp
rm -f tmp

echo "TESTING: list (test/fdns/list.exp)"
./list.exp

echo "TESTING: test-url (test/fdns/test-url.exp)"
./test-url.exp

echo "TESTING: already running (test/fdns/already-running.exp)"
./already-running.exp

echo "TESTING: default wget (test/fdns/default-wget.exp)"
./default-wget.exp
rm -f /tmp/index.html

SERVERS=`fdns --list | grep -v https | awk '{ print $1 }'`
for s in $SERVERS
do
	./wget.exp $s
	rm -f /tmp/index.html
done

echo "TESTING: tags (test/fdns/tags.exp)"
./tags.exp

echo "TESTING: default-not-found wget (test/fdns/default-notfound-wget.exp)"
./default-notfound-wget.exp
rm -f /tmp/index.html

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

echo "TESTING: nofilter (test/fdns/nofilter.exp)"
./filter.exp

echo "TESTING: restart worker (test/fdns/restart-worker.exp)"
./restart-worker.exp

echo "TESTING: workers (test/fdns/workers.exp)"
./workers.exp

echo "TESTING: restart workers (test/fdns/restart-workers.exp)"
./restart-workers.exp

#
# Start server as random and switch back to the regular user
#
echo "TESTING: starting user-level tests, please wait 5 seconds"
fdns --daemonize --server=cloudflare --workers=1
sleep 5
sudo -u $USER ./test-user2.sh
pkill fdns
sleep 3


fdns --daemonize --server=cloudflare
sleep 5
sudo -u $USER ./test-user.sh

