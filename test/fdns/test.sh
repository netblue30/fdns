#!/bin/bash
# This file is part of Firejail project
# Copyright (C) 2014-2019 Firejail Authors
# License GPL v2

export MALLOC_CHECK_=3
export MALLOC_PERTURB_=$(($RANDOM % 255 + 1))

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

echo "TESTING: quad9 wget (test/fdns/quad9-wget.exp)"
./quad9-wget.exp
rm -f /tmp/index.html

echo "TESTING: appliedprivacy wget (test/fdns/appliedprivacy-wget.exp)"
./appliedprivacy-wget.exp
rm -f /tmp/index.html

echo "TESTING: powerdns wget (test/fdns/powerdns-wget.exp)"
./powerdns-wget.exp
rm -f /tmp/index.html

echo "TESTING: cleanbrowsing wget (test/fdns/cleanbrowsing-wget.exp)"
./cleanbrowsing-wget.exp
rm -f /tmp/index.html

echo "TESTING: 42l wget (test/fdns/42l-wget.exp)"
./42l-wget.exp
rm -f /tmp/index.html

echo "TESTING: seby.io wget (test/fdns/seby.io-wget.exp)"
./seby.io-wget.exp
rm -f /tmp/index.html


echo "TESTING: cleanbrowsing-family wget (test/fdns/cleanbrowsing-family-wget.exp)"
./cleanbrowsing-family-wget.exp
rm -f /tmp/index.html

echo "TESTING: cloudflare wget (test/fdns/cloudflare-wget.exp)"
./cloudflare-wget.exp
rm -f /tmp/index.html

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


