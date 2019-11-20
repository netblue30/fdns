#!/bin/bash
# This file is part of Firejail project
# Copyright (C) 2014-2019 Firejail Authors
# License GPL v2

export MALLOC_CHECK_=3
export MALLOC_PERTURB_=$(($RANDOM % 255 + 1))

echo "TESTING: ********************"
printf "TESTING: running as user "
whoami
echo "TESTING: ********************"

echo "TESTING: list (test/fdns/list.exp)"
./list.exp

echo "TESTING: test-url (test/fdns/test-url.exp)"
./test-url.exp

echo "TESTING: monitor (test/fdns/test-monitor.exp)"
./monitor.exp
