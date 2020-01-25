#!/bin/bash
# This file is part of fdns project
# Copyright (C) 2019-2020 FDNS Authors
# License GPL v2

export MALLOC_CHECK_=3
export MALLOC_PERTURB_=$(($RANDOM % 255 + 1))

echo "TESTING: stress (test/fdns/stress.exp)"
./stress.exp

echo "TESTING: list (test/fdns/list.exp)"
./list.exp

echo "TESTING: test-url (test/fdns/test-url.exp)"
./test-url.exp

echo "TESTING: monitor (test/fdns/monitor.exp)"
./monitor.exp

echo "TESTING: LAN rx packet (test/fdns/ptest.exp)"
./ptest.exp
