#!/bin/bash
# This file is part of fdns project
# Copyright (C) 2019-2020 FDNS Authors
# License GPL v2

export MALLOC_CHECK_=3
export MALLOC_PERTURB_=$(($RANDOM % 255 + 1))

echo "TESTING: ********************"
printf "TESTING: running as user "
whoami
echo "TESTING: ********************"

echo "TESTING: stress-cache (test/fdns/stress-cache.exp)"
./stress-cache.exp

echo "TESTING: stress (test/fdns/stress.exp)"
./stress.exp

