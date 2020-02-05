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

SERVERS=`fdns --list=all | grep -v https | grep -v zone | grep -v server | awk '{ print $1 }'`
for s in $SERVERS
do
	./wget.exp $s
	status=$?
	if test $status -eq 0
	then
		echo "OK"
	else
		sleep 1
		./wget.exp $s
	fi
	rm -f /tmp/index.html
done

#
# Start server and switch back to the regular user
#
echo "TESTING: starting user-level tests, please wait 5 seconds"
fdns --daemonize --server=cloudflare --workers=1
sleep 5
sudo -u $USER ./test-user.sh
pkill fdns
sleep 3
