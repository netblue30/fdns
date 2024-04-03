#!/bin/bash

grep -n '127.0.0.1 ..$' `find etc/blocklists/list.*`
exit 0