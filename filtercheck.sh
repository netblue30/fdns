#!/bin/bash

grep -n '127.0.0.1 ..$' `find etc -type f`
exit 0