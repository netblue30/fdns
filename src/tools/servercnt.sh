#!/bin/bash

printf "\n*****\ndefault\n*****\n"
fdns --list=Europe | grep "servers found"  | awk '{print "Europe " $1}'
fdns --list=Americas-East | grep "servers found"  | awk '{print "Americas-East " $1}'
fdns --list=Americas-West | grep "servers found"  | awk '{print "Americas-West " $1}'
fdns --list=Asia-Pacific | grep "servers found"  | awk '{print "Asia-Pacific " $1}'

printf "\n*****\nadblocker\n*****\n"
fdns --list=adblocker --zone=Europe | grep "servers found"  | awk '{print "Europe " $1}'
fdns --list=adblocker --zone=Americas-East | grep "servers found"  | awk '{print "Americas-East " $1}'
fdns --list=adblocker --zone=Americas-West | grep "servers found"  | awk '{print "Americas-West " $1}'
fdns --list=adblocker --zone=Asia-Pacific | grep "servers found"  | awk '{print "Asia-Pacific " $1}'

printf "\n*****\nfamily\n*****\n"
fdns --list=family --zone=Europe | grep "servers found"  | awk '{print "Europe " $1}'
fdns --list=family --zone=Americas-East | grep "servers found"  | awk '{print "Americas-East " $1}'
fdns --list=family --zone=Americas-West | grep "servers found"  | awk '{print "Americas-West " $1}'
fdns --list=family --zone=Asia-Pacific | grep "servers found"  | awk '{print "Asia-Pacific " $1}'

printf "\n*****\nnon-profit\n*****\n"
fdns --list=non-profit --zone=Europe | grep "servers found"  | awk '{print "Europe " $1}'
fdns --list=non-profit --zone=Americas-East | grep "servers found"  | awk '{print "Americas-East " $1}'
fdns --list=non-profit --zone=Americas-West | grep "servers found"  | awk '{print "Americas-West " $1}'
fdns --list=non-profit --zone=Asia-Pacific | grep "servers found"  | awk '{print "Asia-Pacific " $1}'

printf "\n*****\nsecurity\n*****\n"
fdns --list=security --zone=Europe | grep "servers found"  | awk '{print "Europe " $1}'
fdns --list=security --zone=Americas-East | grep "servers found"  | awk '{print "Americas-East " $1}'
fdns --list=security --zone=Americas-West | grep "servers found"  | awk '{print "Americas-West " $1}'
fdns --list=security --zone=Asia-Pacific | grep "servers found"  | awk '{print "Asia-Pacific " $1}'

