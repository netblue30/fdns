#!/bin/bash


printf "<table>\n"
printf "<tr><th>tag<b> 🠗 </b> zone<b> ➜ </b></th><th>Europe</th><th>Asia<br />Pacific</th><th>Americas<br />East</th><th>Americas<br />West</th></tr>\n"

printf "<tr><td><b>sudo fdns</b></td>"
fdns --list=Europe | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
fdns --list=Asia-Pacific | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
fdns --list=Americas-East | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
fdns --list=Americas-West | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
printf "</tr>\n"

printf "<tr><tr><td><b>sudo fdns --server=adblocker</b></td>\n"
fdns --list=adblocker --zone=Europe | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
fdns --list=adblocker --zone=Asia-Pacific | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
fdns --list=adblocker --zone=Americas-East | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
fdns --list=adblocker --zone=Americas-West | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
printf "</tr>\n"

printf "<tr><td><b>sudo fdns --server=family</b></td>\n"
fdns --list=family --zone=Europe | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
fdns --list=family --zone=Asia-Pacific | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
fdns --list=family --zone=Americas-East | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
fdns --list=family --zone=Americas-West | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
printf "</tr>\n"

printf "<tr><td><b>sudo fdns --server=non-profit</b></td>\n"
fdns --list=non-profit --zone=Europe | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
fdns --list=non-profit --zone=Asia-Pacific | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
fdns --list=non-profit --zone=Americas-East | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
fdns --list=non-profit --zone=Americas-West | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
printf "</tr>\n"

printf "<tr><td><b>sudo fdns --server=OpenNIC</b></td>\n"
fdns --list=OpenNIC --zone=Europe | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
fdns --list=OpenNIC --zone=Asia-Pacific | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
fdns --list=OpenNIC --zone=Americas-East | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
fdns --list=OpenNIC --zone=Americas-West | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
printf "</tr>\n"

printf "<tr><td><b>sudo fdns --server=security</b></td>\n"
fdns --list=security --zone=Europe | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
fdns --list=security --zone=Asia-Pacific | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
fdns --list=security --zone=Americas-East | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
fdns --list=security --zone=Americas-West | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
printf "</tr>\n"

printf "<tr><td><b>sudo fdns --server=anycast</b></td>\n"
fdns --list=anycast --zone=Europe | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
fdns --list=anycast --zone=Asia-Pacific | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
fdns --list=anycast --zone=Americas-East | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
fdns --list=anycast --zone=Americas-West | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
printf "</tr>\n"
printf "</table>\n"

