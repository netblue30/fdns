#!/bin/bash


printf "<table>\n"
printf "<tr><th>tag<b> 🠗 </b> zone<b> ➜ </b></th><th>Europe</th><th>Asia<br />Pacific</th><th>East<br />America</th><th>West<br />America</th></tr>\n"

printf "<tr><td><b>sudo fdns</b></td>"
fdns --list=Europe | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
fdns --list=AsiaPacific | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
fdns --list=EastAmerica | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
fdns --list=WestAmerica | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
printf "</tr>\n"

printf "<tr><tr><td><b>sudo fdns --server=adblocker</b></td>\n"
fdns --list=adblocker --zone=Europe | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
fdns --list=adblocker --zone=AsiaPacific | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
fdns --list=adblocker --zone=EastAmerica | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
fdns --list=adblocker --zone=WestAmerica | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
printf "</tr>\n"

printf "<tr><td><b>sudo fdns --server=family</b></td>\n"
fdns --list=family --zone=Europe | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
fdns --list=family --zone=AsiaPacific | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
fdns --list=family --zone=EastAmerica | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
fdns --list=family --zone=WestAmerica | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
printf "</tr>\n"

printf "<tr><td><b>sudo fdns --server=non-profit</b></td>\n"
fdns --list=non-profit --zone=Europe | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
fdns --list=non-profit --zone=AsiaPacific | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
fdns --list=non-profit --zone=EastAmerica | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
fdns --list=non-profit --zone=WestAmerica | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
printf "</tr>\n"

printf "<tr><td><b>sudo fdns --server=OpenNIC</b></td>\n"
fdns --list=OpenNIC --zone=Europe | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
fdns --list=OpenNIC --zone=AsiaPacific | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
fdns --list=OpenNIC --zone=EastAmerica | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
fdns --list=OpenNIC --zone=WestAmerica | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
printf "</tr>\n"

printf "<tr><td><b>sudo fdns --server=security</b></td>\n"
fdns --list=security --zone=Europe | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
fdns --list=security --zone=AsiaPacific | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
fdns --list=security --zone=EastAmerica | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
fdns --list=security --zone=WestAmerica | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
printf "</tr>\n"

printf "<tr><td><b>sudo fdns --server=anycast</b></td>\n"
fdns --list=anycast --zone=Europe | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
fdns --list=anycast --zone=AsiaPacific | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
fdns --list=anycast --zone=EastAmerica | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
fdns --list=anycast --zone=WestAmerica | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
printf "</tr>\n"
printf "</table>\n"

