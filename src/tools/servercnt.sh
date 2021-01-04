#
# Copyright (C) 2019-2021 FDNS Authors
#
# This file is part of fdns project
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
#!/bin/bash


printf "<table>\n"
printf "<tr><th>tag<b> 🠗 </b> zone<b> ➜ </b></th><th>Europe</th><th>Asia<br />Pacific</th><th>East<br />Americas</th></tr>\n"

printf "<tr><td><b>sudo fdns</b></td>"
fdns --list=Europe | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
fdns --list=AsiaPacific | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
fdns --list=EastAmerica | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
fdns --list=WestAmerica | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
printf "</tr>\n"

printf "<tr><tr><td><b>sudo fdns --server=adblocker</b></td>\n"
fdns --list=adblocker --zone=Europe | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
fdns --list=adblocker --zone=AsiaPacific | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
fdns --list=adblocker --zone=Americas | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
printf "</tr>\n"

printf "<tr><td><b>sudo fdns --server=family</b></td>\n"
fdns --list=family --zone=Europe | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
fdns --list=family --zone=AsiaPacific | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
fdns --list=family --zone=Americas | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
printf "</tr>\n"

printf "<tr><td><b>sudo fdns --server=non-profit</b></td>\n"
fdns --list=non-profit --zone=Europe | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
fdns --list=non-profit --zone=AsiaPacific | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
fdns --list=non-profit --zone=Americas | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
printf "</tr>\n"

printf "<tr><td><b>sudo fdns --server=OpenNIC</b></td>\n"
fdns --list=OpenNIC --zone=Europe | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
fdns --list=OpenNIC --zone=AsiaPacific | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
fdns --list=OpenNIC --zone=Americas | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
printf "</tr>\n"

printf "<tr><td><b>sudo fdns --server=security</b></td>\n"
fdns --list=security --zone=Europe | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
fdns --list=security --zone=AsiaPacific | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
fdns --list=security --zone=Americas | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
printf "</tr>\n"

printf "<tr><td><b>sudo fdns --server=anycast</b></td>\n"
fdns --list=anycast --zone=Europe | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
fdns --list=anycast --zone=AsiaPacific | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
fdns --list=anycast --zone=Americas | grep "servers found"  | awk '{print "<td>" $1 "</td>"}'
printf "</tr>\n"
printf "</table>\n"

