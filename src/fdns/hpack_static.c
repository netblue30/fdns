/*
 * Copyright (C) 2019-2020 FDNS Authors
 *
 * This file is part of fdns project based on Dridi Boukelmoune implementation,
 * see below.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include "hpack_static.h"
#include <stdio.h>

static HpackStatic hps[] = {
	{"", ""}, 	// null entry 0
	{":authority",                  ""},
	{":method",                     "GET"},
	{":method",                     "POST"},
	{":path",                       "/"},
	{":path",                       "/index.html"},
	{":scheme",                     "http"},
	{":scheme",                     "https"},
	{":status",                     "200"},
	{":status",                     "204"},
	{":status",                     "206"},
	{":status",                     "304"},
	{":status",                     "400"},
	{":status",                     "404"},
	{":status",                     "500"},
	{"accept-charset",              ""},
	{"accept-encoding",             "gzip, deflate"},
	{"accept-language",             ""},
	{"accept-ranges",               ""},
	{"accept",                      ""},
	{"access-control-allow-origin", ""},
	{"age",                         ""},
	{"allow",                       ""},
	{"authorization",               ""},
	{"cache-control",               ""},
	{"content-disposition",         ""},
	{"content-encoding",            ""},
	{"content-language",            ""},
	{"content-length",              ""},
	{"content-location",            ""},
	{"content-range",               ""},
	{"content-type",                ""},
	{"cookie",                      ""},
	{"date",                        ""},
	{"etag",                        ""},
	{"expect",                      ""},
	{"expires",                     ""},
	{"from",                        ""},
	{"host",                        ""},
	{"if-match",                    ""},
	{"if-modified-since",           ""},
	{"if-none-match",               ""},
	{"if-range",                    ""},
	{"if-unmodified-since",         ""},
	{"last-modified",               ""},
	{"link",                        ""},
	{"location",                    ""},
	{"max-forwards",                ""},
	{"proxy-authenticate",          ""},
	{"proxy-authorization",         ""},
	{"range",                       ""},
	{"referer",                     ""},
	{"refresh",                     ""},
	{"retry-after",                 ""},
	{"server",                      ""},
	{"set-cookie",                  ""},
	{"strict-transport-security",   ""},
	{"transfer-encoding",           ""},
	{"user-agent",                  ""},
	{"vary",                        ""},
	{"via",                         ""},
	{"www-authenticate",            ""},
};

HpackStatic *hpack_static_get(unsigned id) {
	if (id <= 0 || id > sizeof(hps) / sizeof(HpackStatic))
		return NULL;
	return &hps[id];
}

