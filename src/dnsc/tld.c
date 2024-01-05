/*
 * Copyright (C) 2019-2024 FDNS Authors
 *
 * This file is part of fdns project
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

#include "dnsc.h"
// https://ntldstats.com/tld
// https://interisle.net/PhishingLandscape2022.pdf
// https://www.spamhaus.org/statistics/tlds/
// https://en.wikipedia.org/wiki/.top
// https://unit42.paloaltonetworks.com/top-level-domains-cybercrime/
// https://en.wikipedia.org/wiki/GRS_Domains#gTLDs_managed
// https://www.techspot.com/news/97856-meta-suing-freenom-cybercriminals-favorite-domain-registrar.html
// https://en.wikipedia.org/wiki/.tk
// https://en.wikipedia.org/wiki/.cc
// kaperski - phishing attack timelife: https://securelist.com/phishing-page-life-cycle/105171/
// cfd: contracts for difference -> Clothing & Fashion Design
// sbs: Special Broadcasting Service (an Australian public-service broadcaster) -> side by side

typedef struct bnode_t {
	char *name;
	int len;
} BNode;

static BNode blacklist[] = {
//	{"app", 3},
//	{"dev", 3},
//	{"cloud", 5}, ... breaks rumble

	{"accountant", 10},
	{"am", 2},
	{"bazar", 5},
	{"best", 4},
	{"beauty", 6},
	{"bid", 3},
	{"boats", 5},
	{"bond", 4},
	{"buzz", 4},
	{"bd", 2},
	{"cam", 3},
	{"casa", 4},
	{"cd", 2},
	{"cf", 2},
	{"cfd", 3},
	{"club", 4},
	{"cm", 2},
	{"cn", 2},
	{"co.cc", 5},
	{"coin", 4},
	{"cricket", 7},
	{"cyou", 4},
	{"date", 4},
	{"degree", 6},
	{"download", 8},
	{"email", 5},
	{"faith", 5},
	{"fyi", 3},
	{"ga", 2},
	{"gq", 2},
	{"haus", 4},
	{"hair", 4},
	{"help", 4},
	{"icu", 3},
	{"ke", 2},
	{"link", 4},
	{"live", 4},
	{"loan", 4},
	{"men", 3},
	{"mov", 3},
	{"market", 6},
	{"makeup", 6},
	{"ml", 2},
	{"pw", 2},
	{"party", 5},
	{"quest", 5},
	{"rest", 4},
	{"racing",6},
	{"review", 6},
	{"rip", 3},
	{"rodeo", 5},
	{"sbs", 3},
	{"science", 7},
	{"stream", 6},
	{"su", 2},
	{"support", 7},
	{"tk", 2},
	{"tokyo", 5},
	{"top", 3},
	{"trade", 5},
	{"uno", 3},
	{"webcam", 6},
	{"win", 3},
	{"ws", 2},
	{"xyz", 3},
	{"zip", 3},
	{"zone", 4},
	{"zw", 2},
	{NULL, 0}
};

char *tld_find(const char *name) {
//printf("tld_find %s\n", name);
	int i = 0;
	int len = strlen(name);
	while (blacklist[i].name) {
		int delta = len - blacklist[i].len;
//printf("delta %d, %s len %d/%d\n", delta, blacklist[i].name, blacklist[i].len, len);
		if (delta == 0 && strcmp(name, blacklist[i].name) == 0)
			return blacklist[i].name;

		if (delta > 0 && strcmp(name + delta, blacklist[i].name) == 0) {
			if (name[delta - 1] == '.')
				return blacklist[i].name;
		}
		i++;
	}

	return NULL;
}

