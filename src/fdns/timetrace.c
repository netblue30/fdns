/*
 * Copyright (C) 2019-2020 FDNS Authors
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
#include "timetrace.h"
#include <assert.h>
#include <unistd.h>
#include <time.h>
#include <stdio.h>

//**************************
// time trace based on getticks function
//**************************
static int tt_not_implemented = 0; // not implemented for the current architecture
static unsigned long long tt_1ms = 0;
static unsigned long long tt = 0;	// start time
static  int gm_delta = 0;

void timetrace_start(void) {
	if (tt_not_implemented)
		return;
	unsigned long long t1 = getticks();
	if (t1 == 0) {
		tt_not_implemented = 1;
		return;
	}

	if (tt_1ms == 0) {
		usleep(1000);	// sleep 1 ms
		unsigned long long t2 = getticks();
		tt_1ms = t2 - t1;
		if (tt_1ms == 0) {
			tt_not_implemented = 1;
			return;
		}
	}

	tt = getticks();
}

float timetrace_end(void) {
	if (tt_not_implemented)
		return 0;

	unsigned long long delta = getticks() - tt;
	assert(tt_1ms);

	return (float) delta / (float) tt_1ms;
}

// calculate GMT / local time difference
void init_time_delta(void) {
	time_t t = time(NULL);
	struct tm *ts =gmtime(&t);
	int gmh = ts->tm_hour;
	ts =localtime(&t);
	gm_delta = ts->tm_hour - gmh;
}

// print a timestamp - local time
void print_time(void) {
	time_t t = time(NULL);
	struct tm *ts =gmtime(&t);
	printf("%02d:%02d:%02d ", ts->tm_hour + gm_delta, ts->tm_min, ts->tm_sec);
}
