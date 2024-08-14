/*
 * Copyright (C) 2019-2021 FDNS Authors
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
static  int gm_delta = 0;
struct timespec start_time; // start time

// time difference in milliseconds
static inline float msdelta(struct timespec *end, struct timespec *start) {
	unsigned sec = end->tv_sec - start->tv_sec;
	long nsec = end->tv_nsec - start->tv_nsec;

	return (float) sec * 1000 + (float) nsec / 1000000;
}


void timetrace_start(void) {
	clock_gettime(CLOCK_MONOTONIC, &start_time);
}

float timetrace_end(void) {
	struct timespec end_time; // end time
	clock_gettime(CLOCK_MONOTONIC, &end_time);
	return msdelta(&end_time, &start_time);
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
	printf("%02u:%02u:%02u ", ts->tm_hour + gm_delta, ts->tm_min, ts->tm_sec);
}
