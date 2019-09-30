/* 
 * Copyright (C) 2014-2019 fdns Authors
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

//**************************
// time trace based on getticks function
//**************************
static int tt_not_implemented = 0; // not implemented for the current architecture
static unsigned long long tt_1ms = 0;
static unsigned long long tt = 0;	// start time

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
