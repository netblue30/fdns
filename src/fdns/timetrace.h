/*
 * Copyright (C) 2019-2020 fdns Authors
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
#ifndef TIMETRACE_H
#define TIMETRACE_H


// rtdsc timestamp on x86-64/amd64  processors
static inline unsigned long long getticks(void) {
#if defined(__x86_64__)
	unsigned a, d;
	asm volatile("rdtsc" : "=a" (a), "=d" (d));
	return ((unsigned long long)a) | (((unsigned long long)d) << 32);
#elif defined(__i386__)
	unsigned long long ret;
	__asm__ __volatile__("rdtsc" : "=A" (ret));
	return ret;
#else
	return 0; // not implemented
#endif
}


void timetrace_start(void);
float timetrace_end(void);

#endif