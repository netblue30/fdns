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
#include "fdns.h"
#include "timetrace.h"

static LogMsg msg;
static int disabled = 0;

void log_disable(void) {
	disabled = 1;
}

// remote logging (resolver processes to frontend process)
void rlogprintf(const char *format, ...) {
	if (disabled)
//	if (arg_id == -1)
		return;

	// initialize packet
	memset(&msg, 0, sizeof(LogMsgHeader));

	// printf
	va_list valist;
	va_start(valist, format);
	vsnprintf(msg.buf, MAXBUF, format, valist);
	va_end(valist);

	// set packet size
	msg.h.len = sizeof(LogMsgHeader) + strlen(msg.buf) + 1; // + '\0'

	// send packet
	ssize_t rv = write(arg_fd, &msg, msg.h.len);
	if (rv == -1)
		errExit("write");

	fflush(0);
}

// local logging (monitor process)
void logprintf(const char *format, ...) {
	if (disabled)
		return;

	va_list valist;
	va_start(valist, format);

	print_time();
	vprintf(format, valist);

	va_end(valist);
	fflush(0);
}
