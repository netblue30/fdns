/*
 * Copyright (C) 2019-2021 FDNS Authors
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
/*-
 * Written by Dridi Boukelmoune <dridi.boukelmoune@gmail.com>
 *
 * This file is in the public domain.
 *
 * HPACK: Static Table Definition (RFC 7540 Appendix A)
 */
#ifndef HPACK_STATIC_H
#define HPACK_STATIC_H

typedef struct hpac_static_t {
	char * name;
	char *value;
} HpackStatic;

HpackStatic *hpack_static_get(unsigned id);

#endif
