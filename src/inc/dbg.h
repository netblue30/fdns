/*-
 * Written by Dridi Boukelmoune <dridi.boukelmoune@gmail.com>
 *
 * This file is in the public domain.
 */

#include <stdio.h>

#define DBG(fmt, ...)					\
	do {						\
		fprintf(stderr, "%s(%d): " fmt "\n",	\
		    __func__, __LINE__, __VA_ARGS__);	\
	} while (0)
