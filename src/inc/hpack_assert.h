/*-
 * Written by Dridi Boukelmoune <dridi.boukelmoune@gmail.com>
 *
 * This file is in the public domain.
 */

#ifdef NDEBUG
#define WRONG(str)		\
	do {			\
		abort();	\
	} while (0)
#else
#define WRONG(str)		\
	do {			\
		assert(!str);	\
	} while (0)
#endif

#define INCOMPL()	WRONG("Incomplete code")
