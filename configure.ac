#
# Note:
#
# If for any reason autoconf fails, run "autoreconf -i --install " and try again.
# This is how the error looks like on Arch Linux:
#        ./configure: line 3064: syntax error near unexpected token `newline'
#        ./configure: line 3064: `AX_CHECK_COMPILE_FLAG('
#
# We rely solely on autoconf, without automake. Apparently, in this case
# the macros from m4 directory are not picked up by default by automake.
# "autoreconf -i --install" seems to fix the problem.
#

AC_PREREQ([2.68])
AC_INIT(fdns, 0.9.62.8, netblue30@yahoo.com, , https://firejail.wordpress.com)
AC_CONFIG_SRCDIR([src/fdns/main.c])

AC_CONFIG_MACRO_DIR([m4])

AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_RANLIB

HAVE_SPECTRE="no"
AX_CHECK_COMPILE_FLAG(
    [-mindirect-branch=thunk],
    [HAVE_SPECTRE="yes" && EXTRA_CFLAGS+=" -mindirect-branch=thunk"]
)
AX_CHECK_COMPILE_FLAG(
    [-mretpoline],
    [HAVE_SPECTRE="yes" && EXTRA_CFLAGS+=" -mretpoline"]
)
AX_CHECK_COMPILE_FLAG(
    [-fstack-clash-protection],
    [EXTRA_CFLAGS+=" -fstack-clash-protection"]
)
AX_CHECK_COMPILE_FLAG(
    [-fstack-protector-strong],
    [EXTRA_CFLAGS+=" -fstack-protector-strong"]
)

AC_SUBST([EXTRA_CFLAGS])
AC_SUBST([EXTRA_LDFLAGS])

HAVE_FATAL_WARNINGS=""
AC_ARG_ENABLE([fatal_warnings],
    AS_HELP_STRING([--enable-fatal-warnings], [-W -Wall -Werror]))
AS_IF([test "x$enable_fatal_warnings" = "xyes"], [
	HAVE_FATAL_WARNINGS="-W -Wall -Werror"
	AC_SUBST(HAVE_FATAL_WARNINGS)
])

HAVE_GCOV=""
AC_ARG_ENABLE([gcov],
    AS_HELP_STRING([--enable-gcov], [Gcov instrumentation]))
AS_IF([test "x$enable_gcov" = "xyes"], [
	HAVE_GCOV="--coverage -DHAVE_GCOV "
	EXTRA_LDFLAGS+=" -lgcov --coverage "
	AC_SUBST(HAVE_GCOV)
])

# checking pthread library
AC_CHECK_LIB([pthread], [main], [], AC_MSG_ERROR([*** POSIX thread support not installed ***]))
AC_CHECK_HEADER(pthread.h,,AC_MSG_ERROR([*** POSIX thread support not installed ***]))

# bring in seccomp library
AC_CHECK_LIB([seccomp], [main], [], AC_MSG_ERROR([*** libseccomp not installed ***]))
AC_CHECK_HEADER(seccomp.h,,AC_MSG_ERROR([*** libseccomp development headers not installed ***]))
echo libseccomp library found
AX_CHECK_OPENSSL([
	echo OpenSSL library found], [
	AC_MSG_ERROR([*** OpenSSL development headers not installed - packages: libssl-dev (Debian/Ubuntu), openssl-devel (Fedora)  ***])
])

# set sysconfdir
if test "$prefix" = /usr; then
	test "$sysconfdir" = '${prefix}/etc' && sysconfdir="/etc"
fi

AC_OUTPUT(Makefile src/common.mk src/cashpack/Makefile src/fdns/Makefile test/src/fdnstress/Makefile)

echo
echo "Configuration options:"
echo "   prefix: $prefix"
echo "   sysconfdir: $sysconfdir"
echo "   Spectre compiler patch: $HAVE_SPECTRE"
echo "   EXTRA_LDFLAGS: $EXTRA_LDFLAGS"
echo "   EXTRA_CFLAGS: $EXTRA_CFLAGS"
echo "   fatal warnings: $HAVE_FATAL_WARNINGS"
echo "   Gcov instrumentation: $HAVE_GCOV"
echo
