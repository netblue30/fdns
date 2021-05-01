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
# Config options for various distros:
#    - Debian: ./configure --prefix=/usr --enable-apparmor --with-systemd=/lib/systemd/system
#    - Fedora: ./configure --prefix=/usr --with-systemd=/usr/lib/systemd/system
#    - Arch:./configure --prefix=/usr --enable-apparmor --with-systemd=/usr/lib/systemd/system
#
# Run "pkg-config systemd --variable=systemdsystemunitdir" to find out where systemd unit
# files are stored on your system.


AC_PREREQ([2.68])
AC_INIT(fdns, 0.9.66, netblue30@protonmail.com, , https://firejaildns.wordpress.com)
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

HAVE_APPARMOR=""
AC_ARG_ENABLE([apparmor],
    AS_HELP_STRING([--enable-apparmor], [enable apparmor]))
AS_IF([test "x$enable_apparmor" = "xyes"], [
	HAVE_APPARMOR="-DHAVE_APPARMOR"
	AC_SUBST(HAVE_APPARMOR)
])

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

# bring in seccomp and openssl libraries
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

# set systemd unit file
SYSTEMD_DIR="$sysconfdir/fdns"
AC_ARG_WITH([systemd],
        AC_HELP_STRING([--with-systemd=DIR],
	[Pathname to systemd unit directory. Without this option, a copy of the unit file is installed in ${sysconfdir}/fdns directory]),
	[SYSTEMD_DIR="$withval"])
AC_SUBST(SYSTEMD_DIR)

AC_OUTPUT(Makefile src/common.mk src/fdns/Makefile src/nxdomain/Makefile test/src/fdnstress/Makefile)

echo
echo "Configuration options:"
echo "   prefix: $prefix"
echo "   sysconfdir: $sysconfdir"
echo "   systemd directory: $SYSTEMD_DIR"
echo "   Spectre compiler patch: $HAVE_SPECTRE"
echo "   apparmor: $HAVE_APPARMOR"
echo "   EXTRA_LDFLAGS: $EXTRA_LDFLAGS"
echo "   EXTRA_CFLAGS: $EXTRA_CFLAGS"
echo "   fatal warnings: $HAVE_FATAL_WARNINGS"
echo "   Gcov instrumentation: $HAVE_GCOV"
echo
