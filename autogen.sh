#!/bin/sh
# Run this to generate all the initial makefiles, etc.

: ${AUTOCONF=autoconf}
: ${AUTOHEADER=autoheader}
: ${AUTOMAKE=automake}
: ${ACLOCAL=aclocal}
if test "$(uname -s)" != "Darwin"; then
: ${LIBTOOLIZE=libtoolize}
: ${LIBTOOL=libtool}
else
: ${LIBTOOLIZE=glibtoolize}
: ${LIBTOOL=glibtool}
fi

PROJECT=libwebsock
CONFIGURE=configure.ac

DIE=0

($AUTOCONF --version) < /dev/null > /dev/null 2>&1 || {
echo
echo "You must have autoconf installed to compile $PROJECT."
echo "Download the appropriate package for your distribution,"
echo "or get the source tarball at ftp://ftp.gnu.org/pub/gnu/"
DIE=1
}

($AUTOMAKE --version) < /dev/null > /dev/null 2>&1 || {
echo
echo "You must have automake installed to compile $PROJECT."
echo "Get ftp://sourceware.cygnus.com/pub/automake/automake-1.7.tar.gz"
echo "(or a newer version if it is available)"
DIE=1
}

if test "$(uname -s)" != "Darwin"; then
(grep "^AC_PROG_LIBTOOL" $CONFIGURE >/dev/null) && {
($LIBTOOL --version) < /dev/null > /dev/null 2>&1 || {
echo
echo "**Error**: You must have \`libtool' installed to compile $PROJECT."
echo "Get ftp://ftp.gnu.org/pub/gnu/libtool-1.4.tar.gz"
echo "(or a newer version if it is available)"
DIE=1
}
}
fi

if test "$DIE" -eq 1; then
exit 1
fi

if test x"$MSYSTEM" = x"MINGW32"; then
autoreconf --install -I/local/share/aclocal
elif test "$(uname -s)" = "Darwin"; then
autoreconf --install -I/opt/local/share/aclocal
else
autoreconf --install
fi
