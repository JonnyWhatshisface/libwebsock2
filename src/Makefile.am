LIBWEBSOCK_LIBRARY_VERSION=2:0:0
lib_LTLIBRARIES=libwebsock.la

if HAVE_SSL
libwebsock_la_SOURCES = api.c callbacks.c core.c utilities.c websock.c
else
libwebsock_la_SOURCES = api.c callbacks.c core.c utilities.c websock.c
endif

libwebsock_la_LDFLAGS = -version-info $(LIBWEBSOCK_LIBRARY_VERSION)
libwebsock_la_CFLAGS = -Wall -Wmissing-prototypes
library_includedir=$(includedir)
library_include_HEADERS = websock.h
ACLOCAL_AMFLAGS = -I m4
