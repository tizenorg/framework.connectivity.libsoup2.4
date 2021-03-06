## Process this file with automake to produce Makefile.in

include $(GLIB_MAKEFILE)

if OS_WIN32
LIBWS2_32 = -lws2_32
endif

INCLUDES = 				\
	-DG_LOG_DOMAIN=\"libsoup\" 	\
	-I$(top_srcdir)			\
	$(SOUP_DEBUG_FLAGS)		\
	$(SOUP_MAINTAINER_FLAGS)	\
	$(GLIB_CFLAGS)			\
	$(XML_CFLAGS)			\
	$(SQLITE_CFLAGS)		\
	$(GNOME_KEYRING_CFLAGS)

libsoupincludedir = $(includedir)/libsoup-2.4/libsoup

soup_headers =			\
	soup.h			\
	soup-address.h		\
	soup-auth.h		\
	soup-auth-domain.h	\
	soup-auth-domain-basic.h  \
	soup-auth-domain-digest.h \
	soup-cache.h		\
	soup-content-decoder.h	\
	soup-content-sniffer.h	\
	soup-cookie.h		\
	soup-cookie-jar.h	\
	soup-cookie-jar-text.h	\
	soup-date.h		\
	soup-form.h		\
	soup-headers.h		\
	soup-logger.h		\
	soup-message.h		\
	soup-message-body.h	\
	soup-message-headers.h	\
	soup-method.h		\
	soup-misc.h     	\
	soup-multipart.h     	\
	soup-password-manager.h	\
	soup-portability.h	\
	soup-proxy-resolver.h	\
	soup-proxy-resolver-default.h	\
	soup-proxy-uri-resolver.h \
	soup-request.h		\
	soup-request-data.h	\
	soup-request-file.h	\
	soup-request-http.h	\
	soup-requester.h	\
	soup-server.h		\
	soup-session.h		\
	soup-session-async.h	\
	soup-session-feature.h	\
	soup-session-sync.h	\
	soup-socket.h		\
	soup-status.h		\
	soup-types.h		\
	soup-uri.h		\
	soup-value-utils.h	\
	soup-xmlrpc.h

if SQLLITE_SUPPORT
soup_headers +=		\
	soup-cookie-jar-sqlite.h
endif

libsoupinclude_HEADERS =	\
	$(soup_headers)		\
	soup-enum-types.h

lib_LTLIBRARIES = libsoup-2.4.la

libsoup_2_4_la_LDFLAGS =	\
	-version-info $(SOUP_CURRENT):$(SOUP_REVISION):$(SOUP_AGE) -no-undefined

libsoup_2_4_la_LIBADD =			\
	$(GLIB_LIBS)			\
	$(XML_LIBS)			\
	-lz				\
	$(LIBWS2_32)

if SQLLITE_SUPPORT
libsoup_2_4_la_LIBADD +=		\
	$(SQLITE_LIBS)
endif

libsoup_2_4_la_SOURCES =		\
	soup-address.c			\
	soup-auth.c			\
	soup-auth-basic.h		\
	soup-auth-basic.c		\
	soup-auth-digest.h		\
	soup-auth-digest.c		\
	soup-auth-ntlm.h		\
	soup-auth-ntlm.c		\
	soup-auth-domain.c		\
	soup-auth-domain-basic.c	\
	soup-auth-domain-digest.c	\
	soup-auth-manager.h		\
	soup-auth-manager.c		\
	soup-auth-manager-ntlm.h	\
	soup-auth-manager-ntlm.c	\
	soup-cache.c			\
	soup-cache-private.h		\
	soup-connection.h		\
	soup-connection.c		\
	soup-content-decoder.c		\
	soup-content-sniffer.c		\
	soup-cookie.c			\
	soup-cookie-jar.c		\
	soup-cookie-jar-text.c		\
	soup-date.c			\
	soup-directory-input-stream.h	\
	soup-directory-input-stream.c	\
	soup-enum-types.h		\
	soup-enum-types.c		\
	soup-form.c			\
	soup-headers.c			\
	soup-http-input-stream.h	\
	soup-http-input-stream.c	\
	soup-logger.c			\
	soup-marshal.h			\
	soup-marshal.c			\
	soup-message.c			\
	soup-message-body.c		\
	soup-message-client-io.c	\
	soup-message-headers.c		\
	soup-message-io.c		\
	soup-message-private.h		\
	soup-message-queue.h		\
	soup-message-queue.c		\
	soup-message-server-io.c	\
	soup-method.c     		\
	soup-misc.c     		\
	soup-misc-private.h		\
	soup-multipart.c	     	\
	soup-password-manager.c		\
	soup-path-map.h     		\
	soup-path-map.c     		\
	soup-proxy-resolver.c		\
	soup-proxy-resolver-default.c	\
	soup-proxy-resolver-static.h	\
	soup-proxy-resolver-static.c	\
	soup-proxy-uri-resolver.c	\
	soup-request.c			\
	soup-request-data.c		\
	soup-request-file.c		\
	soup-request-http.c		\
	soup-requester.c		\
	soup-server.c			\
	soup-session.c			\
	soup-session-async.c		\
	soup-session-feature.c		\
	soup-session-private.h		\
	soup-session-sync.c		\
	soup-socket.c			\
	soup-status.c			\
	soup-uri.c			\
	soup-value-utils.c		\
	soup-xmlrpc.c

if SQLLITE_SUPPORT
libsoup_2_4_la_SOURCES +=		\
	soup-cookie-jar-sqlite.c
endif

if BUILD_LIBSOUP_GNOME

if OS_WIN32
soup_password_manager_gnome_files =	
else
soup_password_manager_gnome_files =	\
	soup-password-manager-gnome.h	\
	soup-password-manager-gnome.c
endif

libsoupgnomeincludedir = $(includedir)/libsoup-gnome-2.4/libsoup

libsoupgnomeinclude_HEADERS =	\
	soup-cookie-jar-sqlite.h\
	soup-gnome.h		\
	soup-gnome-features.h

lib_LTLIBRARIES += libsoup-gnome-2.4.la

libsoup_gnome_2_4_la_LDFLAGS = $(libsoup_2_4_la_LDFLAGS)

libsoup_gnome_2_4_la_LIBADD =		\
	libsoup-2.4.la			\
	$(GLIB_LIBS)			\
	$(SQLITE_LIBS)			\
	$(GNOME_KEYRING_LIBS)

libsoup_gnome_2_4_la_SOURCES =		\
	soup-cookie-jar-sqlite.c	\
	soup-gnome-features.c		\
	soup-proxy-resolver-gnome.h	\
	soup-proxy-resolver-gnome.c	\
	$(soup_password_manager_gnome_files)

endif

GLIB_GENERATED = soup-marshal.c soup-marshal.h
GLIB_GENERATED += soup-enum-types.c soup-enum-types.h
BUILT_SOURCES = $(GLIB_GENERATED)

soup_marshal_sources = $(libsoup_2_4_la_SOURCES) $(libsoup_gnome_2_4_la_SOURCES)
soup_enum_types_sources = $(libsoupinclude_HEADERS) $(libsoupgnomeinclude_HEADERS)
soup_enum_types_MKENUMS_C_FLAGS = --fhead "\#define LIBSOUP_USE_UNSTABLE_REQUEST_API"

#
# Introspection support
#
include $(INTROSPECTION_MAKEFILE)
INTROSPECTION_GIRS =
INTROSPECTION_SCANNER_ARGS = --add-include-path=.
INTROSPECTION_COMPILER_ARGS = --includedir=.

if HAVE_INTROSPECTION

# Core library
gi_soup_files = \
	$(filter-out soup.h soup-enum-types.% soup-marshal.% soup-proxy-resolver.h,\
	   $(soup_headers) $(filter-out %.h, $(libsoup_2_4_la_SOURCES)))
gi_built_soup_files = soup-enum-types.h

Soup-2.4.gir: libsoup-2.4.la
Soup_2_4_gir_INCLUDES = Gio-2.0
Soup_2_4_gir_CFLAGS = $(INCLUDES)
Soup_2_4_gir_LIBS = libsoup-2.4.la
Soup_2_4_gir_EXPORT_PACKAGES = libsoup-2.4
Soup_2_4_gir_SCANNERFLAGS = --c-include "libsoup/soup.h"
Soup_2_4_gir_FILES = \
	$(addprefix $(srcdir)/, $(gi_soup_files)) \
        $(foreach f,$(gi_built_soup_files), \
	   $(if $(shell test -f $(addprefix $(srcdir)/,$(f)) && echo yes), \
	      $(addprefix $(srcdir)/,$(f)), \
	      $(f)))

INTROSPECTION_GIRS += Soup-2.4.gir

if BUILD_LIBSOUP_GNOME

# GNOME extensions
gi_soup_gnome_files = $(filter-out soup-gnome.h,\
		          $(libsoupgnomeinclude_HEADERS) \
	                  $(filter-out %.h, $(libsoup_gnome_2_4_la_SOURCES)))
SoupGNOME-2.4.gir: libsoup-gnome-2.4.la Soup-2.4.gir
SoupGNOME_2_4_gir_SCANNERFLAGS =			\
	--identifier-prefix=Soup			\
	--symbol-prefix=soup				\
	--c-include "libsoup/soup-gnome.h"		\
	--include-uninstalled=$(builddir)/Soup-2.4.gir
SoupGNOME_2_4_gir_CFLAGS = $(INCLUDES)
SoupGNOME_2_4_gir_LIBS = libsoup-gnome-2.4.la libsoup-2.4.la
SoupGNOME_2_4_gir_FILES = $(addprefix $(srcdir)/,$(gi_soup_gnome_files))
SoupGNOME_2_4_gir_EXPORT_PACKAGES = libsoup-gnome-2.4

INTROSPECTION_GIRS += SoupGNOME-2.4.gir

endif

girdir = $(datadir)/gir-1.0
gir_DATA = $(INTROSPECTION_GIRS)

typelibdir = $(libdir)/girepository-1.0
typelib_DATA = $(INTROSPECTION_GIRS:.gir=.typelib)

CLEANFILES = $(gir_DATA) $(typelib_DATA)

endif
