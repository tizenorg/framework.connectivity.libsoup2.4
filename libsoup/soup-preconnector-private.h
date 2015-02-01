/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-preconnector-private.h:
 *
 * Copyright (C) 2012 Samsung Electronics.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public License
 * along with this library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

#ifndef SOUP_PRECONNECTOR_PRIVATE_H
#define SOUP_PRECONNECTOR_PRIVATE_H 1

#include <libsoup/soup-types.h>
#include <gio/gio.h>

G_BEGIN_DECLS

#define SOUP_TYPE_PRECONNECTOR            (soup_preconnector_get_type ())
#define SOUP_PRECONNECTOR(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SOUP_TYPE_PRECONNECTOR, SoupPreconnector))
#define SOUP_PRECONNECTOR_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SOUP_TYPE_PRECONNECTOR, SoupPreconnectorClass))
#define SOUP_IS_PRECONNECTOR(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SOUP_TYPE_PRECONNECTOR))
#define SOUP_IS_PRECONNECTOR_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), SOUP_TYPE_PRECONNECTOR))
#define SOUP_PRECONNECTOR_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SOUP_TYPE_PRECONNECTOR, SoupPreconnectorClass))

typedef struct _SoupPreconnector SoupPreconnector;
typedef struct _SoupPreconnectorPrivate SoupPreconnectorPrivate;

struct _SoupPreconnector {
	GObject parent_instance;

	SoupPreconnectorPrivate *priv;
};

typedef struct {
	GObjectClass parent_class;

} SoupPreconnectorClass;

typedef enum {
	SOUP_PRECONNECTOR_NOTIFY_TYPE_USE_CACHE,
	SOUP_PRECONNECTOR_NOTIFY_TYPE_CACHE_VALIDATION,
	SOUP_PRECONNECTOR_NOTIFY_TYPE_LOADING,
	SOUP_PRECONNECTOR_NOTIFY_TYPE_REDIRECTION
} SoupPreconnectorNotifyType;

GType             soup_preconnector_get_type            (void);
SoupPreconnector *soup_preconnector_new                 (const char *preconnector_dir);
void              soup_preconnector_notify      (SoupSession *session, SoupURI *uri, SoupPreconnectorNotifyType notify_type);
void              soup_preconnector_notify_redirect           (SoupSession *session, SoupURI *uri, SoupURI *redirected_uri);

void              soup_preconnector_load                (SoupPreconnector *preconnector);
void              soup_preconnector_dump                (SoupPreconnector *preconnector);

G_END_DECLS

#endif /* SOUP_PRECONNECTOR_PRIVATE_H */

