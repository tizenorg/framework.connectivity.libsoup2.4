/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-socket-client-private.h:
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

#ifndef SOUP_SOCKET_CLIENT_PRIVATE_H
#define SOUP_SOCKET_CLIENT_PRIVATE_H 1

#include <gio/gio.h>
#include "soup-types.h"

G_BEGIN_DECLS

#define SOUP_TYPE_SOCKET_CLIENT            (soup_socket_client_get_type ())
#define SOUP_SOCKET_CLIENT(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SOUP_TYPE_SOCKET_CLIENT, SoupSocketClient))
#define SOUP_SOCKET_CLIENT_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SOUP_TYPE_SOCKET_CLIENT, SoupSocketClientClass))
#define SOUP_IS_SOCKET_CLIENT(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SOUP_TYPE_SOCKET_CLIENT))
#define SOUP_IS_SOCKET_CLIENT_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), SOUP_TYPE_SOCKET_CLIENT))
#define SOUP_SOCKET_CLIENT_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SOUP_TYPE_SOCKET_CLIENT, SoupSocketClientClass))

typedef struct _SoupSocketClient SoupSocketClient;
typedef struct _SoupSocketClientPrivate SoupSocketClientPrivate;

struct _SoupSocketClient {
	GObject parent_instance;

	SoupSocketClientPrivate *priv;
};

typedef struct {
	GObjectClass parent_class;

} SoupSocketClientClass;

GType             soup_socket_client_get_type            (void);

#define SOUP_SOCKET_CLIENT_TIMEOUT             "timeout"

SoupSocketClient *soup_socket_client_new                 (void);

guint                   soup_socket_client_get_timeout                     (SoupSocketClient        *client);
void                    soup_socket_client_set_timeout                     (SoupSocketClient        *client,
									 guint                 timeout);

void
soup_socket_client_connect_async (SoupSocketClient       *client,
			       GSocketConnectable  *connectable,
			       GCancellable        *cancellable,
			       GAsyncReadyCallback  callback,
			       gpointer             user_data);

GSocketConnection *
soup_socket_client_connect_finish (SoupSocketClient  *client,
				GAsyncResult   *result,
				GError        **error);

G_END_DECLS

#endif /* SOUP_SOCKET_CLIENT_PRIVATE_H */

