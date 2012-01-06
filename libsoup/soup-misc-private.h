/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright 2011 Igalia, S.L.
 * Copyright 2011 Red Hat, Inc.
 */

#ifndef SOUP_URI_PRIVATE_H
#define SOUP_URI_PRIVATE_H 1

#include "soup-socket.h"

char *uri_decoded_copy (const char *str, int length);

guint soup_socket_handshake_sync  (SoupSocket         *sock,
				   GCancellable       *cancellable);
void  soup_socket_handshake_async (SoupSocket         *sock,
				   GCancellable       *cancellable,
				   SoupSocketCallback  callback,
				   gpointer            user_data);

#endif /* SOUP_URI_PRIVATE_H */
