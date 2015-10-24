/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifndef SOUP_SESSION_PRIVATE_H
#define SOUP_SESSION_PRIVATE_H 1

#include "soup-session.h"
#include "soup-message-private.h"
#include "soup-proxy-uri-resolver.h"
#include "TIZEN.h"

G_BEGIN_DECLS

/* "protected" methods for subclasses */
SoupMessageQueue     *soup_session_get_queue            (SoupSession          *session);

SoupMessageQueueItem *soup_session_append_queue_item    (SoupSession          *session,
							 SoupMessage          *msg,
							 gboolean              async,
							 gboolean              new_api,
							 SoupSessionCallback   callback,
							 gpointer              user_data);

void                  soup_session_kick_queue           (SoupSession          *session);

GInputStream         *soup_session_send_request         (SoupSession          *session,
							 SoupMessage          *msg,
							 GCancellable         *cancellable,
							 GError              **error);

void                  soup_session_send_request_async   (SoupSession          *session,
							 SoupMessage          *msg,
							 GCancellable         *cancellable,
							 GAsyncReadyCallback   callback,
							 gpointer              user_data);
GInputStream         *soup_session_send_request_finish  (SoupSession          *session,
							 GAsyncResult         *result,
							 GError              **error);

void                  soup_session_process_queue_item   (SoupSession          *session,
							 SoupMessageQueueItem *item,
							 gboolean             *should_prune,
							 gboolean              loop);

#if ENABLE(TIZEN_CERTIFICATE_FILE_SET)
void			soup_session_set_certificate_file (SoupSession  *session);
void 			soup_session_tls_start_idle_timer (SoupSession *session, guint idle_timeout);
void 			soup_session_tls_stop_idle_timer (SoupSession *session);
gboolean		soup_session_is_tls_db_initialized (SoupSession* session);
#endif
#if ENABLE(TIZEN_TV_CREATE_IDLE_TCP_CONNECTION)
guint                 soup_session_get_idle_connection_for_host      (SoupSession  *session,
		                                                 SoupURI      *uri);
#endif

G_END_DECLS

#endif /* SOUP_SESSION_PRIVATE_H */
