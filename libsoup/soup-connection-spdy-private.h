/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2013 Samsung Electronics Co., Ltd. All rights reserved.
 */

#ifndef SOUP_CONNECTION_SPDY_H
#define SOUP_CONNECTION_SPDY_H 1

#include <spindly/spindly.h>

#include "soup-types.h"
#include "soup-message-private.h"
#include "soup-misc.h"

G_BEGIN_DECLS

#define SOUP_TYPE_CONNECTION_SPDY            (soup_connection_spdy_get_type ())
#define SOUP_CONNECTION_SPDY(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SOUP_TYPE_CONNECTION_SPDY, SoupConnectionSpdy))
#define SOUP_CONNECTION_SPDY_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SOUP_TYPE_CONNECTION_SPDY, SoupConnectionSpdyClass))
#define SOUP_IS_CONNECTION_SPDY(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SOUP_TYPE_CONNECTION_SPDY))
#define SOUP_IS_CONNECTION_SPDY_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), SOUP_TYPE_CONNECTION_SPDY))
#define SOUP_CONNECTION_SPDY_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SOUP_TYPE_CONNECTION_SPDY, SoupConnectionSpdyClass))

struct _SoupConnectionSpdy {
	GObject parent;

};

typedef struct {
	GObjectClass parent_class;

	/* signals */
	void (*readable)       (SoupConnectionSpdy *);
	void (*writable)       (SoupConnectionSpdy *);

} SoupConnectionSpdyClass;

GType soup_connection_spdy_get_type (void);

#define SOUP_CONNECTION_SPDY_SOCKET			"socket"
#define SOUP_CONNECTION_SPDY_VERSION			"version"

typedef enum {
	SOUP_CONNECTION_SPDY_OK,
	SOUP_CONNECTION_SPDY_ERROR_NO_AVAILABLE_STREAM,
	SOUP_CONNECTION_SPDY_ERROR_INVALID_INPUT,
	SOUP_CONNECTION_SPDY_ERROR_UNKNOWN
} SoupConnectionSpdyError;

typedef enum {
	SOUP_CONNECTION_SPDY_VERSION_INVALID,
	SOUP_CONNECTION_SPDY_VERSION_HTTP1_1,
	SOUP_CONNECTION_SPDY_VERSION_SPDY2,
	SOUP_CONNECTION_SPDY_VERSION_SPDY3,
	SOUP_CONNECTION_SPDY_VERSION_LAST = SOUP_CONNECTION_SPDY_VERSION_SPDY3
} SoupConnectionSpdyVersion;

typedef void  (*SoupConnectionSpdyCallback)        (SoupConnectionSpdy   *spdy_conn, SoupMessage	*msg);
typedef SoupSpdyRecvState  (*SoupConnectionSpdyReadableCallback)        (SoupMessage	*msg, 		int stream_id, 		struct spindly_demux *spdy_demux);

SoupConnectionSpdy	*soup_connection_spdy_new						(const char			*propname1,
						...) G_GNUC_NULL_TERMINATED;

struct spindly_stream	*soup_connection_spdy_get_new_spdy_stream	(SoupConnectionSpdy			*spdy_conn,
																				SoupMessage				*msg,
																				gboolean			 		 has_body,
																				struct spindly_headers	*spdy_request_header,
																				SoupConnectionSpdyError	*error);
void 					soup_connection_spdy_register_msg (SoupConnectionSpdy   *spdy_conn,
																				SoupMessage	*msg,
																				SoupConnectionSpdyCallback writable_cb,
																				SoupConnectionSpdyReadableCallback readable_cb,
																				SoupConnectionSpdyCallback disconnected_cb);
void 					soup_connection_spdy_deregister_msg (SoupConnectionSpdy   *spdy_conn,
																				SoupMessage	*msg);

void 					soup_connection_spdy_deregister_msg_in_waiting_write (SoupConnectionSpdy   *spdy_conn,
																				SoupMessage	*msg);

void 					soup_connection_spdy_reregister_msg_in_waiting_write (SoupConnectionSpdy   *spdy_conn,
																				SoupMessage	*msg);

gboolean				soup_connection_spdy_spindly_stream_wndupdate	(SoupConnectionSpdy			*spdy_conn,
																				SoupMessage				*msg,
																				struct spindly_stream	*stream_client,
																				int							 wnd_update_len);

gboolean 				soup_connection_spdy_spindly_reset_stream 	(SoupConnectionSpdy			*spdy_conn,
																				SoupMessage	*msg,
																				struct spindly_stream *stream_client);


gboolean				 soup_connection_spdy_is_disconnected			(SoupConnectionSpdy			*spdy_conn);

int						 soup_connection_spdy_get_max_window_size			(SoupConnectionSpdy		*spdy_conn);
int						 soup_connection_spdy_get_max_concurrent_streams	(SoupConnectionSpdy		*spdy_conn);

// FIXME These functions are only medium for easy refactoring.
void soup_connection_spdy_set_connection (SoupConnectionSpdy *spdy_conn, SoupConnection *conn);

G_END_DECLS

#endif /* SOUP_CONNECTION_SPDY_H */
