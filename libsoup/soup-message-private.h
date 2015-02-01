/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifndef SOUP_MESSAGE_PRIVATE_H
#define SOUP_MESSAGE_PRIVATE_H 1

#include "soup-message.h"
#include "soup-auth.h"
#include "soup-content-sniffer.h"

// Need to wrap this code with ENABLE_TIZEN_SPDY, but just comment it because typedef is not able to wrap #ifdef
/* #if ENABLE_TIZEN_SPDY */
typedef enum {
	SPDY_MESSAGE_STATE_NOT_STARTED,
	SPDY_MESSAGE_STATE_HEADERS,
	SPDY_MESSAGE_STATE_BODY,
	SPDY_MESSAGE_STATE_BODY_FINISHED,
	SPDY_MESSAGE_STATE_SETTINGS,
	SPDY_MESSAGE_STATE_PING,
	SPDY_MESSAGE_STATE_WND_UPDATE,
	SPDY_MESSAGE_STATE_STREAM_REQ,
	SPDY_MESSAGE_STATE_GOAWAY,
	SPDY_MESSAGE_STATE_NONE
} SoupSpdyRecvState;
/* #endif */

typedef struct {
	gpointer           io_data;

	SoupChunkAllocator chunk_allocator;
	gpointer           chunk_allocator_data;
	GDestroyNotify     chunk_allocator_dnotify;

	guint              msg_flags;
	gboolean           server_side;

	SoupContentSniffer *sniffer;
	gsize              bytes_for_sniffing;

	SoupHTTPVersion    http_version, orig_http_version;

	SoupURI           *uri;
	SoupAddress       *addr;

	SoupAuth          *auth, *proxy_auth;

	GSList            *disabled_features;
	GSList            *decoders;

	SoupURI           *first_party;

	GTlsCertificate      *tls_certificate;
	GTlsCertificateFlags  tls_errors;

#if ENABLE_TIZEN_SPDY
	gboolean	is_sync_context;
	gboolean	is_spdy;
	SoupSpdyRecvState spdy_state;
#endif
} SoupMessagePrivate;
#define SOUP_MESSAGE_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), SOUP_TYPE_MESSAGE, SoupMessagePrivate))

void             soup_message_cleanup_response (SoupMessage      *req);


typedef void     (*SoupMessageGetHeadersFn)  (SoupMessage      *msg,
					      GString          *headers,
					      SoupEncoding     *encoding,
					      gpointer          user_data);
typedef guint    (*SoupMessageParseHeadersFn)(SoupMessage      *msg,
					      char             *headers,
					      guint             header_len,
					      SoupEncoding     *encoding,
					      gpointer          user_data);
typedef void     (*SoupMessageCompletionFn)  (SoupMessage      *msg,
					      gpointer          user_data);


void soup_message_send_request (SoupMessageQueueItem      *item,
				SoupMessageCompletionFn    completion_cb,
				gpointer                   user_data);
void soup_message_read_request (SoupMessage               *req,
				SoupSocket                *sock,
				SoupMessageCompletionFn    completion_cb,
				gpointer                   user_data);

void soup_message_io_client    (SoupMessageQueueItem      *item,
				SoupMessageGetHeadersFn    get_headers_cb,
				SoupMessageParseHeadersFn  parse_headers_cb,
				gpointer                   headers_data,
				SoupMessageCompletionFn    completion_cb,
				gpointer                   user_data);

//#if ENABLE_TIZEN_SPDY
gboolean soup_message_is_using_sync_context (SoupMessage *msg);
//#endif

void soup_message_io_server    (SoupMessage               *msg,
				SoupSocket                *sock,
				SoupMessageGetHeadersFn    get_headers_cb,
				SoupMessageParseHeadersFn  parse_headers_cb,
				gpointer                   headers_data,
				SoupMessageCompletionFn    completion_cb,
				gpointer                   user_data);
void soup_message_io_cleanup   (SoupMessage               *msg);

/* Auth handling */
void           soup_message_set_auth       (SoupMessage *msg,
					    SoupAuth    *auth);
SoupAuth      *soup_message_get_auth       (SoupMessage *msg);
void           soup_message_set_proxy_auth (SoupMessage *msg,
					    SoupAuth    *auth);
SoupAuth      *soup_message_get_proxy_auth (SoupMessage *msg);

/* I/O */
void                soup_message_io_stop        (SoupMessage          *msg);
void                soup_message_io_finished    (SoupMessage          *msg);
void                soup_message_io_pause       (SoupMessage          *msg);
void                soup_message_io_unpause     (SoupMessage          *msg);
gboolean            soup_message_io_in_progress (SoupMessage          *msg);

gboolean soup_message_disables_feature (SoupMessage *msg,
					gpointer     feature);

void soup_message_set_https_status (SoupMessage    *msg,
				    SoupConnection *conn);

void soup_message_network_event (SoupMessage         *msg,
				 GSocketClientEvent   event,
				 GIOStream           *connection);

// #if ENABL(TIZEN_CERTIFICATE_FILE_SET)
gboolean		soup_message_is_from_session_restore (SoupMessage *msg);
// #endif

#endif /* SOUP_MESSAGE_PRIVATE_H */
