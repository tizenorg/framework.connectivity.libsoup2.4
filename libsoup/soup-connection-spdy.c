/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-connection-spdy.c: A single SPDY connection.
 *
 * Copyright (C) 2013 Samsung Electronics Co., Ltd. All rights reserved.
 */

// #if ENABLE_TIZEN_TURBO
#define LIBSOUP_USE_UNSTABLE_REQUEST_API
// #endif

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <glib.h>

#include "soup-connection.h"
#include "soup-connection-spdy-private.h"
#include "soup-marshal.h"
#include "soup-message-private.h"
#include "soup-message-queue.h"
#include "soup-socket.h"
#include "TIZEN.h"

// FIXME This RESPONSE_BLOCK_SIZE has same context with the one from soup-message-io.c. Should remove or refatoring later.
#define RESPONSE_BLOCK_SIZE 8192
#define INVALID_STREAM_ID	0

typedef struct {
	SoupMessage					*msg;
	uint32_t		 				 stream_id;
	SoupConnectionSpdyCallback	 writable_cb;
	SoupConnectionSpdyReadableCallback	 readable_cb;
	SoupConnectionSpdyCallback	 disconnected_cb;
} MsgData;

typedef struct {
	SoupSocket						*socket;
	SoupConnection				*conn;
	SoupConnectionSpdyVersion	 version;
	struct spindly_phys			*spdy_phys_client;
	gboolean						 is_disconnected;

	GHashTable						*msgs_using_this_spdy_conn; // list of MsgData, SoupMessage inside of MsgData is g_object_ref-ed, key is SoupMessage
	GHashTable						*msgs_in_active;	// list of MsgData, Key is stream_id.
	GSList							*msgs_in_waiting_write;		// list of MsgData.
	GSList							*msgs_in_waiting_stream_id;	// list of MsgData.

	GSource						*check_more_write_source;
	SoupSocketIOStatus			 socket_status;

	int max_window_size;
	int max_concurrent_streams;

	unsigned char		*spdy_packet;
	gsize				 spdy_packet_len;
	goffset			 spdy_packet_written;
} SoupConnectionSpdyPrivate;

#define SOUP_CONNECTION_SPDY_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), SOUP_TYPE_CONNECTION_SPDY, SoupConnectionSpdyPrivate))

G_DEFINE_TYPE (SoupConnectionSpdy, soup_connection_spdy, G_TYPE_OBJECT)

enum {
	READABLE,
	WRITABLE,
	// FIXME can use DISCONNECTED for handling GOAWAY?
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

enum {
	PROP_0,
	PROP_SOCKET,
	PROP_VERSION,
	LAST_PROP
};

static void set_property			(GObject *object, guint prop_id, const GValue *value, GParamSpec *pspec);
static void get_property			(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec);

static void got_readable			(SoupSocket *sock, SoupConnectionSpdy *spdy_conn);
static void got_writable			(SoupSocket *sock, SoupConnectionSpdy *spdy_conn);
static void socket_disconnected	(SoupSocket *sock, gpointer conn);

static gboolean			is_control_frame					(struct spindly_demux	*spdy_demux);
static SoupSpdyRecvState	handle_control_frame				(SoupConnectionSpdy		*spdy_conn,
																	struct spindly_demux	*spdy_demux);
static uint32_t					get_stream_id_from_spdy_demux	(struct spindly_demux	*spdy_demux);
static MsgData*		get_msg_data_for_stream_id		(SoupConnectionSpdy		*spdy_conn,
																	uint32_t					 stream_id);

static void				read_from_socket					(SoupSocket				*sock,
																	SoupConnectionSpdy	*spdy_conn);
static SoupSpdyRecvState	demux_data							(SoupConnectionSpdy		*spdy_conn,
																	SoupBuffer				*buffer);

static MsgData *			new_msg_data						(SoupMessage				*msg);
static void				destroy_msg_data					(MsgData					*msg_data);

static gboolean			do_write							(SoupConnectionSpdy		*spdy_conn);
static gboolean			check_more_write					(gpointer					 user_data);
static void				add_check_more_write_source		(SoupConnectionSpdy		*spdy_conn);
static void				clear_check_more_write_source	(SoupConnectionSpdy		*spdy_conn);
static void				check_waiting_stream_id_list	(SoupConnectionSpdy		*spdy_conn);

// FIXME
static void				spdy_send_settings (SoupConnectionSpdy *spdy_conn, unsigned int id, unsigned char flag, unsigned int value);

static void
prepare_to_use_socket (SoupConnectionSpdy *spdy_conn)
{
	SoupConnectionSpdyPrivate *priv = SOUP_CONNECTION_SPDY_GET_PRIVATE (spdy_conn);

	g_signal_connect (priv->socket, "readable", G_CALLBACK (got_readable), spdy_conn);
	g_signal_connect (priv->socket, "writable", G_CALLBACK (got_writable), spdy_conn);
	g_signal_connect (priv->socket, "disconnected", G_CALLBACK (socket_disconnected), spdy_conn);
}

static void
prepare_to_use_spindly (SoupConnectionSpdy *spdy_conn)
{
	SoupConnectionSpdyPrivate *priv = SOUP_CONNECTION_SPDY_GET_PRIVATE (spdy_conn);

	if (!priv->spdy_phys_client) {
		spindly_spdyver_t spindly_version;

		if (priv->version == SOUP_CONNECTION_SPDY_VERSION_SPDY2)
			spindly_version = SPINDLY_SPDYVER2;
		else if (priv->version == SOUP_CONNECTION_SPDY_VERSION_SPDY3)
			spindly_version = SPINDLY_SPDYVER3;
		else {
			TIZEN_LOGE ("spdy_conn[%p] no spindly version", spdy_conn);
			return;
		}

		priv->spdy_phys_client = spindly_phys_init (SPINDLY_SIDE_CLIENT, spindly_version, NULL);

		priv->max_window_size = 65536;
		priv->max_concurrent_streams = 20;

		if (priv->version == SOUP_CONNECTION_SPDY_VERSION_SPDY3) {
			spdy_send_settings (spdy_conn, SETTINGS_MAX_CONCURRENT_STREAMS, 0, priv->max_concurrent_streams);
			spdy_send_settings (spdy_conn, SETTINGS_INITIAL_WINDOW_SIZE, 0, priv->max_window_size);
		}
	}

	read_from_socket (priv->socket, spdy_conn);
	check_more_write (spdy_conn);

}
static void
soup_connection_spdy_init (SoupConnectionSpdy *spdy_conn)
{
	SoupConnectionSpdyPrivate *priv = SOUP_CONNECTION_SPDY_GET_PRIVATE (spdy_conn);
	priv->msgs_using_this_spdy_conn = g_hash_table_new_full (g_direct_hash, g_direct_equal, g_object_unref, (GDestroyNotify)destroy_msg_data);
	priv->msgs_in_active = g_hash_table_new (g_direct_hash, g_direct_equal);
}

static void
finalize (GObject *object)
{
	SoupConnectionSpdyPrivate *priv = SOUP_CONNECTION_SPDY_GET_PRIVATE (object);

	if (priv->socket) {
		g_signal_handlers_disconnect_by_func (priv->socket, got_readable, object);
		g_signal_handlers_disconnect_by_func (priv->socket, got_writable, object);
		g_signal_handlers_disconnect_by_func (priv->socket, socket_disconnected, object);

		g_object_unref (priv->socket);
		priv->socket = NULL;
	}

	g_hash_table_destroy (priv->msgs_in_active);
	priv->msgs_in_active = NULL;

	g_hash_table_destroy (priv->msgs_using_this_spdy_conn);
	priv->msgs_using_this_spdy_conn = NULL;

	if (priv->check_more_write_source)
		clear_check_more_write_source ((SoupConnectionSpdy *)object);

	if (priv->spdy_phys_client) {
		spindly_phys_cleanup (priv->spdy_phys_client);
		priv->spdy_phys_client = NULL;
	}

	G_OBJECT_CLASS (soup_connection_spdy_parent_class)->finalize (object);
}

static void
dispose (GObject *object)
{
	G_OBJECT_CLASS (soup_connection_spdy_parent_class)->dispose (object);
}

static void
soup_connection_spdy_class_init (SoupConnectionSpdyClass *spdy_connection_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (spdy_connection_class);

	g_type_class_add_private (spdy_connection_class, sizeof (SoupConnectionSpdyPrivate));

	/* virtual method override */
	object_class->dispose = dispose;
	object_class->finalize = finalize;
	object_class->set_property = set_property;
	object_class->get_property = get_property;

	/* signals */
	signals[READABLE] =
			g_signal_new ("readable",
			G_OBJECT_CLASS_TYPE (object_class),
			G_SIGNAL_RUN_LAST,
			G_STRUCT_OFFSET (SoupConnectionSpdyClass, readable),
			NULL, NULL,
			_soup_marshal_NONE__NONE,
			G_TYPE_NONE, 0);

	signals[WRITABLE] =
			g_signal_new ("writable",
			G_OBJECT_CLASS_TYPE (object_class),
			G_SIGNAL_RUN_LAST,
			G_STRUCT_OFFSET (SoupConnectionSpdyClass, writable),
			NULL, NULL,
			_soup_marshal_NONE__NONE,
			G_TYPE_NONE, 0);

	/* properties */
	g_object_class_install_property (
		object_class, PROP_SOCKET,
		g_param_spec_object (SOUP_CONNECTION_SPDY_SOCKET,
				     "SoupSocket",
				     "SoupSocket",
				     SOUP_TYPE_SOCKET,
				     G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
	g_object_class_install_property (
		object_class, PROP_VERSION,
		g_param_spec_int (SOUP_CONNECTION_SPDY_VERSION,
				"SPDY version",
				"SPDY version",
				0,
				SOUP_CONNECTION_SPDY_VERSION_LAST,
				SOUP_CONNECTION_SPDY_VERSION_INVALID,
				G_PARAM_READWRITE));
}

SoupConnectionSpdy *
soup_connection_spdy_new (const char *propname1, ...)
{
	SoupConnectionSpdy *spdy_conn;
	va_list ap;

	va_start (ap, propname1);
	spdy_conn = (SoupConnectionSpdy *)g_object_new_valist (SOUP_TYPE_CONNECTION_SPDY,
						      propname1, ap);
	va_end (ap);

	return spdy_conn;
}

static void
set_property (GObject *object, guint prop_id,
	      const GValue *value, GParamSpec *pspec)
{
	SoupConnectionSpdyPrivate *priv = SOUP_CONNECTION_SPDY_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_SOCKET:
		priv->socket = (SoupSocket *)g_value_dup_object (value);
		prepare_to_use_socket ((SoupConnectionSpdy *)object);
		TIZEN_LOGD("spdy_conn[%p] socket[%p]", object, priv->socket);
		break;
	case PROP_VERSION:
		priv->version = g_value_get_int (value);
		prepare_to_use_spindly ((SoupConnectionSpdy *)object);
		TIZEN_LOGD("spdy_conn[%p] version[%d]", object, priv->version);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
get_property (GObject *object, guint prop_id,
	      GValue *value, GParamSpec *pspec)
{
	SoupConnectionSpdyPrivate *priv = SOUP_CONNECTION_SPDY_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_SOCKET:
		g_value_set_object (value, priv->socket);
		break;
	case PROP_VERSION:
		g_value_set_int (value, priv->version);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

gboolean
do_write (SoupConnectionSpdy *spdy_conn)
{
	SoupConnectionSpdyPrivate *priv = SOUP_CONNECTION_SPDY_GET_PRIVATE (spdy_conn);
	spindly_error_t spint;
	gsize nwrote;
	GError *error = NULL;

	if (!spdy_conn || !priv)
		return FALSE;

	while (priv->socket_status == SOUP_SOCKET_OK) {
		if (!priv->spdy_packet) {
			spint = spindly_phys_outgoing (priv->spdy_phys_client, &priv->spdy_packet, &priv->spdy_packet_len);
			if (spint != SPINDLYE_OK)
				TIZEN_LOGD ("spdy_conn[%p] spint[%d] for spindly_phys_outgoing", spdy_conn, spint);
		}

		if (priv->spdy_packet_len) {
			// FIXME delete msg, take care of cancellable
			while (priv->spdy_packet_len > priv->spdy_packet_written) {
				priv->socket_status = soup_socket_write (priv->socket,
											priv->spdy_packet + priv->spdy_packet_written,
											priv->spdy_packet_len - priv->spdy_packet_written,
											&nwrote, NULL, &error);
				if (priv->socket_status == SOUP_SOCKET_OK) {
					priv->spdy_packet_written += nwrote;
				} else if (priv->socket_status == SOUP_SOCKET_WOULD_BLOCK) {
					return FALSE;
				} else {
					TIZEN_LOGD("spdy_conn[%p] socket_status[%d]", spdy_conn, priv->socket_status);
					return FALSE;
				}
			}
			spint = spindly_phys_sent (priv->spdy_phys_client, priv->spdy_packet_len);
			priv->spdy_packet = NULL;
			priv->spdy_packet_len = 0;
			priv->spdy_packet_written = 0;
		} else {
			break;
		}
	}

	return TRUE;
}

gboolean
check_more_write (gpointer user_data)
{
	SoupConnectionSpdy *spdy_conn = (SoupConnectionSpdy *)user_data;
	SoupConnectionSpdyPrivate *priv = SOUP_CONNECTION_SPDY_GET_PRIVATE (spdy_conn);
	gboolean can_write_more;
	GSList *list;

	if (!spdy_conn || !priv)
		return FALSE;

	list = priv->msgs_in_waiting_write;
	can_write_more = do_write (spdy_conn);

	while (list && can_write_more) {
		if (((MsgData*)list->data)->writable_cb)
			((MsgData*)list->data)->writable_cb (spdy_conn, ((MsgData*)list->data)->msg);

		can_write_more = do_write (spdy_conn);
		list = g_slist_next (list);
		// Act like circular queue
		if (!list)
			list = priv->msgs_in_waiting_write;
	}

	if (priv->socket_status == SOUP_SOCKET_WOULD_BLOCK) {
		priv->check_more_write_source = NULL;
		return FALSE;
	}

	if (!g_slist_length (priv->msgs_in_waiting_write)) {
		priv->check_more_write_source = NULL;
		return FALSE;
	}

	add_check_more_write_source (spdy_conn);

	return TRUE;
}

void
add_check_more_write_source (SoupConnectionSpdy *spdy_conn)
{
	SoupConnectionSpdyPrivate *priv = SOUP_CONNECTION_SPDY_GET_PRIVATE (spdy_conn);
	GMainContext *async_context;
	gboolean non_blocking, use_thread_context;

	if (!spdy_conn || !priv || priv->check_more_write_source)
		return;

	if (priv->socket_status == SOUP_SOCKET_WOULD_BLOCK)
		return;

	g_object_get (priv->socket,
		      SOUP_SOCKET_FLAG_NONBLOCKING, &non_blocking,
		      SOUP_SOCKET_USE_THREAD_CONTEXT, &use_thread_context,
		      NULL);
	if (use_thread_context)
		async_context = g_main_context_get_thread_default ();
	else {
		g_object_get (priv->socket,
			      SOUP_SOCKET_ASYNC_CONTEXT, &async_context,
			      NULL);
	}
	priv->check_more_write_source = soup_add_completion (
		async_context, check_more_write, spdy_conn);
}

void
clear_check_more_write_source (SoupConnectionSpdy *spdy_conn)
{
	SoupConnectionSpdyPrivate *priv = SOUP_CONNECTION_SPDY_GET_PRIVATE (spdy_conn);

	if (!spdy_conn || !priv || !priv->check_more_write_source)
		return;

	g_source_destroy (priv->check_more_write_source);
	priv->check_more_write_source = NULL;
}

void
got_readable (SoupSocket *sock, SoupConnectionSpdy *spdy_conn)
{
	read_from_socket (sock, spdy_conn);
	g_signal_emit (spdy_conn, signals[READABLE], 0);
}

void
got_writable (SoupSocket *sock, SoupConnectionSpdy *spdy_conn)
{
	SoupConnectionSpdyPrivate *priv = SOUP_CONNECTION_SPDY_GET_PRIVATE (spdy_conn);

	if (!spdy_conn || !priv)
		return;

	if (priv->socket_status == SOUP_SOCKET_WOULD_BLOCK)
		priv->socket_status = SOUP_SOCKET_OK;

	check_more_write (spdy_conn);
}

static void
call_msg_finished (gpointer key, gpointer value, gpointer user_data)
{
	MsgData *msg_data = (MsgData*) value;
	SoupConnectionSpdy* spdy_conn = (SoupConnectionSpdy*) user_data;

	msg_data->disconnected_cb (spdy_conn, msg_data->msg);
}

static void
clear_messages_from_connection (SoupConnectionSpdy *spdy_conn)
{
	SoupConnectionSpdyPrivate *priv = SOUP_CONNECTION_SPDY_GET_PRIVATE (spdy_conn);
	if (!spdy_conn || !priv)
		return;

	g_hash_table_foreach (priv->msgs_using_this_spdy_conn, call_msg_finished, spdy_conn);
}

void
socket_disconnected (SoupSocket *sock, gpointer spdy_conn)
{
	SoupConnectionSpdyPrivate *priv = SOUP_CONNECTION_SPDY_GET_PRIVATE (spdy_conn);

	if (!spdy_conn || !priv)
		return;

	if (sock != priv->socket)
		return;

	if (priv->socket) {
		g_signal_handlers_disconnect_by_func (priv->socket, got_readable, spdy_conn);
		g_signal_handlers_disconnect_by_func (priv->socket, got_writable, spdy_conn);
		g_signal_handlers_disconnect_by_func (priv->socket, socket_disconnected, spdy_conn);

		g_object_unref (priv->socket);
		priv->socket = NULL;
	}
}

gboolean
is_control_frame (struct spindly_demux *spdy_demux)
{
	if (!spdy_demux)
		return FALSE;

	switch (spdy_demux->type) {
	case SPINDLY_DX_STREAM_KILL:
	case SPINDLY_DX_GOAWAY:
	case SPINDLY_DX_SETTINGS:
	case SPINDLY_DX_PING:
		return TRUE;
	default:
		return FALSE;
	}
}

static void
set_spdy_settings(SoupConnectionSpdy *spdy_conn, struct spindly_iv_block* settings)
{
	int i;
	SoupConnectionSpdyPrivate *priv = SOUP_CONNECTION_SPDY_GET_PRIVATE (spdy_conn);

	if (!priv)
		return;

	for(i = 0; i < settings->count; i++) {
		if(settings->pairs[i].id == SETTINGS_INITIAL_WINDOW_SIZE) {
			priv->max_window_size = settings->pairs[i].value;
			TIZEN_LOGD ("spdy_conn[%p] max_window_size[%d]", spdy_conn, priv->max_window_size);
		} else if(settings->pairs[i].id == SETTINGS_MAX_CONCURRENT_STREAMS) {
			priv->max_concurrent_streams = settings->pairs[i].value;
			TIZEN_LOGD ("spdy_conn[%p] max_concurrent_streams[%d]", spdy_conn, priv->max_concurrent_streams);
		}
	}
}

SoupSpdyRecvState
handle_control_frame (SoupConnectionSpdy *spdy_conn, struct spindly_demux *spdy_demux)
{
	SoupConnectionSpdyPrivate *priv = SOUP_CONNECTION_SPDY_GET_PRIVATE (spdy_conn);

	if (!spdy_demux || !priv)
		return SPDY_MESSAGE_STATE_NONE;

	switch (spdy_demux->type) {
	case SPINDLY_DX_STREAM_KILL:
	case SPINDLY_DX_GOAWAY:
		TIZEN_LOGD ("SPINDLY_DX_GOAWAY spdy_conn[%p] stream_id[%d]", spdy_conn, get_stream_id_from_spdy_demux(spdy_demux));
		priv->is_disconnected = TRUE;
		clear_messages_from_connection (spdy_conn);
		soup_connection_disconnect (priv->conn);
		return SPDY_MESSAGE_STATE_GOAWAY;
	break;

	case SPINDLY_DX_SETTINGS:
		TIZEN_LOGD ("SPINDLY_DX_SETTINGS spdy_conn[%p]", spdy_conn);
		set_spdy_settings(spdy_conn, &(spdy_demux->msg.settings));
		return SPDY_MESSAGE_STATE_SETTINGS;
	break;

	case SPINDLY_DX_PING:
		TIZEN_LOGD ("SPINDLY_DX_PING spdy_conn[%p]", spdy_conn);
		return SPDY_MESSAGE_STATE_PING;
	break;
	default:
		TIZEN_LOGD("spdy_conn[%p] spdy_demux->type[%d]", spdy_conn, spdy_demux->type);
		return SPDY_MESSAGE_STATE_NONE;
	}
}

uint32_t
get_stream_id_from_spdy_demux (struct spindly_demux *spdy_demux)
{
	if (!spdy_demux)
		return INVALID_STREAM_ID;

	switch (spdy_demux->type) {
	case SPINDLY_DX_GOAWAY:            /* struct spindly_dx_goaway */
		return spdy_demux->msg.goaway.stream_id;

	case SPINDLY_DX_RST_STREAM:            /* struct spindly_dx_rst_stream */
		return spdy_demux->msg.rst_stream.stream_id;

	case SPINDLY_DX_STREAM_ACK:        /* struct spindly_dx_ack_stream */
		return spdy_demux->msg.stream_ack.streamid;

	case SPINDLY_DX_STREAM_REQ:        /* struct spindly_dx_stream */
	case SPINDLY_DX_STREAM_KILL:       /* struct spindly_dx_stream */
		return spdy_demux->msg.stream.streamid;

	case SPINDLY_DX_PING:              /* struct spindly_dx_ping */
		return spdy_demux->msg.ping.stream_id;

	case SPINDLY_DX_DATA:              /* struct spindly_dx_data */
		return spdy_demux->msg.data.streamid;

	case SPINDLY_DX_HEADERS:           /* struct spindly_dx_headers */
		return spdy_demux->msg.headers.streamid;

	case SPINDLY_DX_WND_UPDATE:              /* struct spindly_dx_wnd */
		return spdy_demux->msg.wnd.stream_id;

	case SPINDLY_DX_SETTINGS:          /* spindly_iv_block */
	case SPINDLY_DX_NOOP:              /* NO struct, just ignore it */
	default:
		return INVALID_STREAM_ID;
	}
}

MsgData*
get_msg_data_for_stream_id (SoupConnectionSpdy *spdy_conn, uint32_t stream_id)
{
	SoupConnectionSpdyPrivate *priv = SOUP_CONNECTION_SPDY_GET_PRIVATE (spdy_conn);
	MsgData *msg_data;
	if (stream_id == INVALID_STREAM_ID || !spdy_conn || !priv)
		return NULL;

	msg_data = g_hash_table_lookup (priv->msgs_in_active, (gconstpointer) stream_id);
	if (msg_data)
		return msg_data;

	return NULL;
}

SoupSpdyRecvState
demux_data (SoupConnectionSpdy *spdy_conn, SoupBuffer *buffer)
{
	SoupConnectionSpdyPrivate *priv = SOUP_CONNECTION_SPDY_GET_PRIVATE (spdy_conn);
	SoupSpdyRecvState spdy_state = SPDY_MESSAGE_STATE_NONE;
	spindly_error_t spint = SPINDLYE_OK;
	struct spindly_demux spdy_demux;

	if (!spdy_conn || !priv) {
		TIZEN_LOGE("spdy_conn[%p] priv[%p]", spdy_conn, priv);
		return spdy_state;
	}

	spint = spindly_phys_incoming (priv->spdy_phys_client,
				(unsigned char *)buffer->data,
				buffer->length,
				SPINDLY_INCOMING_COPY, NULL);

	if (spint != SPINDLYE_OK) {
		TIZEN_LOGE ("io_spdy_demux spint %d \n", spint);
		return spdy_state;
	}

	do {
			/*
			 * io->read_length will be decreased in soup_message_recv_spdy_response
			 * after demux and decode.
			 */
		memset(&spdy_demux, 0, sizeof(spdy_demux));
		TIZEN_LOGD ("calling spindly_phys_demux \n");
		spint = spindly_phys_demux (priv->spdy_phys_client, &spdy_demux);

		if ((spint >= SPINDLYE_PROTOCOL_ERROR) && (spint <= SPINDLYE_SESSION_ERROR)) {
			TIZEN_LOGE ("SPINDLYE_ERROR type=%d\n", spint);
			spindly_free_demux(priv->spdy_phys_client, &spdy_demux);
			break;
		}

		if (spdy_demux.type == SPINDLY_DX_NONE) {
			spindly_free_demux(priv->spdy_phys_client, &spdy_demux);
			break;
		}

		if (is_control_frame (&spdy_demux)) {
			spdy_state = handle_control_frame (spdy_conn, &spdy_demux);

		} else {
			uint32_t stream_id = INVALID_STREAM_ID;
			MsgData *msg_data = NULL;

			stream_id = get_stream_id_from_spdy_demux (&spdy_demux);
			msg_data = get_msg_data_for_stream_id (spdy_conn, stream_id);
			if (!msg_data) {
				TIZEN_LOGE ("msg_data is NULL spdy_conn[%p] stream_id[%d]", spdy_conn, stream_id);
				spindly_free_demux(priv->spdy_phys_client, &spdy_demux);
				break;
			}
			spdy_state = msg_data->readable_cb (msg_data->msg, stream_id, &spdy_demux);
		}

		spindly_free_demux(priv->spdy_phys_client, &spdy_demux);

		// FIXME This is lousy. Need more beautiful handling for spdy_state.
		if (spdy_state == SPDY_MESSAGE_STATE_GOAWAY)
			break;
	} while (spdy_state != SPDY_MESSAGE_STATE_NONE);

	return spdy_state;
}

void
read_from_socket (SoupSocket *sock, SoupConnectionSpdy *spdy_conn)
{
	SoupSocketIOStatus status = SOUP_SOCKET_OK;
	guchar *stack_buf = NULL;
	gsize nread = 0;
	GError *error = NULL;
	SoupBuffer *buffer = NULL;
	SoupSpdyRecvState spdyState = SPDY_MESSAGE_STATE_NOT_STARTED;

	// FIXME Those two lines are medium for easy refactoring, so removed later.
	SoupConnectionSpdyPrivate *priv = SOUP_CONNECTION_SPDY_GET_PRIVATE (spdy_conn);
	SoupConnection *conn = priv->conn;

read_spdy_more:
	if(!stack_buf)
		stack_buf = alloca (RESPONSE_BLOCK_SIZE);

	buffer = soup_buffer_new (SOUP_MEMORY_TEMPORARY,
							stack_buf,
							RESPONSE_BLOCK_SIZE);
	if (!buffer) {
		TIZEN_LOGE ("spdy_conn[%p] sock[%p] conn[%p] buffer from soup_buffer_new is NULL", spdy_conn, sock, conn);
		return;
	}

	/* Since buffer will contain the spdy frame,
	* the buffer size should not be limited to io->read_length,
	* which is the html content length.
	*/
	status = soup_socket_read (sock,
					(guchar *)buffer->data, buffer->length,
					&nread, NULL, &error);

	if (status == SOUP_SOCKET_OK && nread) {
		buffer->length = nread;

		spdyState = demux_data (spdy_conn, buffer);
	}

	/* Free soup buffer */
	soup_buffer_free (buffer);
	buffer = NULL;

	switch (status) {
	case SOUP_SOCKET_OK:
		if (spdyState == SPDY_MESSAGE_STATE_GOAWAY) {
			TIZEN_LOGD ("spdy_conn[%p] sock[%p] conn[%p] SPDY_MESSAGE_STATE_GOAWAY", spdy_conn, sock, conn);
			return;
		} else {
			if(nread > 0)
				goto read_spdy_more;
		}
		break;

	case SOUP_SOCKET_ERROR:
		TIZEN_LOGD ("spdy_conn[%p] sock[%p] conn[%p] SOUP_SOCKET_ERROR", spdy_conn, sock, conn);
		// FIXME need function like disconnect and cleanup.
		priv->is_disconnected = TRUE;
		clear_messages_from_connection (spdy_conn);
		soup_connection_disconnect (priv->conn);
		return;

	case SOUP_SOCKET_EOF:
		return;

	case SOUP_SOCKET_WOULD_BLOCK:
		return;
	}

	return;
}

MsgData *
new_msg_data (SoupMessage *msg)
{
	MsgData *msg_data = g_slice_new0 (MsgData);
	msg_data->msg = msg;
	return msg_data;
}

void
destroy_msg_data (MsgData *msg_data)
{
	g_slice_free (MsgData, msg_data);
}

void
check_waiting_stream_id_list (SoupConnectionSpdy *spdy_conn)
{
	SoupConnectionSpdyPrivate *priv = SOUP_CONNECTION_SPDY_GET_PRIVATE (spdy_conn);
	gsize count_available_slot;

	if (!spdy_conn || !priv)
		return;

	if (!priv->msgs_in_waiting_stream_id)
		return;

	count_available_slot = priv->max_concurrent_streams - g_hash_table_size (priv->msgs_in_active);
	if (count_available_slot < 1)
		return;

	while (count_available_slot && priv->msgs_in_waiting_stream_id) {
		GSList *list = priv->msgs_in_waiting_stream_id;
		MsgData* msg_data = list->data;

		count_available_slot--;

		msg_data->writable_cb(spdy_conn, msg_data->msg);
	}
}

struct spindly_stream *
soup_connection_spdy_get_new_spdy_stream (SoupConnectionSpdy			*spdy_conn,
																				SoupMessage				*msg,
																				gboolean			 		 has_body,
																				struct spindly_headers	*spdy_request_header,
																				SoupConnectionSpdyError	*error)
{
	SoupConnectionSpdyPrivate *priv = SOUP_CONNECTION_SPDY_GET_PRIVATE (spdy_conn);
	spindly_error_t spint;
	struct spindly_stream *spdy_stream_client;
	MsgData *msg_data;

	if (!spdy_conn || !priv || !msg || !spdy_request_header) {
		if (error)
			*error = SOUP_CONNECTION_SPDY_ERROR_INVALID_INPUT;
		return NULL;
	}

	msg_data = g_hash_table_lookup (priv->msgs_using_this_spdy_conn, msg);
	if(!msg_data) {
		TIZEN_LOGE ("spdy_conn[%p] msg[%p] No Message available to create a new spdy stream",
				spdy_conn, msg);
		if (error)
			*error = SOUP_CONNECTION_SPDY_ERROR_INVALID_INPUT;
		return NULL;
	}

	if (g_hash_table_size (priv->msgs_in_active) >= priv->max_concurrent_streams) {
		TIZEN_LOGD ("spdy_conn[%p] msg[%p] reject because of max concurrent stream is fullmax[%d]",
				spdy_conn, msg, g_hash_table_size (priv->msgs_in_active));
		if (error)
			*error = SOUP_CONNECTION_SPDY_ERROR_NO_AVAILABLE_STREAM;
		priv->msgs_in_waiting_stream_id = g_slist_append (priv->msgs_in_waiting_stream_id, msg_data);
		return NULL;
	}

	spint = spindly_stream_new (priv->spdy_phys_client,
									has_body? 0 : SPINDLY_DATA_FLAGS_FIN, 0,
									&spdy_stream_client, NULL, NULL, spdy_request_header);

	if (spint != SPINDLYE_OK) {
		TIZEN_LOGE ("spdy_conn[%p] msg[%p] spint[%d]", spdy_conn, msg, spint);
		if (error)
			*error = SOUP_CONNECTION_SPDY_ERROR_UNKNOWN;
		return NULL;
	}

	msg_data->stream_id = spindly_stream_get_stream_id (spdy_stream_client);
	g_hash_table_insert (priv->msgs_in_active, (gpointer)msg_data->stream_id, msg_data);

	priv->msgs_in_waiting_stream_id = g_slist_remove (priv->msgs_in_waiting_stream_id, msg_data);
	priv->msgs_in_waiting_write = g_slist_append (priv->msgs_in_waiting_write, msg_data);
	add_check_more_write_source (spdy_conn);

	if (error)
		*error = SOUP_CONNECTION_SPDY_OK;
	return spdy_stream_client;
}

static void
clear_spdy_stream (SoupConnectionSpdy *spdy_conn, MsgData *msg_data)
{
	SoupConnectionSpdyPrivate *priv = SOUP_CONNECTION_SPDY_GET_PRIVATE (spdy_conn);

	if (!spdy_conn || !priv || !msg_data)
		return;

	g_hash_table_remove (priv->msgs_in_active, (gconstpointer)msg_data->stream_id);
	priv->msgs_in_waiting_write = g_slist_remove (priv->msgs_in_waiting_write, msg_data);
	priv->msgs_in_waiting_stream_id = g_slist_remove (priv->msgs_in_waiting_stream_id, msg_data);
	g_hash_table_remove (priv->msgs_using_this_spdy_conn, msg_data->msg);
	check_waiting_stream_id_list (spdy_conn);
}

void
soup_connection_spdy_register_msg (SoupConnectionSpdy   *spdy_conn,
													SoupMessage	*msg,
													SoupConnectionSpdyCallback writable_cb,
													SoupConnectionSpdyReadableCallback readable_cb,
													SoupConnectionSpdyCallback disconnected_cb)
{
	SoupConnectionSpdyPrivate *priv = SOUP_CONNECTION_SPDY_GET_PRIVATE (spdy_conn);
	MsgData *msg_data;

	if (!spdy_conn || !priv)
		return;

	msg_data = new_msg_data (msg);
	g_hash_table_insert (priv->msgs_using_this_spdy_conn, g_object_ref (msg), msg_data);

	msg_data->writable_cb = writable_cb;
	msg_data->readable_cb = readable_cb;
	msg_data->disconnected_cb = disconnected_cb;
}

void
soup_connection_spdy_deregister_msg (SoupConnectionSpdy   *spdy_conn,
													SoupMessage	*msg)
{
	SoupConnectionSpdyPrivate *priv = SOUP_CONNECTION_SPDY_GET_PRIVATE (spdy_conn);
	MsgData *msg_data;

	if (!spdy_conn || !priv || !msg)
		return;

	msg_data = g_hash_table_lookup (priv->msgs_using_this_spdy_conn, msg);
	if (!msg_data)
		return;

	msg_data->writable_cb = NULL;
	msg_data->readable_cb = NULL;
	msg_data->disconnected_cb = NULL;
	
	// FIX ME clear_spdy_strem here is correct ?
	clear_spdy_stream (spdy_conn, msg_data);
}

void
soup_connection_spdy_deregister_msg_in_waiting_write (SoupConnectionSpdy   *spdy_conn,
													SoupMessage	*msg)
{
	SoupConnectionSpdyPrivate *priv = SOUP_CONNECTION_SPDY_GET_PRIVATE (spdy_conn);
	MsgData *msg_data;

	if (!spdy_conn || !priv || !msg)
		return;

	msg_data = g_hash_table_lookup (priv->msgs_using_this_spdy_conn, msg);
	if (!msg_data) {
		TIZEN_LOGE ("spdy_conn[%p] msg[%p] no msg_data", spdy_conn, msg);
		return;
	}

	priv->msgs_in_waiting_write = g_slist_remove (priv->msgs_in_waiting_write, msg_data);
}

void
soup_connection_spdy_reregister_msg_in_waiting_write (SoupConnectionSpdy   *spdy_conn,
													SoupMessage	*msg)
{
	SoupConnectionSpdyPrivate *priv = SOUP_CONNECTION_SPDY_GET_PRIVATE (spdy_conn);
	MsgData *msg_data;

	if (!spdy_conn || !priv || !msg)
		return;

	msg_data = g_hash_table_lookup (priv->msgs_using_this_spdy_conn, msg);
	if (!msg_data) {
		TIZEN_LOGE ("spdy_conn[%p] msg[%p] no msg_data", spdy_conn, msg);
		return;
	}
	if(!g_slist_find(priv->msgs_in_waiting_write, msg_data)) {
		priv->msgs_in_waiting_write = g_slist_append (priv->msgs_in_waiting_write, msg_data);
		add_check_more_write_source (spdy_conn);
	}
}

gboolean soup_connection_spdy_spindly_stream_wndupdate (SoupConnectionSpdy	*spdy_conn,
																SoupMessage	*msg,
																struct spindly_stream *stream_client,
																int wnd_update_len)
{
	spindly_error_t spint;

	spint = spindly_stream_wndupdate (stream_client, wnd_update_len);
	if (spint != SPINDLYE_OK) {
		TIZEN_LOGE ("spdy_conn[%p] msg[%p] spindly_stream_wndupdate spint[%d]", spdy_conn, msg, spint);
		return FALSE;
	}

	add_check_more_write_source (spdy_conn);
	return TRUE;
}

gboolean soup_connection_spdy_spindly_reset_stream (SoupConnectionSpdy	*spdy_conn,
																SoupMessage	*msg,
																struct spindly_stream *stream_client)
{
	spindly_error_t spint;

	spint = spindly_stream_nack (stream_client, SPINDLYE_CANCEL);
	if (spint != SPINDLYE_OK) {
		TIZEN_LOGE ("spdy_conn[%p] msg[%p] stream_client[%p] spindly_reset_stream spint[%d]", spdy_conn, msg, stream_client, spint);
		return FALSE;
	}

	add_check_more_write_source (spdy_conn);
	return TRUE;
}

gboolean
soup_connection_spdy_is_disconnected (SoupConnectionSpdy	*spdy_conn)
{
	SoupConnectionSpdyPrivate *priv = SOUP_CONNECTION_SPDY_GET_PRIVATE (spdy_conn);

	if (!spdy_conn || !priv)
		return TRUE;

	if (priv->is_disconnected)
		return TRUE;

	return FALSE;
}

// FIXME These functions are only medium for easy refactoring.
void
soup_connection_spdy_set_connection (SoupConnectionSpdy *spdy_conn, SoupConnection *conn)
{
	SoupConnectionSpdyPrivate *priv = SOUP_CONNECTION_SPDY_GET_PRIVATE (spdy_conn);

	if (!spdy_conn || !priv)
		return;

	priv->conn = conn;
}

void
spdy_send_settings(SoupConnectionSpdy *spdy_conn, unsigned int id, unsigned char flag, unsigned int value)
{

	SoupConnectionSpdyPrivate *priv = SOUP_CONNECTION_SPDY_GET_PRIVATE (spdy_conn);

	spindly_iv_block iv_block;
	spindly_iv_pair* iv_pair = NULL;

	if (!priv)
		return;

	if (priv->version != SOUP_CONNECTION_SPDY_VERSION_SPDY3)
		return;

	if (!priv->spdy_phys_client)
		return;

	iv_pair = malloc(sizeof(spindly_iv_pair));

	iv_block.count = 1;

	iv_pair->id = id;
	iv_pair->flag = flag;
	iv_pair->value = value;

	iv_block.pairs = iv_pair;

	spindly_phys_settings(priv->spdy_phys_client, &iv_block);

	// FIXME I think iv_pair should be freed here.
}

int
soup_connection_spdy_get_max_window_size (SoupConnectionSpdy *spdy_conn)
{
	SoupConnectionSpdyPrivate *priv = SOUP_CONNECTION_SPDY_GET_PRIVATE (spdy_conn);
	return priv->max_window_size;
}

int
soup_connection_spdy_get_max_concurrent_streams (SoupConnectionSpdy *spdy_conn)
{
	SoupConnectionSpdyPrivate *priv = SOUP_CONNECTION_SPDY_GET_PRIVATE (spdy_conn);
	return priv->max_concurrent_streams;
}
