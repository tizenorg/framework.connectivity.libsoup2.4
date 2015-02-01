/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-message-io-spdy.c: HTTP message I/O for SPDY
 *
 * Copyright (C) 2013 Samsung Electronics Co., Ltd. All rights reserved.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>

#include "soup-connection-spdy-private.h"
#include "soup-message-io-spdy-private.h"
#include "soup-message-private.h"
#include "soup-message-queue.h"
#include "TIZEN.h"

// FIXME Following headers should be removed sooner or later
#include "soup-connection.h"
#include "soup-session-private.h"
#include "soup-socket.h"
#include "soup-uri.h"

#define SOUP_MESSAGE_IO_PREPARE_FOR_CALLBACK { gboolean cancelled; g_object_ref (msg);
#define SOUP_MESSAGE_IO_RETURN_IF_CANCELLED_OR_PAUSED cancelled = (priv->io_data != io); g_object_unref (msg); if (cancelled) return; }
#define SOUP_MESSAGE_IO_RETURN_VAL_IF_CANCELLED_OR_PAUSED(val) cancelled = (priv->io_data != io); g_object_unref (msg); if (cancelled) return val; }

// FIXME This RESPONSE_BLOCK_SIZE has same context with the one from soup-message-io.c. Should remove or refatoring later.
#define RESPONSE_BLOCK_SIZE 8192
#define SPDY_FRAME_HEADER_SIZE 8
#define DEFAULT_WRITE_CHUNK_SIZE (16384 - SPDY_FRAME_HEADER_SIZE) // 16K - SPDY_FRAME_HEADER_SIZE

typedef enum {
	SOUP_MESSAGE_IO_CLIENT,
	SOUP_MESSAGE_IO_SERVER,
} SoupMessageIOMode;

typedef enum {
	SOUP_MESSAGE_IO_STATE_NOT_STARTED,
	SOUP_MESSAGE_IO_STATE_HEADERS,
	SOUP_MESSAGE_IO_STATE_BLOCKING,
	SOUP_MESSAGE_IO_STATE_BODY,
	SOUP_MESSAGE_IO_STATE_CHUNK_SIZE,
	SOUP_MESSAGE_IO_STATE_CHUNK,
	SOUP_MESSAGE_IO_STATE_CHUNK_END,
	SOUP_MESSAGE_IO_STATE_TRAILERS,
	SOUP_MESSAGE_IO_STATE_FINISHING,
	SOUP_MESSAGE_IO_STATE_DONE
} SoupMessageIOState;

typedef struct {
	SoupConnectionSpdy	*spdy_conn;
	SoupMessageQueueItem *item;
	SoupMessageIOMode     mode;
	GCancellable         *cancellable;

	struct spindly_stream	*spdy_stream_client;
	struct spindly_headers	*spdy_request_header;

	SoupMessageIOState    read_state;
	SoupEncoding          read_encoding;
	GByteArray           *read_meta_buf;
	SoupMessageBody      *read_body;
	goffset               read_length;
	gboolean              read_eof_ok;

	gboolean              need_content_sniffed, need_got_chunk;
	SoupMessageBody      *sniff_data;

	SoupMessageIOState    write_state;
	SoupEncoding          write_encoding;
	SoupMessageBody      *write_body;
	SoupBuffer           *write_chunk;
	goffset               write_body_offset;
	goffset               write_length;

	gsize					 spdy_body_offset;
	gsize					 spdy_wnd_remaining_size;

	SoupMessageParseHeadersFn parse_headers_cb;
	gpointer                  header_data;
	SoupMessageCompletionFn   completion_cb;
	gpointer                  completion_data;
} SoupMessageIOSpdyData;

static void parse_spdy_header (struct spindly_headers *header, GByteArray *out);
static void io_spdy_write (SoupConnectionSpdy *spdy_conn, SoupMessage *msg);
static void soup_message_io_spdy_disconnected (SoupConnectionSpdy *spdy_conn, SoupMessage *msg);
static SoupSpdyRecvState soup_message_parse_spdy_response (SoupMessage *msg, int stream_id, struct spindly_demux *spdy_demux);

static void
cancel_handler (GCancellable *cancellable,
			    gpointer       user_data)
{
	SoupMessage *msg = SOUP_MESSAGE (user_data);

	TIZEN_LOGD ("msg[%p]", msg);
}

static gboolean
io_handle_sniffing (SoupMessage *msg, gboolean done_reading)
{
	SoupMessagePrivate *priv = SOUP_MESSAGE_GET_PRIVATE (msg);
	SoupMessageIOSpdyData *io = priv->io_data;
	SoupBuffer *sniffed_buffer;
	char *sniffed_mime_type;
	GHashTable *params = NULL;

	if (!priv->sniffer)
		return TRUE;

	if (!io->sniff_data) {
		io->sniff_data = soup_message_body_new ();
		io->need_content_sniffed = TRUE;
	}

	if (io->need_content_sniffed) {
		if (io->sniff_data->length < priv->bytes_for_sniffing &&
		    !done_reading)
			return TRUE;

		io->need_content_sniffed = FALSE;
		sniffed_buffer = soup_message_body_flatten (io->sniff_data);
		sniffed_mime_type = soup_content_sniffer_sniff (priv->sniffer, msg, sniffed_buffer, &params);

		SOUP_MESSAGE_IO_PREPARE_FOR_CALLBACK;
		soup_message_content_sniffed (msg, sniffed_mime_type, params);
		g_free (sniffed_mime_type);
		if (params)
			g_hash_table_destroy (params);
		if (sniffed_buffer)
			soup_buffer_free (sniffed_buffer);
		SOUP_MESSAGE_IO_RETURN_VAL_IF_CANCELLED_OR_PAUSED (FALSE);
	}

	if (io->need_got_chunk) {
		io->need_got_chunk = FALSE;
		sniffed_buffer = soup_message_body_flatten (io->sniff_data);

		SOUP_MESSAGE_IO_PREPARE_FOR_CALLBACK;
		soup_message_got_chunk (msg, sniffed_buffer);
		soup_buffer_free (sniffed_buffer);
		SOUP_MESSAGE_IO_RETURN_VAL_IF_CANCELLED_OR_PAUSED (FALSE);
	}

	return TRUE;
}

static SoupBuffer *
content_decode_one (SoupBuffer *buf, GConverter *converter, GError **error)
{
	gsize outbuf_length, outbuf_used, outbuf_cur, input_used, input_cur;
	char *outbuf;
	GConverterResult result;
	gboolean dummy_zlib_header_used = FALSE;

	outbuf_length = MAX (buf->length * 2, 1024);
	outbuf = g_malloc (outbuf_length);
	outbuf_cur = input_cur = 0;

	do {
		result = g_converter_convert (
			converter,
			buf->data + input_cur, buf->length - input_cur,
			outbuf + outbuf_cur, outbuf_length - outbuf_cur,
			0, &input_used, &outbuf_used, error);
		input_cur += input_used;
		outbuf_cur += outbuf_used;

		if (g_error_matches (*error, G_IO_ERROR, G_IO_ERROR_NO_SPACE) ||
		    (!*error && outbuf_cur == outbuf_length)) {
			g_clear_error (error);
			outbuf_length *= 2;
			outbuf = g_realloc (outbuf, outbuf_length);
		} else if (input_cur == 0 &&
			   !dummy_zlib_header_used &&
			   G_IS_ZLIB_DECOMPRESSOR (converter) &&
			   g_error_matches (*error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA)) {

			GZlibCompressorFormat format;
			g_object_get (G_OBJECT (converter), "format", &format, NULL);

			if (format == G_ZLIB_COMPRESSOR_FORMAT_ZLIB) {
				/* Some servers (especially Apache with mod_deflate)
				 * return RAW compressed data without the zlib headers
				 * when the client claims to support deflate. For
				 * those cases use a dummy header (stolen from
				 * Mozilla's nsHTTPCompressConv.cpp) and try to
				 * continue uncompressing data.
				 */
				static char dummy_zlib_header[2] = { 0x78, 0x9C };

				g_converter_reset (converter);
				result = g_converter_convert (converter,
							      dummy_zlib_header, sizeof(dummy_zlib_header),
							      outbuf + outbuf_cur, outbuf_length - outbuf_cur,
							      0, &input_used, &outbuf_used, NULL);
				dummy_zlib_header_used = TRUE;
				if (result == G_CONVERTER_CONVERTED) {
					g_clear_error (error);
					continue;
				}
			}

			g_free (outbuf);
			return NULL;

		} else if (*error) {
			/* GZlibDecompressor can't ever return
			 * G_IO_ERROR_PARTIAL_INPUT unless we pass it
			 * input_length = 0, which we don't. Other
			 * converters might of course, so eventually
			 * this code needs to be rewritten to deal
			 * with that.
			 */
			g_free (outbuf);
			return NULL;
		}
	} while (input_cur < buf->length && result != G_CONVERTER_FINISHED);

	if (outbuf_cur)
		return soup_buffer_new (SOUP_MEMORY_TAKE, outbuf, outbuf_cur);
	else {
		g_free (outbuf);
		return NULL;
	}
}

static SoupBuffer *
content_decode (SoupMessage *msg, SoupBuffer *buf)
{
	SoupMessagePrivate *priv = SOUP_MESSAGE_GET_PRIVATE (msg);
	GConverter *decoder;
	SoupBuffer *decoded;
	GError *error = NULL;
	GSList *d;

	for (d = priv->decoders; d; d = d->next) {
		decoder = d->data;

		decoded = content_decode_one (buf, decoder, &error);
		if (error) {
			if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_FAILED))
				g_warning ("Content-Decoding error: %s\n", error->message);
			g_error_free (error);

			soup_message_set_flags (msg, priv->msg_flags & ~SOUP_MESSAGE_CONTENT_DECODED);
			break;
		}
		if (buf)
			soup_buffer_free (buf);

		if (decoded)
			buf = decoded;
		else
			return NULL;
	}

	return buf;
}

static SoupSpdyRecvState
handle_stream_req (SoupMessage *msg, int stream_id, struct spindly_demux *spdy_demux)
{
	return SPDY_MESSAGE_STATE_NONE;
}

static SoupSpdyRecvState
handle_stream_ack (SoupMessage *msg, int stream_id, struct spindly_demux *spdy_demux)
{
	struct spindly_headers *header = NULL;
	SoupMessagePrivate *priv = NULL;
	SoupMessageIOSpdyData *io = NULL;
	guint status = 0;
	SoupSpdyRecvState spdy_state = SPDY_MESSAGE_STATE_NOT_STARTED;

	priv = SOUP_MESSAGE_GET_PRIVATE (msg);
	if (!priv) {
		return SPDY_MESSAGE_STATE_NONE;
	}

	io = priv->io_data;

	if (spdy_demux->type == SPINDLY_DX_HEADERS) {
		header = &(spdy_demux->msg.headers.headers);
		TIZEN_LOGD("SPINDLY_DX_HEADERS stream_id[%d]", stream_id);
	}	else {
		header = &(spdy_demux->msg.stream_ack.headers);
		TIZEN_LOGD("SPINDLY_DX_STREAM_ACK stream_id[%d] flag[%d]", stream_id, spdy_demux->msg.stream_ack.flags);
	}

	parse_spdy_header (header, io->read_meta_buf);
	spdy_state = SPDY_MESSAGE_STATE_HEADERS;

	/* We need to "rewind" io->read_meta_buf back one line.
	 * That SHOULD be two characters (CR LF), but if the
	 * web server was stupid, it might only be one.
	 */
	if (io->read_meta_buf->len < 3 ||
		io->read_meta_buf->data[io->read_meta_buf->len - 2] == '\n')
	io->read_meta_buf->len--;
	else
		io->read_meta_buf->len -= 2;
	io->read_meta_buf->data[io->read_meta_buf->len] = '\0';
	status = io->parse_headers_cb (msg, (char *)io->read_meta_buf->data,
			       	   io->read_meta_buf->len,
			       	   &io->read_encoding,
			       	   io->header_data);
	g_byte_array_set_size (io->read_meta_buf, 0);
	if (msg->status_code != 200)
		TIZEN_LOGD ("msg[%p] stream_id[%d] status[%d] msg->status_code[%d]", msg, stream_id, status, msg->status_code);

	if (status != SOUP_STATUS_OK) {
		/* Either we couldn't parse the headers, or they
		 * indicated something that would mean we wouldn't
		 * be able to parse the body. (Eg, unknown
		 * Transfer-Encoding.). Skip the rest of the
		 * reading, and make sure the connection gets
		 * closed when we're done.
		 */

		soup_message_set_status (msg, status);
		soup_message_headers_append (msg->request_headers,
				     	 "Connection", "close");

		io->read_state = SOUP_MESSAGE_IO_STATE_DONE;
		TIZEN_LOGD ("msg[%p] stream_id[%d] status code[%d] finish it", msg, stream_id, status);
		soup_message_io_spdy_finished (msg);

		return spdy_state;
	}

	io->spdy_wnd_remaining_size = soup_connection_spdy_get_max_window_size(io->spdy_conn);

	if (io->read_encoding == SOUP_ENCODING_EOF) {
		io->read_eof_ok = TRUE;
	}

	if (io->read_encoding == SOUP_ENCODING_CONTENT_LENGTH) {
		SoupMessageHeaders *hdrs =
				(io->mode == SOUP_MESSAGE_IO_CLIENT) ?
						msg->response_headers : msg->request_headers;
		io->read_length = soup_message_headers_get_content_length (hdrs);

		if (io->mode == SOUP_MESSAGE_IO_CLIENT &&
			!soup_message_is_keepalive (msg)) {
			/* Some servers suck and send
			 * incorrect Content-Length values, so
			 * allow EOF termination in this case
			 * (iff the message is too short) too.
			 */
			io->read_eof_ok = TRUE;
		}
	}

	if (io->mode == SOUP_MESSAGE_IO_CLIENT &&
		SOUP_STATUS_IS_INFORMATIONAL (msg->status_code)) {
		SOUP_MESSAGE_IO_PREPARE_FOR_CALLBACK;
		soup_message_got_informational (msg);
		soup_message_cleanup_response (msg);
		SOUP_MESSAGE_IO_RETURN_VAL_IF_CANCELLED_OR_PAUSED(SPDY_MESSAGE_STATE_NONE);
	} else {
		SOUP_MESSAGE_IO_PREPARE_FOR_CALLBACK;
		soup_message_got_headers (msg);
		SOUP_MESSAGE_IO_RETURN_VAL_IF_CANCELLED_OR_PAUSED(SPDY_MESSAGE_STATE_NONE);
	}

	if (!io_handle_sniffing (msg, FALSE)) {
		return SPDY_MESSAGE_STATE_NONE;
	}

	spdy_state = SPDY_MESSAGE_STATE_HEADERS;

	if ((spdy_demux->type == SPINDLY_DX_STREAM_ACK) && (spdy_demux->msg.stream_ack.flags == SPINDLY_DATA_FLAGS_FIN)) {
		TIZEN_LOGD("SPINDLY_DX_STREAM_ACK streamId[%d] flag[%d] finish it", spdy_demux->msg.stream_ack.streamid, spdy_demux->msg.stream_ack.flags);
		SOUP_MESSAGE_IO_PREPARE_FOR_CALLBACK;
		soup_message_got_body (msg);
		SOUP_MESSAGE_IO_RETURN_VAL_IF_CANCELLED_OR_PAUSED(SPDY_MESSAGE_STATE_NONE);

		priv->spdy_state = spdy_state = SPDY_MESSAGE_STATE_BODY_FINISHED;
		soup_message_io_spdy_finished (msg);
	}

	return spdy_state;
}

static SoupSpdyRecvState
handle_data (SoupMessage *msg, int stream_id, struct spindly_demux *spdy_demux)
{
	SoupMessagePrivate *priv = NULL;
	SoupMessageIOSpdyData *io = NULL;
	SoupBuffer *buffer = NULL;
	SoupSpdyRecvState spdy_state = SPDY_MESSAGE_STATE_NOT_STARTED;

	priv = SOUP_MESSAGE_GET_PRIVATE (msg);
	if (!priv) {
		TIZEN_LOGE ("SPINDLY_DX_DATA priv is NULL stream_id[%d] msg[%p]",  stream_id, msg);
		return SPDY_MESSAGE_STATE_NONE;
	}

	io = priv->io_data;
	io->read_state = SOUP_MESSAGE_IO_STATE_BODY;

	if (spdy_demux->msg.data.flags != SPINDLY_DATA_FLAGS_FIN) {
		io->spdy_wnd_remaining_size -= spdy_demux->msg.data.len;
		//send window update length when remaing length < 30% of MAX, if we send for every 8K more latency & performance issue
		TIZEN_LOGE ("SPINDLY_DX_DATA priv is NULL stream_id[%d] io->spdy_wnd_remaining_size[%d] max_size[%d]",  stream_id, io->spdy_wnd_remaining_size, soup_connection_spdy_get_max_window_size(io->spdy_conn));
		if(io->spdy_wnd_remaining_size <= 0.3*soup_connection_spdy_get_max_window_size(io->spdy_conn))
			soup_connection_spdy_spindly_stream_wndupdate (io->spdy_conn, msg, io->spdy_stream_client, spdy_demux->msg.data.len);
	}

	if (spdy_demux->msg.data.len > 0 ) {
		buffer = soup_buffer_new (SOUP_MEMORY_TEMPORARY,
						spdy_demux->msg.data.datap,
						spdy_demux->msg.data.len);

		/* io->read_length should be decreased,
		 * when the http body is handled, but before content decoding.
		 */
		if (io->read_encoding == SOUP_ENCODING_CONTENT_LENGTH)
			io->read_length -= spdy_demux->msg.data.len;

		buffer = content_decode (msg, buffer);

		if (buffer) {
			soup_message_body_got_chunk (io->read_body, buffer);
			if (io->need_content_sniffed) {
				soup_message_body_append_buffer (io->sniff_data, buffer);
				soup_buffer_free (buffer);
				io->need_got_chunk = TRUE;
				if (!io_handle_sniffing (msg, FALSE))
					return SPDY_MESSAGE_STATE_NONE;
			}
			else {
				SOUP_MESSAGE_IO_PREPARE_FOR_CALLBACK;
				soup_message_got_chunk (msg, buffer);
				soup_buffer_free (buffer);
				SOUP_MESSAGE_IO_RETURN_VAL_IF_CANCELLED_OR_PAUSED (FALSE);
			}
		}
	}

	priv->spdy_state = spdy_state = SPDY_MESSAGE_STATE_BODY;

	if(spdy_demux->msg.data.flags == SPINDLY_DATA_FLAGS_FIN) {
		priv->spdy_state = spdy_state = SPDY_MESSAGE_STATE_BODY_FINISHED;

		TIZEN_LOGD ("msg[%p] data len[%d] stream_id[%d] set SPDY_MESSAGE_STATE_BODY_FINISHED", msg, spdy_demux->msg.data.len, stream_id);
		if (!io_handle_sniffing (msg, TRUE)) {
			return SPDY_MESSAGE_STATE_NONE;
		}

		SOUP_MESSAGE_IO_PREPARE_FOR_CALLBACK;
		soup_message_got_body (msg);
		SOUP_MESSAGE_IO_RETURN_VAL_IF_CANCELLED_OR_PAUSED(SPDY_MESSAGE_STATE_NONE);

		io->read_state = SOUP_MESSAGE_IO_STATE_DONE;

		if (io->read_eof_ok) {
			io->read_length = 0;
		}

		soup_message_io_spdy_finished(msg);
	}
	return spdy_state;
}

static SoupSpdyRecvState
handle_window_update (SoupMessage *msg, int stream_id, struct spindly_demux *spdy_demux)
{
	SoupMessagePrivate *priv = NULL;
	SoupMessageIOSpdyData *io = NULL;
	SoupSpdyRecvState spdy_state = SPDY_MESSAGE_STATE_NOT_STARTED;

	TIZEN_LOGD("msg[%p] stream_id[%d] spdy_demux[%p] remaining window size[%d]", msg, stream_id, spdy_demux,
			spdy_demux->msg.wnd.remainaing_size);

	priv = SOUP_MESSAGE_GET_PRIVATE (msg);
	if (!priv) {
		TIZEN_LOGE ("SPINDLY_DX_WND_UPDATE priv is NULL stream_id[%d] msg[%p]",  stream_id, msg);
		spdy_state = SPDY_MESSAGE_STATE_NONE;
		return spdy_state;
	}
	io = priv->io_data;
	if(io) {
		io->spdy_wnd_remaining_size = spdy_demux->msg.wnd.remainaing_size;
		if(io->write_state == SOUP_MESSAGE_IO_STATE_BODY)
			soup_connection_spdy_reregister_msg_in_waiting_write (io->spdy_conn, msg);
	}
	spdy_state = SPDY_MESSAGE_STATE_WND_UPDATE;

	return spdy_state;
}

SoupSpdyRecvState
soup_message_parse_spdy_response (SoupMessage *msg, int stream_id, struct spindly_demux *spdy_demux)
{
	SoupMessagePrivate *priv = NULL;
	SoupMessageIOSpdyData *io = NULL;
	SoupSpdyRecvState spdy_state = SPDY_MESSAGE_STATE_NOT_STARTED;

	priv = SOUP_MESSAGE_GET_PRIVATE (msg);
	if (!priv) {
		TIZEN_LOGE ("priv[%p]", priv);
		return SPDY_MESSAGE_STATE_NONE;
	}

	io = priv->io_data;
	if (!io) {
		TIZEN_LOGE ("io[%p]", io);
		return SPDY_MESSAGE_STATE_NONE;
	}

	switch(spdy_demux->type) {
		case SPINDLY_DX_STREAM_REQ:
			spdy_state = handle_stream_req (msg, stream_id, spdy_demux);
			break;

		case SPINDLY_DX_HEADERS:
		case SPINDLY_DX_STREAM_ACK:
			spdy_state = handle_stream_ack (msg, stream_id, spdy_demux);
			break;

		case SPINDLY_DX_DATA:
			spdy_state = handle_data (msg, stream_id, spdy_demux);
			break;

		case SPINDLY_DX_WND_UPDATE:
			handle_window_update (msg, stream_id, spdy_demux);
			break;
		default:
			TIZEN_LOGD ("[TURBO LOGS] msg[%p] stream_id[%d] spdy_demux[%p] spdy_demux->type[%d]", msg, stream_id, spdy_demux, spdy_demux->type);
			spdy_state = SPDY_MESSAGE_STATE_NONE;
		break;
	}
	return spdy_state;
}

// temp
static inline SoupMessageIOState
io_body_state (SoupEncoding encoding)
{
	if (encoding == SOUP_ENCODING_CHUNKED)
		return SOUP_MESSAGE_IO_STATE_CHUNK_SIZE;
	else
		return SOUP_MESSAGE_IO_STATE_BODY;
}

static gboolean
get_spdy_request_header (SoupMessage *msg, struct spindly_headers *request_header,
		     SoupEncoding *encoding, SoupMessageQueueItem *item)
{
	SoupMessagePrivate *priv = SOUP_MESSAGE_GET_PRIVATE (msg);
	SoupURI *uri;
	char *uri_host;
	char *uri_string;
	char *uri_scheme, *uri_path;
	spindly_error_t spint;
	SoupMessageHeadersIter iter;
	const char *name, *value;
	GString* header_name;

	if (!msg || !priv || !request_header || !encoding || !item)
		return FALSE;

	uri = soup_message_get_uri (msg);

	if (strchr (uri->host, ':'))
		uri_host = g_strdup_printf ("[%s]", uri->host);
	else if (g_hostname_is_non_ascii (uri->host))
		uri_host = g_hostname_to_ascii (uri->host);
	else
		uri_host = uri->host;

	if (msg->method == SOUP_METHOD_CONNECT) {
		/* CONNECT URI is hostname:port for tunnel destination */
		uri_string = g_strdup_printf ("%s:%d", uri_host, uri->port);
	} else {
		gboolean proxy = soup_connection_is_via_proxy (item->conn);

		/* Proxy expects full URI to destination. Otherwise
		 * just the path.
		 */
		uri_string = soup_uri_to_string (uri, !proxy);

		if (proxy && uri->fragment) {
			/* Strip fragment */
			// FIXME isn't it memory leak to insert 0?
			char *fragment = strchr (uri_string, '#');
			if (fragment)
				*fragment = '\0';
		}
	}

	uri_scheme = (char *) soup_uri_get_scheme(uri);
	uri_path = (char *) soup_uri_get_path(uri);

	TIZEN_SECURE_LOGD ("uri_host[%s] uri_string[%s] uri_scheme[%s] uri_path[%s]\n",
					uri_host, uri_string, uri_scheme, uri_path);

	if (uri_host) {
		spint = spindly_add_header(request_header,":host", uri_host);
	}

	if (msg->method) {
		spint = spindly_add_header(request_header,":method", msg->method);
	}

	if (uri_scheme) {
		spint = spindly_add_header(request_header,":scheme", uri_scheme);
	}

	if (uri_path) {
		spint = spindly_add_header(request_header,":path", uri_string);
	}

	if (priv->http_version == SOUP_HTTP_1_0) {
		spint = spindly_add_header(request_header,":version", "HTTP/1.0");
	} else if (priv->http_version == SOUP_HTTP_1_1) {
		spint = spindly_add_header(request_header,":version", "HTTP/1.1");
	}

	*encoding = soup_message_headers_get_encoding (msg->request_headers);
	if ((*encoding == SOUP_ENCODING_CONTENT_LENGTH ||
	     *encoding == SOUP_ENCODING_NONE) &&
	    (msg->request_body->length > 0 ||
	     soup_message_headers_get_one (msg->request_headers, "Content-Type")) &&
	    !soup_message_headers_get_content_length (msg->request_headers)) {
		*encoding = SOUP_ENCODING_CONTENT_LENGTH;
		soup_message_headers_set_content_length (msg->request_headers,
							 msg->request_body->length);
	}

	soup_message_headers_iter_init (&iter, msg->request_headers);
	while (soup_message_headers_iter_next (&iter, &name, &value)) {
		header_name = g_string_ascii_down (g_string_new(name));
		spint = spindly_add_header (request_header, header_name->str, value);
		g_string_free (header_name, TRUE);
	}

	g_free (uri_string);
	if (uri_host != uri->host)
		g_free (uri_host);

	return TRUE;
}

void
io_spdy_write (SoupConnectionSpdy *spdy_conn, SoupMessage *msg)
{
	SoupMessagePrivate *priv = SOUP_MESSAGE_GET_PRIVATE (msg);
	SoupMessageIOSpdyData *io = priv->io_data;

	spindly_error_t spint;
	int max_window_size;

	switch (io->write_state) {
	case SOUP_MESSAGE_IO_STATE_NOT_STARTED:
		return;

	case SOUP_MESSAGE_IO_STATE_HEADERS:
	{
		gboolean has_request_body = FALSE;
		SoupConnectionSpdyError	error;
		uint32_t spdy_stream_client_id;

		if (!io->spdy_request_header) {
			gboolean is_succeed;
			io->spdy_request_header = g_slice_new0 (struct spindly_headers);
			is_succeed = get_spdy_request_header (msg, io->spdy_request_header,
					&io->write_encoding,
					io->item);
			if (!is_succeed) {
				g_slice_free (struct spindly_headers, io->spdy_request_header);
				io->spdy_request_header = NULL;
				return;
			}
		}

		if ((msg->method == SOUP_METHOD_PUT || msg->method == SOUP_METHOD_POST) && msg->request_body->length) {
			TIZEN_LOGD ("spdy_conn[%p] msg[%p] method[%d] request_body->length[%d]", spdy_conn, msg, msg->method, msg->request_body->length);
			has_request_body = TRUE;
			io->spdy_wnd_remaining_size = soup_connection_spdy_get_max_window_size(io->spdy_conn);
		}

		io->spdy_stream_client = soup_connection_spdy_get_new_spdy_stream (spdy_conn, msg, has_request_body, io->spdy_request_header, &error);
		if (!io->spdy_stream_client) {
			if (error != SOUP_CONNECTION_SPDY_ERROR_NO_AVAILABLE_STREAM) {
				TIZEN_LOGE ("spdy_conn[%p] msg[%p] error[%d] fail to get spdy_stream", spdy_conn, msg, error);
				// FIXME check this would be good enough to finish whole flow
				soup_message_set_status (msg, SOUP_STATUS_IO_ERROR);
				soup_message_io_spdy_finished (msg);
			}
			return;
		}

		spdy_stream_client_id = spindly_stream_get_stream_id (io->spdy_stream_client);
		TIZEN_LOGD ("spdy_conn[%p] msg[%p] stream_id[%d] is created.", spdy_conn, msg, spdy_stream_client_id);

		if (io->write_encoding == SOUP_ENCODING_CONTENT_LENGTH) {
			SoupMessageHeaders *hdrs =
				(io->mode == SOUP_MESSAGE_IO_CLIENT) ?
					msg->request_headers : msg->response_headers;
				/* io->write_length should consider the original http body size and a
				 * spdy frame header size for SOUP_MESSAGE_IO_STATE_BODY case in io_write().
				 */
			io->write_length = soup_message_headers_get_content_length (hdrs);
			TIZEN_LOGD ("spdy_conn[%p] msg[%p] write_encoding is SOUP_ENCODING_CONTENT_LENGTH write_length[%lld]", spdy_conn, msg, io->write_length);
		}

		io->write_state = io_body_state (io->write_encoding);

		SOUP_MESSAGE_IO_PREPARE_FOR_CALLBACK;
		if (SOUP_STATUS_IS_INFORMATIONAL (msg->status_code)) {
			soup_message_wrote_informational (msg);
			soup_message_cleanup_response (msg);
		} else
			soup_message_wrote_headers (msg);
		SOUP_MESSAGE_IO_RETURN_IF_CANCELLED_OR_PAUSED;

		break;
	}
	case SOUP_MESSAGE_IO_STATE_BODY:
		if (!io->write_length && io->write_encoding != SOUP_ENCODING_EOF) {
		wrote_body:
			io->write_state = SOUP_MESSAGE_IO_STATE_FINISHING;

			SOUP_MESSAGE_IO_PREPARE_FOR_CALLBACK;
			soup_message_wrote_body (msg);
			SOUP_MESSAGE_IO_RETURN_IF_CANCELLED_OR_PAUSED;
			break;
		}

		if (!io->write_chunk) {
			io->write_chunk = soup_message_body_get_chunk (io->write_body, io->write_body_offset);
			if (!io->write_chunk) {
//				soup_message_io_pause (msg);
				return;
			}
			if (io->write_chunk->length > io->write_length &&
			    io->write_encoding != SOUP_ENCODING_EOF) {
				/* App is trying to write more than it
				 * claimed it would; we have to truncate.
				 */
				SoupBuffer *truncated =
					soup_buffer_new_subbuffer (io->write_chunk,
								   0, io->write_length);
				soup_buffer_free (io->write_chunk);
				io->write_chunk = truncated;
			} else if (io->write_encoding == SOUP_ENCODING_EOF && !io->write_chunk->length) {
				goto wrote_body;
			}
			TIZEN_LOGD ("spdy_conn[%p] msg[%p] write_chunk len[%d]", spdy_conn, msg, io->write_chunk->length);
		}

		max_window_size = soup_connection_spdy_get_max_window_size(io->spdy_conn);

		if(io->spdy_wnd_remaining_size == 0) {
			TIZEN_LOGD ("SOUP_MESSAGE_IO_STATE_BODY max_window_size is reached io->spdy_wnd_remaining_size %d, msg %x\n", io->spdy_wnd_remaining_size, msg);
			soup_connection_spdy_deregister_msg_in_waiting_write (io->spdy_conn, msg);
			return;
		}
		{
			SoupBuffer* spdy_sub_chunk = NULL;
			gsize left_chunk_size = io->write_chunk->length - io->spdy_body_offset;
			gsize proper_chunk_size;

			if (DEFAULT_WRITE_CHUNK_SIZE < io->spdy_wnd_remaining_size)
				proper_chunk_size = DEFAULT_WRITE_CHUNK_SIZE;
			else
				proper_chunk_size = io->spdy_wnd_remaining_size;

			if (proper_chunk_size > left_chunk_size)
				proper_chunk_size = left_chunk_size;

			spdy_sub_chunk = soup_buffer_new_subbuffer (io->write_chunk,
									   io->spdy_body_offset, proper_chunk_size);

			if((io->write_length - spdy_sub_chunk->length) == 0) {
				spint = spindly_stream_data (io->spdy_stream_client, SPINDLY_DATA_FLAGS_FIN,
								(unsigned char *) spdy_sub_chunk->data, spdy_sub_chunk->length, NULL);
			}
			else {
				spint = spindly_stream_data (io->spdy_stream_client, 0,
								(unsigned char *) spdy_sub_chunk->data, spdy_sub_chunk->length, NULL);
			}

			if (spint != SPINDLYE_OK) {
				TIZEN_LOGE ("spindly_stream_data spint != SPINDLYE_OK %d max_window_size %d io->spdy_body_offset %d\n",spint, max_window_size, io->spdy_body_offset);
				soup_buffer_free(spdy_sub_chunk);
				soup_message_set_status (msg, SOUP_STATUS_IO_ERROR);
				soup_message_io_spdy_finished (msg);
				return;
			}

			SOUP_MESSAGE_IO_PREPARE_FOR_CALLBACK;
			soup_message_wrote_body_data (msg, spdy_sub_chunk);
			SOUP_MESSAGE_IO_RETURN_IF_CANCELLED_OR_PAUSED;

			io->write_length -= spdy_sub_chunk->length;
			io->spdy_body_offset += spdy_sub_chunk->length;
			io->spdy_wnd_remaining_size -= spdy_sub_chunk->length;

			soup_buffer_free(spdy_sub_chunk);
		}

		if (io->write_chunk->length <= io->spdy_body_offset) {
			io->write_body_offset += io->write_chunk->length;
			soup_buffer_free (io->write_chunk);
			io->write_chunk = NULL;
			io->spdy_body_offset = 0;
			SOUP_MESSAGE_IO_PREPARE_FOR_CALLBACK;
			soup_message_wrote_chunk (msg);
			SOUP_MESSAGE_IO_RETURN_IF_CANCELLED_OR_PAUSED;
		}

		return;

	case SOUP_MESSAGE_IO_STATE_CHUNK_SIZE:

		if (!io->write_chunk) {
			io->write_chunk = soup_message_body_get_chunk (io->write_body, io->write_body_offset);
			if (!io->write_chunk) {
//				soup_message_io_pause (msg);
				return;
			}
			io->write_body_offset += io->write_chunk->length;
		}

		if (io->write_chunk->length == 0) {
			/* The last chunk has no CHUNK_END... */
			spint = spindly_stream_data (io->spdy_stream_client, SPINDLY_DATA_FLAGS_FIN,
						(unsigned char *) io->write_chunk->data, io->write_chunk->length, NULL);

			io->write_state = SOUP_MESSAGE_IO_STATE_TRAILERS;
			break;
		}

		io->write_state = SOUP_MESSAGE_IO_STATE_CHUNK;
		/* fall through */

	case SOUP_MESSAGE_IO_STATE_CHUNK:

		spint = spindly_stream_data (io->spdy_stream_client, 0,
					(unsigned char *) io->write_chunk->data, io->write_chunk->length, NULL);
		if (spint != SPINDLYE_OK)
			return;

		if (io->mode == SOUP_MESSAGE_IO_SERVER ||
		    priv->msg_flags & SOUP_MESSAGE_CAN_REBUILD)
			soup_message_body_wrote_chunk (io->write_body, io->write_chunk);
		soup_buffer_free (io->write_chunk);
		io->write_chunk = NULL;

		io->write_state = SOUP_MESSAGE_IO_STATE_CHUNK_END;

		SOUP_MESSAGE_IO_PREPARE_FOR_CALLBACK;
		soup_message_wrote_chunk (msg);
		SOUP_MESSAGE_IO_RETURN_IF_CANCELLED_OR_PAUSED;

		/* fall through */

	case SOUP_MESSAGE_IO_STATE_CHUNK_END:
		io->write_state = SOUP_MESSAGE_IO_STATE_CHUNK_SIZE;
		break;

	case SOUP_MESSAGE_IO_STATE_TRAILERS:
		io->write_state = SOUP_MESSAGE_IO_STATE_FINISHING;

		SOUP_MESSAGE_IO_PREPARE_FOR_CALLBACK;
		soup_message_wrote_body (msg);
		SOUP_MESSAGE_IO_RETURN_IF_CANCELLED_OR_PAUSED;
		/* fall through */

	case SOUP_MESSAGE_IO_STATE_FINISHING:
		TIZEN_LOGD("spdy_conn[%p] msg[%p] SOUP_MESSAGE_IO_STATE_FINISHING", spdy_conn, msg);
		soup_connection_spdy_deregister_msg_in_waiting_write (io->spdy_conn, msg);
		io->write_state = SOUP_MESSAGE_IO_STATE_DONE;
		io->read_state = SOUP_MESSAGE_IO_STATE_HEADERS;
		return;

	case SOUP_MESSAGE_IO_STATE_DONE:
	default:
		g_return_if_reached ();
	}

	return;

}

static SoupMessageIOSpdyData *
new_spdy_iostate (SoupMessageQueueItem *item, SoupConnectionSpdy *spdy_conn, SoupMessageIOMode mode,
	     SoupMessageParseHeadersFn parse_headers_cb,
	     gpointer header_data,
	     SoupMessageCompletionFn completion_cb,
	     gpointer completion_data)
{
	SoupMessagePrivate *priv = SOUP_MESSAGE_GET_PRIVATE (item->msg);
	SoupMessageIOSpdyData *io = NULL;

	io = g_slice_new0 (SoupMessageIOSpdyData);
	io->spdy_conn = g_object_ref (spdy_conn);
	io->mode = mode;
	io->parse_headers_cb = parse_headers_cb;
	io->header_data      = header_data;
	io->completion_cb    = completion_cb;
	io->completion_data  = completion_data;

	io->read_meta_buf    = g_byte_array_new ();

	io->read_state  = SOUP_MESSAGE_IO_STATE_NOT_STARTED;
	io->write_state = SOUP_MESSAGE_IO_STATE_NOT_STARTED;

	//if (priv->io_data)
	//	soup_message_io_cleanup (item->msg);

	priv->io_data = io;
	priv->is_spdy = TRUE;

	soup_connection_spdy_register_msg (io->spdy_conn, item->msg, io_spdy_write, soup_message_parse_spdy_response, soup_message_io_spdy_disconnected);

	return io;
}

void
soup_message_io_spdy_client (SoupMessageQueueItem *item,
			SoupMessageParseHeadersFn parse_headers_cb,
			gpointer header_data,
			SoupMessageCompletionFn completion_cb,
			gpointer completion_data)
{
	SoupMessageIOSpdyData *io = NULL;
	SoupConnectionSpdy *spdy_conn = soup_connection_get_spdy_connection (item->conn);

	TIZEN_LOGD("item[%p] spdy_conn[%p] msg[%p] conn[%p]", item, spdy_conn, item->msg, item->conn);

	io = new_spdy_iostate (item, spdy_conn, SOUP_MESSAGE_IO_CLIENT,
			  parse_headers_cb, header_data,
			  completion_cb, completion_data);

	io->item = item;
	soup_message_queue_item_ref (item);
	io->cancellable = item->cancellable;
	g_cancellable_connect (io->cancellable, G_CALLBACK (cancel_handler), item->msg, NULL);

	io->read_body       = item->msg->response_body;
	io->write_body      = item->msg->request_body;

	io->write_state     = SOUP_MESSAGE_IO_STATE_HEADERS;
	io_spdy_write (spdy_conn, item->msg);
}

static gchar*
convert_spdy_to_Http_Header(gchar *header)
{
	gchar *field = NULL;
	int index = 0;

	if (g_ascii_strcasecmp(header, "p3p") == 0)
		return strdup("P3P");
	else if (g_ascii_strcasecmp(header, "x-xss-protection") == 0)
		return strdup("X-XSS-Protection");
	else if (g_ascii_strcasecmp(header, "www-authenticate") == 0)
		return strdup("WWW-Authenticate");
	else if (g_ascii_strcasecmp(header, "etag") == 0)
		return strdup("ETag");
	else if (g_ascii_strcasecmp(header, "content-md5") == 0)
		return strdup("Content-MD5");
	else if (g_ascii_strcasecmp(header, "x-webkit-csp") == 0)
		return strdup("X-WebKit-CSP");
	else if (g_ascii_strcasecmp(header, "x-ua-compatible") == 0)
		return strdup("X-UA-Compatible");

	field = strdup(header);

	field[0] = g_ascii_toupper(field[0]);

	for (index = 0; field[index]!= '\0'; index++) {
		if (field[index] == '-') {
			index++;
			field[index] = g_ascii_toupper(field[index]);
		}
	}

	return field;
}

void
parse_spdy_header (struct spindly_headers *header, GByteArray *out)
{
	int index = 0;
	gsize entity_len = 0;
	gchar *status_code = NULL;
	gchar *version = NULL;
	gchar *header_entity = NULL;
	gchar *header_status_entity = NULL;
	gchar *header_name = NULL;
	struct spindly_header_pair* pairs = NULL;

	if (!header || !out)
		return;

	pairs = header->pairs;

	for (index = 0; index < header->count; index++) {

		/* name for ":status" would show up prior to one for ":version" */
		if (pairs[index].name && ((strcmp(pairs[index].name, ":status") == 0) || (strcmp(pairs[index].name, "status") == 0))) {
			if (version) {
				entity_len = strlen(pairs[index].value) + strlen(version) + 3 + 1;
				header_status_entity = g_malloc(entity_len);
				snprintf(header_status_entity, entity_len, "%s %s\r\n", version, pairs[index].value);
				g_free(version);
				version = NULL;
			}
			else {
				entity_len = strlen(pairs[index].value) + 1;
				status_code = g_malloc(entity_len);
				snprintf(status_code, entity_len, "%s", pairs[index].value);
			}
		} else if (pairs[index].name && ((strcmp(pairs[index].name, ":version") == 0) || (strcmp(pairs[index].name, "version") == 0))) {
			if (status_code) {
				entity_len = strlen(pairs[index].value) + strlen(status_code) + 3 + 1;
				header_status_entity = g_malloc(entity_len);
				snprintf(header_status_entity, entity_len, "%s %s\r\n", pairs[index].value, status_code);
				g_free(status_code);
				status_code = NULL;
			}
			else {
				entity_len = strlen(pairs[index].value) + 1;
				version = g_malloc(entity_len);
				snprintf(version, entity_len, "%s", pairs[index].value);
			}
		} else {
			int name_len = 0, value_len=0;
			if(pairs[index].name)
				name_len = strlen(pairs[index].name);
			if(pairs[index].value)
				value_len = strlen(pairs[index].value);
			entity_len = name_len + value_len + 4 + 1;
			//entity_len = strlen(pairs[index].name) + strlen(pairs[index].value) + 4 + 1;
			header_entity = g_malloc(entity_len);
			header_name = convert_spdy_to_Http_Header(pairs[index].name);
			snprintf(header_entity, entity_len, "%s: %s\r\n", header_name, pairs[index].value);
			free(header_name);
		}

		if (header_status_entity) {
			g_byte_array_prepend (out, (const guint8 *) header_status_entity, strlen(header_status_entity));
			g_free(header_status_entity);
			header_status_entity = NULL;
		} else if (header_entity) {
			g_byte_array_append (out, (const guint8 *) header_entity, strlen(header_entity));
			g_free(header_entity);
			header_entity = NULL;
		} else {
			/* FIXME: broken last body part, depending on empty_buf size
			 *        RESPONSE_BLOCK_SIZE is tentative and is picked as large as much
			 */
			char empty_buf[RESPONSE_BLOCK_SIZE] = {0,};
			g_byte_array_append (out, (const guint8 *) empty_buf, strlen(empty_buf));
		}
	}

	/* for safe release: status_code */
	if (status_code) {
		g_free(status_code);
		status_code = NULL;
	}

	if (version) {
		g_free(version);
		version = NULL;
	}

	g_byte_array_append (out, (const guint8 *) "\r\n", strlen("\r\n"));
}

static gboolean
soup_message_io_is_active (SoupMessageIOSpdyData *io)
{
	if ((io->write_state == SOUP_MESSAGE_IO_STATE_NOT_STARTED && io->read_state == SOUP_MESSAGE_IO_STATE_NOT_STARTED) ||
		(io->write_state == SOUP_MESSAGE_IO_STATE_DONE && io->read_state == SOUP_MESSAGE_IO_STATE_DONE))
		return FALSE;
	TIZEN_LOGD ("soup_message_io_is_active io->write_state[%d] io->read_state[%d]", io->write_state, io->read_state);
	return TRUE;
}

void
soup_message_io_spdy_stop (SoupMessage *msg)
{
	SoupMessagePrivate *priv = SOUP_MESSAGE_GET_PRIVATE (msg);
	SoupMessageIOSpdyData *io = NULL;

	if (priv)
		io = priv->io_data;

	if (!io)
		return;

	if(io->spdy_stream_client) {
		if(soup_message_io_is_active(io)) {
			TIZEN_LOGD ("spindly_reset_stream msg[%p] stream[%p]", msg, io->spdy_stream_client);
			soup_connection_spdy_spindly_reset_stream (io->spdy_conn, msg, io->spdy_stream_client);
		}

		TIZEN_LOGD ("spindly_stream_close msg[%p] stream[%p]", msg, io->spdy_stream_client);
		spindly_stream_close (io->spdy_stream_client);
	}

	soup_connection_spdy_deregister_msg(io->spdy_conn, msg);
}

void soup_message_io_spdy_cleanup	(SoupMessage	*msg)
{

	SoupMessagePrivate *priv = SOUP_MESSAGE_GET_PRIVATE (msg);
	SoupMessageIOSpdyData *io;

	io = priv->io_data;
	if (!io)
		return;

	soup_message_io_spdy_stop (msg);

	priv->io_data = NULL;

	if (io->item)
		soup_message_queue_item_unref (io->item);

	g_byte_array_free (io->read_meta_buf, TRUE);

	if (io->write_chunk)
		soup_buffer_free (io->write_chunk);

	if (io->sniff_data)
		soup_message_body_free (io->sniff_data);

	if (io->spdy_request_header)
		g_slice_free (struct spindly_headers, io->spdy_request_header);

	if (io->spdy_conn)
		g_object_unref (io->spdy_conn);

	priv->is_spdy = FALSE;
	g_slice_free (SoupMessageIOSpdyData, io);

}

void
soup_message_io_spdy_finished (SoupMessage *msg)
{
	SoupMessagePrivate *priv = SOUP_MESSAGE_GET_PRIVATE (msg);
	SoupMessageIOSpdyData *io = priv->io_data;
	SoupMessageCompletionFn completion_cb = io->completion_cb;
	gpointer completion_data = io->completion_data;

	g_object_ref (msg);
	soup_message_io_spdy_cleanup (msg);
	if (completion_cb)
		completion_cb (msg, completion_data);
	g_object_unref (msg);
}

void
soup_message_io_spdy_disconnected (SoupConnectionSpdy *spdy_conn, SoupMessage *msg)
{
	soup_message_set_status (msg, SOUP_STATUS_IO_ERROR);
	soup_message_io_spdy_finished (msg);
}
