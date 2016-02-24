/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-connection.c: A single HTTP/HTTPS connection
 *
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "soup-connection.h"
#include "soup.h"
#include "soup-message-queue.h"
#include "soup-misc-private.h"

#include "TIZEN.h"

#if ENABLE(TIZEN_PERFORMANCE_TEST_LOG)
#include <sys/prctl.h>
#ifndef PR_TASK_PERF_USER_TRACE
#define PR_TASK_PERF_USER_TRACE 666
#endif
static void prctl_with_url(const char *prestr, const char *url)
{
	char s[256];
	int lem_max = 120;
	int len_pre = strlen(prestr);
	int len_url = strlen(url);

	strcpy(s, prestr);
	if(len_pre + len_url < lem_max) {
		strcpy(s+len_pre, url);
	}
	else {
		int len_part = lem_max - len_pre - 10;
		strncpy(s+len_pre, url, len_part );
		strcpy(s+len_pre+len_part, "...");
		strcpy(s+len_pre+len_part+3, url+len_url-7);
	}
	prctl(PR_TASK_PERF_USER_TRACE, s, strlen(s));
}

static void prctl_with_url_and_free(const char *prestr, char *url)
{
	prctl_with_url(prestr, url);
	g_free(url);
}
#endif

typedef struct {
	SoupSocket  *socket;

	SoupAddress *local_addr;
	SoupURI *remote_uri, *proxy_uri;
	GProxyResolver *proxy_resolver;
	GTlsDatabase *tlsdb;
	gboolean ssl, ssl_strict, ssl_fallback;

	GMainContext *async_context;
	gboolean      use_thread_context;

	SoupMessage *current_msg;
	SoupConnectionState state;
	time_t       unused_timeout;
	guint        io_timeout, idle_timeout;
	GSource     *idle_timeout_src;
	gboolean     reusable;
#if ENABLE(TIZEN_VD_CREATE_IDLE_TCP_CONNECTION)
	SoupMessageQueueItem *cur_item;
#endif

#if ENABLE(TIZEN_VD_CLIENT_CERTIFICATE)
	gboolean     widget_engine;
#endif
} SoupConnectionPrivate;
#define SOUP_CONNECTION_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), SOUP_TYPE_CONNECTION, SoupConnectionPrivate))

G_DEFINE_TYPE (SoupConnection, soup_connection, G_TYPE_OBJECT)

enum {
	EVENT,
	DISCONNECTED,
#if ENABLE(TIZEN_VD_DYNAMIC_CERTIFICATE_LOADING)
	DYNAMIC_CERTIFICATEPATH,
#endif
#if ENABLE(TIZEN_VD_CERTIFICATE_HANDLING)
	ACCEPT_CERTIFICATE,
#endif
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

enum {
	PROP_0,

	PROP_LOCAL_ADDRESS,
	PROP_REMOTE_URI,
	PROP_PROXY_RESOLVER,
	PROP_SSL,
	PROP_SSL_CREDS,
	PROP_SSL_STRICT,
	PROP_SSL_FALLBACK,
	PROP_ASYNC_CONTEXT,
	PROP_USE_THREAD_CONTEXT,
	PROP_TIMEOUT,
	PROP_IDLE_TIMEOUT,
	PROP_STATE,
#if ENABLE(TIZEN_VD_CLIENT_CERTIFICATE)
	PROP_WIDGET_ENGINE,
#endif

	LAST_PROP
};

static void stop_idle_timer (SoupConnectionPrivate *priv);

#if ENABLE(TIZEN_VD_CREATE_IDLE_TCP_CONNECTION)
static void clear_current_item (SoupConnection *conn);
#endif

/* Number of seconds after which we close a connection that hasn't yet
 * been used.
 */
#define SOUP_CONNECTION_UNUSED_TIMEOUT 3

static void
soup_connection_init (SoupConnection *conn)
{
}

static void
soup_connection_finalize (GObject *object)
{
	SoupConnectionPrivate *priv = SOUP_CONNECTION_GET_PRIVATE (object);

	g_clear_pointer (&priv->remote_uri, soup_uri_free);
	g_clear_pointer (&priv->proxy_uri, soup_uri_free);
	g_clear_object (&priv->tlsdb);
	g_clear_object (&priv->proxy_resolver);
	g_clear_object (&priv->local_addr);
	g_clear_pointer (&priv->async_context, g_main_context_unref);

	G_OBJECT_CLASS (soup_connection_parent_class)->finalize (object);
}

static void
soup_connection_dispose (GObject *object)
{
	SoupConnection *conn = SOUP_CONNECTION (object);
	SoupConnectionPrivate *priv = SOUP_CONNECTION_GET_PRIVATE (conn);

	stop_idle_timer (priv);

#if ENABLE(TIZEN_VD_CREATE_IDLE_TCP_CONNECTION)
	if (priv->cur_item) {
		clear_current_item (conn);
	}
#endif
	if (priv->socket) {
		g_warning ("Disposing connection while connected");
		soup_connection_disconnect (conn);
	}

	G_OBJECT_CLASS (soup_connection_parent_class)->dispose (object);
}

static void
soup_connection_set_property (GObject *object, guint prop_id,
			      const GValue *value, GParamSpec *pspec)
{
	SoupConnectionPrivate *priv = SOUP_CONNECTION_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_LOCAL_ADDRESS:
		priv->local_addr = g_value_dup_object (value);
		break;
	case PROP_REMOTE_URI:
		priv->remote_uri = g_value_dup_boxed (value);
		break;
	case PROP_PROXY_RESOLVER:
		priv->proxy_resolver = g_value_dup_object (value);
		break;
	case PROP_SSL:
		priv->ssl = g_value_get_boolean (value);
		break;
	case PROP_SSL_CREDS:
		if (priv->tlsdb)
			g_object_unref (priv->tlsdb);
		priv->tlsdb = g_value_dup_object (value);
		break;
	case PROP_SSL_STRICT:
		priv->ssl_strict = g_value_get_boolean (value);
		break;
	case PROP_SSL_FALLBACK:
		priv->ssl_fallback = g_value_get_boolean (value);
		break;
	case PROP_ASYNC_CONTEXT:
		priv->async_context = g_value_get_pointer (value);
		if (priv->async_context)
			g_main_context_ref (priv->async_context);
		break;
	case PROP_USE_THREAD_CONTEXT:
		priv->use_thread_context = g_value_get_boolean (value);
		break;
	case PROP_TIMEOUT:
		priv->io_timeout = g_value_get_uint (value);
		break;
	case PROP_IDLE_TIMEOUT:
		priv->idle_timeout = g_value_get_uint (value);
		break;
	case PROP_STATE:
		soup_connection_set_state (SOUP_CONNECTION (object), g_value_get_uint (value));
		break;
#if ENABLE(TIZEN_VD_CLIENT_CERTIFICATE)
	case PROP_WIDGET_ENGINE:
		priv->widget_engine = g_value_get_boolean (value);
		break;
#endif
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
soup_connection_get_property (GObject *object, guint prop_id,
			      GValue *value, GParamSpec *pspec)
{
	SoupConnectionPrivate *priv = SOUP_CONNECTION_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_LOCAL_ADDRESS:
		g_value_set_object (value, priv->local_addr);
		break;
	case PROP_REMOTE_URI:
		g_value_set_boxed (value, priv->remote_uri);
		break;
	case PROP_SSL:
		g_value_set_boolean (value, priv->ssl);
		break;
	case PROP_SSL_CREDS:
		g_value_set_object (value, priv->tlsdb);
		break;
	case PROP_SSL_STRICT:
		g_value_set_boolean (value, priv->ssl_strict);
		break;
	case PROP_SSL_FALLBACK:
		g_value_set_boolean (value, priv->ssl_fallback);
		break;
	case PROP_ASYNC_CONTEXT:
		g_value_set_pointer (value, priv->async_context ? g_main_context_ref (priv->async_context) : NULL);
		break;
	case PROP_USE_THREAD_CONTEXT:
		g_value_set_boolean (value, priv->use_thread_context);
		break;
	case PROP_TIMEOUT:
		g_value_set_uint (value, priv->io_timeout);
		break;
	case PROP_IDLE_TIMEOUT:
		g_value_set_uint (value, priv->idle_timeout);
		break;
	case PROP_STATE:
		g_value_set_enum (value, priv->state);
		break;
#if ENABLE(TIZEN_VD_CLIENT_CERTIFICATE)
	case PROP_WIDGET_ENGINE:
		g_value_set_boolean (value, priv->widget_engine);
		break;
#endif
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
soup_connection_class_init (SoupConnectionClass *connection_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (connection_class);

	g_type_class_add_private (connection_class, sizeof (SoupConnectionPrivate));

	/* virtual method override */
	object_class->dispose = soup_connection_dispose;
	object_class->finalize = soup_connection_finalize;
	object_class->set_property = soup_connection_set_property;
	object_class->get_property = soup_connection_get_property;

	/* signals */
	signals[EVENT] =
		g_signal_new ("event",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      0,
			      NULL, NULL,
			      NULL,
			      G_TYPE_NONE, 2,
			      G_TYPE_SOCKET_CLIENT_EVENT,
			      G_TYPE_IO_STREAM);
	signals[DISCONNECTED] =
		g_signal_new ("disconnected",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (SoupConnectionClass, disconnected),
			      NULL, NULL,
			      NULL,
			      G_TYPE_NONE, 0);
#if ENABLE(TIZEN_VD_CERTIFICATE_HANDLING)
	signals[ACCEPT_CERTIFICATE] =
		g_signal_new ("accept-certificate",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_LAST,
			      0,
			      NULL, NULL,
			      NULL,
			      G_TYPE_BOOLEAN, 2,
			      G_TYPE_TLS_CERTIFICATE,
			      G_TYPE_TLS_CERTIFICATE_FLAGS);
#endif

#if ENABLE(TIZEN_VD_DYNAMIC_CERTIFICATE_LOADING)
	signals[DYNAMIC_CERTIFICATEPATH] =
		g_signal_new ("dynamic-certificatePath",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_LAST,
			      0,
			      NULL, NULL,
			      NULL,
			      G_TYPE_POINTER, 1,
			      G_TYPE_POINTER);
#endif

	/* properties */
	g_object_class_install_property (
		object_class, PROP_LOCAL_ADDRESS,
		g_param_spec_object (SOUP_CONNECTION_LOCAL_ADDRESS,
				     "Local address",
				     "Address of local end of socket",
				     SOUP_TYPE_ADDRESS,
				     G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
	g_object_class_install_property (
		object_class, PROP_REMOTE_URI,
		g_param_spec_boxed (SOUP_CONNECTION_REMOTE_URI,
				    "Remote URI",
				    "The URI of the HTTP server",
				    SOUP_TYPE_URI,
				    G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
	g_object_class_install_property (
		object_class, PROP_PROXY_RESOLVER,
		g_param_spec_object (SOUP_CONNECTION_PROXY_RESOLVER,
				     "Proxy resolver",
				     "GProxyResolver to use",
				     G_TYPE_PROXY_RESOLVER,
				     G_PARAM_WRITABLE | G_PARAM_CONSTRUCT_ONLY));
	g_object_class_install_property (
		object_class, PROP_SSL,
		g_param_spec_boolean (SOUP_CONNECTION_SSL,
				      "SSL",
				      "Whether this is an SSL connection",
				      FALSE,
				      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
	g_object_class_install_property (
		object_class, PROP_SSL_CREDS,
		g_param_spec_object (SOUP_CONNECTION_SSL_CREDENTIALS,
				     "SSL credentials",
				     "SSL credentials for this connection",
				     G_TYPE_TLS_DATABASE,
				     G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
	g_object_class_install_property (
		object_class, PROP_SSL_STRICT,
		g_param_spec_boolean (SOUP_CONNECTION_SSL_STRICT,
				      "Strictly validate SSL certificates",
				      "Whether certificate errors should be considered a connection error",
				      TRUE,
				      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
	g_object_class_install_property (
		object_class, PROP_SSL_FALLBACK,
		g_param_spec_boolean (SOUP_CONNECTION_SSL_FALLBACK,
				      "SSLv3 fallback",
				      "Use SSLv3 instead of TLS",
				      FALSE,
				      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
	g_object_class_install_property (
		object_class, PROP_ASYNC_CONTEXT,
		g_param_spec_pointer (SOUP_CONNECTION_ASYNC_CONTEXT,
				      "Async GMainContext",
				      "GMainContext to dispatch this connection's async I/O in",
				      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
	g_object_class_install_property (
		object_class, PROP_USE_THREAD_CONTEXT,
		g_param_spec_boolean (SOUP_CONNECTION_USE_THREAD_CONTEXT,
				      "Use thread context",
				      "Use g_main_context_get_thread_default",
				      FALSE,
				      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
	g_object_class_install_property (
		object_class, PROP_TIMEOUT,
		g_param_spec_uint (SOUP_CONNECTION_TIMEOUT,
				   "Timeout value",
				   "Value in seconds to timeout a blocking I/O",
				   0, G_MAXUINT, 0,
				   G_PARAM_READWRITE));
	g_object_class_install_property (
		object_class, PROP_IDLE_TIMEOUT,
		g_param_spec_uint (SOUP_CONNECTION_IDLE_TIMEOUT,
				   "Idle Timeout",
				   "Connection lifetime when idle",
				   0, G_MAXUINT, 0,
				   G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
	g_object_class_install_property (
		object_class, PROP_STATE,
		g_param_spec_enum (SOUP_CONNECTION_STATE,
				   "Connection state",
				   "Current state of connection",
				   SOUP_TYPE_CONNECTION_STATE, SOUP_CONNECTION_NEW,
				   G_PARAM_READWRITE));
#if ENABLE(TIZEN_VD_CLIENT_CERTIFICATE)
	g_object_class_install_property (
		object_class, PROP_WIDGET_ENGINE,
		g_param_spec_boolean (SOUP_CONNECTION_WIDGET_ENGINE,
				      "widget engine",
				      "Whether or not to be running Widget Engine",
				      FALSE,
				      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
#endif
}

static void
soup_connection_event (SoupConnection      *conn,
		       GSocketClientEvent   event,
		       GIOStream           *connection)
{
	SoupConnectionPrivate *priv = SOUP_CONNECTION_GET_PRIVATE (conn);

	if (!connection && priv->socket)
		connection = soup_socket_get_connection (priv->socket);

	g_signal_emit (conn, signals[EVENT], 0,
		       event, connection);
}

#if ENABLE(TIZEN_VD_DYNAMIC_CERTIFICATE_LOADING)
static const char*
soup_connection_dynamic_client_certificate (SoupSocket *sock,
					    const char* current_host,
					    gpointer user_data)
{
	SoupConnection* conn = user_data;
	const char* get_certpath = NULL;

	g_signal_emit (conn, signals[DYNAMIC_CERTIFICATEPATH], 0,
		       current_host, &get_certpath);

	return get_certpath;
}
#endif
#if ENABLE(TIZEN_VD_CERTIFICATE_HANDLING)
static gboolean
soup_connection_accept_certificate (SoupSocket *sock,
				    GTlsCertificate* certificate,
				    GTlsCertificateFlags errors,
				    gpointer user_data)
{
	SoupConnection* conn = user_data;
	gboolean accept = FALSE;

	g_signal_emit (conn, signals[ACCEPT_CERTIFICATE], 0,
		       certificate, errors, &accept);

	return accept;
}
#endif

static gboolean
idle_timeout (gpointer conn)
{
	soup_connection_disconnect (conn);
	return FALSE;
}

static void
start_idle_timer (SoupConnection *conn)
{
	SoupConnectionPrivate *priv = SOUP_CONNECTION_GET_PRIVATE (conn);

	if (priv->idle_timeout > 0 && !priv->idle_timeout_src) {
		priv->idle_timeout_src =
			soup_add_timeout (priv->async_context,
					  priv->idle_timeout * 1000,
					  idle_timeout, conn);
	}
}

static void
stop_idle_timer (SoupConnectionPrivate *priv)
{
	if (priv->idle_timeout_src) {
		g_source_destroy (priv->idle_timeout_src);
		priv->idle_timeout_src = NULL;
	}
}

static void
current_msg_got_body (SoupMessage *msg, gpointer user_data)
{
	SoupConnection *conn = user_data;
	SoupConnectionPrivate *priv = SOUP_CONNECTION_GET_PRIVATE (conn);

	priv->unused_timeout = 0;

	if (priv->proxy_uri &&
	    msg->method == SOUP_METHOD_CONNECT &&
	    SOUP_STATUS_IS_SUCCESSFUL (msg->status_code)) {
		soup_connection_event (conn, G_SOCKET_CLIENT_PROXY_NEGOTIATED, NULL);

		/* We're now effectively no longer proxying */
		g_clear_pointer (&priv->proxy_uri, soup_uri_free);
	}

	priv->reusable = soup_message_is_keepalive (msg);
}

static void
clear_current_msg (SoupConnection *conn)
{
	SoupConnectionPrivate *priv = SOUP_CONNECTION_GET_PRIVATE (conn);
	SoupMessage *msg;

	msg = priv->current_msg;
	priv->current_msg = NULL;

	g_signal_handlers_disconnect_by_func (msg, G_CALLBACK (current_msg_got_body), conn);
	g_object_unref (msg);
}

#if ENABLE(TIZEN_VD_CREATE_IDLE_TCP_CONNECTION)
gboolean
soup_connection_has_current_item (SoupConnection *conn)
{
	SoupConnectionPrivate *priv = SOUP_CONNECTION_GET_PRIVATE (conn);

	if (priv)
		return (priv->cur_item == NULL) ? FALSE : TRUE;
	else
		return FALSE;
}

SoupMessageQueueItem *
soup_connection_get_current_item (SoupConnection *conn)
{
	SoupConnectionPrivate *priv = SOUP_CONNECTION_GET_PRIVATE (conn);

	if (priv)
		return priv->cur_item;
	else
		return NULL;
}

static void
clear_current_item (SoupConnection *conn)
{
	SoupConnectionPrivate *priv = SOUP_CONNECTION_GET_PRIVATE (conn);

	g_return_if_fail (priv != NULL);

	g_object_freeze_notify (G_OBJECT (conn));
	if (priv->cur_item)
		priv->cur_item = NULL;
}

static void
set_current_item (SoupConnection *conn, SoupMessageQueueItem *item)
{
	SoupConnectionPrivate *priv = SOUP_CONNECTION_GET_PRIVATE (conn);

	g_return_if_fail (priv != NULL);

	priv->cur_item = item;
}



/* soup_connection_set_current_item() sets only item, and does not change any state.
 * That is what this function is different from set_current_item() above. */
void
soup_connection_set_current_item (SoupConnection *conn, SoupMessageQueueItem *item)
{
	SoupConnectionPrivate *priv = SOUP_CONNECTION_GET_PRIVATE (conn);

	g_return_if_fail (priv != NULL);
	g_return_if_fail (priv->cur_item == NULL);

	g_object_freeze_notify (G_OBJECT (conn));

	stop_idle_timer (priv);

	priv->cur_item = item;

	g_object_thaw_notify (G_OBJECT (conn));
}
#endif

static void
set_current_msg (SoupConnection *conn, SoupMessage *msg)
{
	SoupConnectionPrivate *priv = SOUP_CONNECTION_GET_PRIVATE (conn);

	g_return_if_fail (priv->state == SOUP_CONNECTION_IN_USE);

	g_object_freeze_notify (G_OBJECT (conn));

	if (priv->current_msg) {
		g_return_if_fail (priv->current_msg->method == SOUP_METHOD_CONNECT);
		clear_current_msg (conn);
	}

	stop_idle_timer (priv);

	priv->current_msg = g_object_ref (msg);
	priv->reusable = FALSE;

	g_signal_connect (msg, "got-body",
			  G_CALLBACK (current_msg_got_body), conn);

	if (priv->proxy_uri && msg->method == SOUP_METHOD_CONNECT)
		soup_connection_event (conn, G_SOCKET_CLIENT_PROXY_NEGOTIATING, NULL);

	g_object_thaw_notify (G_OBJECT (conn));
}

static void
re_emit_socket_event (SoupSocket          *socket,
		      GSocketClientEvent   event,
		      GIOStream           *connection,
		      gpointer             user_data)
{
	SoupConnection *conn = user_data;

	/* We handle COMPLETE ourselves */
	if (event != G_SOCKET_CLIENT_COMPLETE)
		soup_connection_event (conn, event, connection);
}

static void
socket_connect_finished (GTask *task, SoupSocket *sock, GError *error)
{
	SoupConnection *conn = g_task_get_source_object (task);
	SoupConnectionPrivate *priv = SOUP_CONNECTION_GET_PRIVATE (conn);

	if (priv->async_context && !priv->use_thread_context)
		g_main_context_pop_thread_default (priv->async_context);

	g_signal_handlers_disconnect_by_func (sock, G_CALLBACK (re_emit_socket_event), conn);

	if (!error) {
		if (priv->ssl && !priv->proxy_uri) {
			soup_connection_event (conn,
					       G_SOCKET_CLIENT_TLS_HANDSHAKED,
					       NULL);
		}
		if (!priv->ssl || !priv->proxy_uri) {
			soup_connection_event (conn,
					       G_SOCKET_CLIENT_COMPLETE,
					       NULL);
		}

		soup_connection_set_state (conn, SOUP_CONNECTION_IN_USE);
		priv->unused_timeout = time (NULL) + SOUP_CONNECTION_UNUSED_TIMEOUT;
		start_idle_timer (conn);

		g_task_return_boolean (task, TRUE);
	} else
		g_task_return_error (task, error);
	g_object_unref (task);
}

static void
socket_handshake_complete (GObject *object, GAsyncResult *result, gpointer user_data)
{
	SoupSocket *sock = SOUP_SOCKET (object);
	GTask *task = user_data;
	GError *error = NULL;

	soup_socket_handshake_finish (sock, result, &error);
	socket_connect_finished (task, sock, error);
}

static void
socket_connect_complete (GObject *object, GAsyncResult *result, gpointer user_data)
{
	SoupSocket *sock = SOUP_SOCKET (object);
	GTask *task = user_data;
	SoupConnection *conn = g_task_get_source_object (task);
	SoupConnectionPrivate *priv = SOUP_CONNECTION_GET_PRIVATE (conn);
	GError *error = NULL;

	if (!soup_socket_connect_finish_internal (sock, result, &error)) {
		socket_connect_finished (task, sock, error);
		return;
	}

	priv->proxy_uri = soup_socket_get_http_proxy_uri (sock);

	if (priv->ssl && !priv->proxy_uri) {
		soup_connection_event (conn,
				       G_SOCKET_CLIENT_TLS_HANDSHAKING,
				       NULL);

		soup_socket_handshake_async (sock, priv->remote_uri->host,
					     g_task_get_cancellable (task),
					     socket_handshake_complete, task);
		return;
	}

	socket_connect_finished (task, sock, NULL);
}

void
soup_connection_connect_async (SoupConnection      *conn,
			       GCancellable        *cancellable,
			       GAsyncReadyCallback  callback,
			       gpointer             user_data)
{
	SoupConnectionPrivate *priv;
	SoupAddress *remote_addr;
	GTask *task;

	g_return_if_fail (SOUP_IS_CONNECTION (conn));
	priv = SOUP_CONNECTION_GET_PRIVATE (conn);
	g_return_if_fail (priv->socket == NULL);

	soup_connection_set_state (conn, SOUP_CONNECTION_CONNECTING);

	/* Set the protocol to ensure correct proxy resolution. */
	remote_addr =
		g_object_new (SOUP_TYPE_ADDRESS,
			      SOUP_ADDRESS_NAME, priv->remote_uri->host,
			      SOUP_ADDRESS_PORT, priv->remote_uri->port,
			      SOUP_ADDRESS_PROTOCOL, priv->remote_uri->scheme,
			      NULL);

	priv->socket =
		soup_socket_new (SOUP_SOCKET_REMOTE_ADDRESS, remote_addr,
				 SOUP_SOCKET_SSL_CREDENTIALS, priv->tlsdb,
				 SOUP_SOCKET_SSL_STRICT, priv->ssl_strict,
				 SOUP_SOCKET_SSL_FALLBACK, priv->ssl_fallback,
				 SOUP_SOCKET_ASYNC_CONTEXT, priv->async_context,
				 SOUP_SOCKET_USE_THREAD_CONTEXT, priv->use_thread_context,
				 SOUP_SOCKET_PROXY_RESOLVER, priv->proxy_resolver,
				 SOUP_SOCKET_TIMEOUT, priv->io_timeout,
				 SOUP_SOCKET_CLEAN_DISPOSE, TRUE,
				 SOUP_SOCKET_LOCAL_ADDRESS, priv->local_addr,
#if ENABLE(TIZEN_VD_CLIENT_CERTIFICATE)
				 SOUP_SOCKET_WIDGET_ENGINE, priv->widget_engine,
#endif
				 NULL);
	g_object_unref (remote_addr);

	g_signal_connect (priv->socket, "event",
			  G_CALLBACK (re_emit_socket_event), conn);
#if ENABLE(TIZEN_VD_CERTIFICATE_HANDLING)
	g_signal_connect (priv->socket, "accept-certificate",
			  G_CALLBACK (soup_connection_accept_certificate), conn);
#endif

#if ENABLE(TIZEN_VD_DYNAMIC_CERTIFICATE_LOADING)
	g_signal_connect (priv->socket, "dynamic-certificatePath",
				  G_CALLBACK (soup_connection_dynamic_client_certificate), conn);
#endif
	if (priv->async_context && !priv->use_thread_context)
		g_main_context_push_thread_default (priv->async_context);
	task = g_task_new (conn, cancellable, callback, user_data);

	soup_socket_connect_async_internal (priv->socket, cancellable,
					    socket_connect_complete, task);
}

gboolean
soup_connection_connect_finish (SoupConnection  *conn,
				GAsyncResult    *result,
				GError         **error)
{
	return g_task_propagate_boolean (G_TASK (result), error);
}

gboolean
soup_connection_connect_sync (SoupConnection  *conn,
			      GCancellable    *cancellable,
			      GError         **error)
{
	SoupConnectionPrivate *priv;
	guint event_id = 0;
	SoupAddress *remote_addr;
	gboolean success = TRUE;

	g_return_val_if_fail (SOUP_IS_CONNECTION (conn), FALSE);
	priv = SOUP_CONNECTION_GET_PRIVATE (conn);
	g_return_val_if_fail (priv->socket == NULL, FALSE);

	soup_connection_set_state (conn, SOUP_CONNECTION_CONNECTING);

	/* Set the protocol to ensure correct proxy resolution. */
	remote_addr =
		g_object_new (SOUP_TYPE_ADDRESS,
			      SOUP_ADDRESS_NAME, priv->remote_uri->host,
			      SOUP_ADDRESS_PORT, priv->remote_uri->port,
			      SOUP_ADDRESS_PROTOCOL, priv->remote_uri->scheme,
			      NULL);

	priv->socket =
		soup_socket_new (SOUP_SOCKET_REMOTE_ADDRESS, remote_addr,
				 SOUP_SOCKET_PROXY_RESOLVER, priv->proxy_resolver,
				 SOUP_SOCKET_SSL_CREDENTIALS, priv->tlsdb,
				 SOUP_SOCKET_SSL_STRICT, priv->ssl_strict,
				 SOUP_SOCKET_SSL_FALLBACK, priv->ssl_fallback,
				 SOUP_SOCKET_FLAG_NONBLOCKING, FALSE,
				 SOUP_SOCKET_TIMEOUT, priv->io_timeout,
				 SOUP_SOCKET_CLEAN_DISPOSE, TRUE,
				 SOUP_SOCKET_LOCAL_ADDRESS, priv->local_addr,
#if ENABLE(TIZEN_VD_CLIENT_CERTIFICATE)
				 SOUP_SOCKET_WIDGET_ENGINE, priv->widget_engine,
#endif
				 NULL);
	g_object_unref (remote_addr);

	event_id = g_signal_connect (priv->socket, "event",
				     G_CALLBACK (re_emit_socket_event), conn);
#if ENABLE(TIZEN_VD_CERTIFICATE_HANDLING)
	g_signal_connect (priv->socket, "accept-certificate",
			  G_CALLBACK (soup_connection_accept_certificate), conn);
#endif

	if (!soup_socket_connect_sync_internal (priv->socket, cancellable, error)) {
		success = FALSE;
		goto done;
	}

	priv->proxy_uri = soup_socket_get_http_proxy_uri (priv->socket);

	if (priv->ssl && !priv->proxy_uri) {
		soup_connection_event (conn,
				       G_SOCKET_CLIENT_TLS_HANDSHAKING,
				       NULL);
		if (!soup_socket_handshake_sync (priv->socket,
						 priv->remote_uri->host,
						 cancellable, error)) {
			success = FALSE;
			goto done;
		}
		soup_connection_event (conn,
				       G_SOCKET_CLIENT_TLS_HANDSHAKED,
				       NULL);
	}

	if (!priv->ssl || !priv->proxy_uri) {
		soup_connection_event (conn,
				       G_SOCKET_CLIENT_COMPLETE,
				       NULL);
	}
	soup_connection_set_state (conn, SOUP_CONNECTION_IN_USE);
	priv->unused_timeout = time (NULL) + SOUP_CONNECTION_UNUSED_TIMEOUT;
	start_idle_timer (conn);

 done:
	if (priv->socket && event_id)
		g_signal_handler_disconnect (priv->socket, event_id);

	return success;
}

gboolean
soup_connection_is_tunnelled (SoupConnection *conn)
{
	SoupConnectionPrivate *priv;

	g_return_val_if_fail (SOUP_IS_CONNECTION (conn), FALSE);
	priv = SOUP_CONNECTION_GET_PRIVATE (conn);

	return priv->ssl && priv->proxy_uri != NULL;
}

gboolean
soup_connection_start_ssl_sync (SoupConnection  *conn,
				GCancellable    *cancellable,
				GError         **error)
{
	SoupConnectionPrivate *priv;

	g_return_val_if_fail (SOUP_IS_CONNECTION (conn), FALSE);
	priv = SOUP_CONNECTION_GET_PRIVATE (conn);

	soup_connection_event (conn, G_SOCKET_CLIENT_TLS_HANDSHAKING, NULL);
	if (soup_socket_handshake_sync (priv->socket, priv->remote_uri->host,
					cancellable, error)) {
		soup_connection_event (conn, G_SOCKET_CLIENT_TLS_HANDSHAKED, NULL);
		soup_connection_event (conn, G_SOCKET_CLIENT_COMPLETE, NULL);
		return TRUE;
	} else
		return FALSE;
}

static void
start_ssl_completed (GObject *object, GAsyncResult *result, gpointer user_data)
{
	GTask *task = user_data;
	SoupConnection *conn = g_task_get_source_object (task);
	SoupConnectionPrivate *priv = SOUP_CONNECTION_GET_PRIVATE (conn);
	GError *error = NULL;

	if (priv->async_context && !priv->use_thread_context)
		g_main_context_pop_thread_default (priv->async_context);

	if (soup_socket_handshake_finish (priv->socket, result, &error)) {
		soup_connection_event (conn, G_SOCKET_CLIENT_TLS_HANDSHAKED, NULL);
		soup_connection_event (conn, G_SOCKET_CLIENT_COMPLETE, NULL);
		g_task_return_boolean (task, TRUE);
#if ENABLE(TIZEN_PERFORMANCE_TEST_LOG)
		prctl_with_url_and_free("[EVT] soup handshake complete : ", soup_uri_to_string(soup_connection_get_remote_uri(conn), FALSE));
#endif
	} else
		g_task_return_error (task, error);
	g_object_unref (task);
}

void
soup_connection_start_ssl_async (SoupConnection      *conn,
				 GCancellable        *cancellable,
				 GAsyncReadyCallback  callback,
				 gpointer             user_data)
{
	SoupConnectionPrivate *priv;
	GTask *task;

	g_return_if_fail (SOUP_IS_CONNECTION (conn));
	priv = SOUP_CONNECTION_GET_PRIVATE (conn);

	soup_connection_event (conn, G_SOCKET_CLIENT_TLS_HANDSHAKING, NULL);

	if (priv->async_context && !priv->use_thread_context)
		g_main_context_push_thread_default (priv->async_context);
	task = g_task_new (conn, cancellable, callback, user_data);

	soup_socket_handshake_async (priv->socket, priv->remote_uri->host,
				     cancellable, start_ssl_completed, task);
}

gboolean
soup_connection_start_ssl_finish (SoupConnection  *conn,
				  GAsyncResult    *result,
				  GError         **error)
{
	return g_task_propagate_boolean (G_TASK (result), error);
}

/**
 * soup_connection_disconnect:
 * @conn: a connection
 *
 * Disconnects @conn's socket and emits a %disconnected signal.
 * After calling this, @conn will be essentially useless.
 **/
void
soup_connection_disconnect (SoupConnection *conn)
{
	SoupConnectionPrivate *priv;
	SoupConnectionState old_state;

	g_return_if_fail (SOUP_IS_CONNECTION (conn));
	priv = SOUP_CONNECTION_GET_PRIVATE (conn);

	old_state = priv->state;
	if (old_state != SOUP_CONNECTION_DISCONNECTED)
		soup_connection_set_state (conn, SOUP_CONNECTION_DISCONNECTED);

	if (priv->socket) {
		SoupSocket *socket = priv->socket;

		priv->socket = NULL;
		soup_socket_disconnect (socket);
		g_object_unref (socket);
	}

	if (old_state != SOUP_CONNECTION_DISCONNECTED)
		g_signal_emit (conn, signals[DISCONNECTED], 0);
}

SoupSocket *
soup_connection_get_socket (SoupConnection *conn)
{
	g_return_val_if_fail (SOUP_IS_CONNECTION (conn), NULL);

	return SOUP_CONNECTION_GET_PRIVATE (conn)->socket;
}

SoupURI *
soup_connection_get_remote_uri (SoupConnection *conn)
{
	g_return_val_if_fail (SOUP_IS_CONNECTION (conn), NULL);

	return SOUP_CONNECTION_GET_PRIVATE (conn)->remote_uri;
}

SoupURI *
soup_connection_get_proxy_uri (SoupConnection *conn)
{
	g_return_val_if_fail (SOUP_IS_CONNECTION (conn), NULL);

	return SOUP_CONNECTION_GET_PRIVATE (conn)->proxy_uri;
}

gboolean
soup_connection_is_via_proxy (SoupConnection *conn)
{
	g_return_val_if_fail (SOUP_IS_CONNECTION (conn), FALSE);

	return SOUP_CONNECTION_GET_PRIVATE (conn)->proxy_uri != NULL;
}

SoupConnectionState
soup_connection_get_state (SoupConnection *conn)
{
	SoupConnectionPrivate *priv;

	g_return_val_if_fail (SOUP_IS_CONNECTION (conn),
			      SOUP_CONNECTION_DISCONNECTED);
	priv = SOUP_CONNECTION_GET_PRIVATE (conn);

	if (priv->state == SOUP_CONNECTION_IDLE &&
	    g_socket_condition_check (soup_socket_get_gsocket (priv->socket), G_IO_IN))
		soup_connection_set_state (conn, SOUP_CONNECTION_REMOTE_DISCONNECTED);

	if (priv->state == SOUP_CONNECTION_IDLE &&
	    priv->unused_timeout && priv->unused_timeout < time (NULL))
		soup_connection_set_state (conn, SOUP_CONNECTION_REMOTE_DISCONNECTED);

	return priv->state;
}

void
soup_connection_set_state (SoupConnection *conn, SoupConnectionState state)
{
	SoupConnectionPrivate *priv;

	g_return_if_fail (SOUP_IS_CONNECTION (conn));
	g_return_if_fail (state >= SOUP_CONNECTION_NEW &&
			  state <= SOUP_CONNECTION_DISCONNECTED);

	g_object_freeze_notify (G_OBJECT (conn));

	priv = SOUP_CONNECTION_GET_PRIVATE (conn);

	if (priv->current_msg) {
		g_warn_if_fail (state == SOUP_CONNECTION_IDLE ||
				state == SOUP_CONNECTION_DISCONNECTED);
#if ENABLE(TIZEN_VD_CREATE_IDLE_TCP_CONNECTION)
		clear_current_item (conn);
#endif
		clear_current_msg (conn);
	}

	if (state == SOUP_CONNECTION_IDLE && !priv->reusable) {
		/* This will recursively call set_state() */
		soup_connection_disconnect (conn);
	} else {
		priv->state = state;

		if (priv->state == SOUP_CONNECTION_IDLE)
			start_idle_timer (conn);

		g_object_notify (G_OBJECT (conn), "state");
	}

	g_object_thaw_notify (G_OBJECT (conn));
}

gboolean
soup_connection_get_ever_used (SoupConnection *conn)
{
	g_return_val_if_fail (SOUP_IS_CONNECTION (conn), FALSE);

	return SOUP_CONNECTION_GET_PRIVATE (conn)->unused_timeout == 0;
}

gboolean
soup_connection_get_ssl_fallback (SoupConnection *conn)
{
	return SOUP_CONNECTION_GET_PRIVATE (conn)->ssl_fallback;
}

void
soup_connection_send_request (SoupConnection          *conn,
			      SoupMessageQueueItem    *item,
			      SoupMessageCompletionFn  completion_cb,
			      gpointer                 user_data)
{
	SoupConnectionPrivate *priv;

	g_return_if_fail (SOUP_IS_CONNECTION (conn));
	g_return_if_fail (item != NULL);
	priv = SOUP_CONNECTION_GET_PRIVATE (conn);
	g_return_if_fail (priv->state != SOUP_CONNECTION_NEW &&
			  priv->state != SOUP_CONNECTION_DISCONNECTED);

#if ENABLE(TIZEN_VD_CREATE_IDLE_TCP_CONNECTION)
	set_current_item (conn, item);
	set_current_msg (conn, item->msg);
#else
	if (item->msg != priv->current_msg)
		set_current_msg (conn, item->msg);
	else
		priv->reusable = FALSE;
#endif

	soup_message_send_request (item, completion_cb, user_data);
}

#if ENABLE(TIZEN_VD_CREATE_IDLE_TCP_CONNECTION)
void
soup_connection_set_pre_connect_idle (SoupConnection *conn)
{
	SoupConnectionPrivate *priv = NULL;

	g_return_val_if_fail (SOUP_IS_CONNECTION (conn), FALSE);
	priv = SOUP_CONNECTION_GET_PRIVATE (conn);

	if (priv) {
		if (priv->state == SOUP_CONNECTION_IN_USE)
			priv->state = SOUP_CONNECTION_IDLE;
	}
}
#endif
