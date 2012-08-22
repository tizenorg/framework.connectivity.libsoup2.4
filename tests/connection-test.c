/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright 2007-2012 Red Hat, Inc.
 */

#include <string.h>

#include <libsoup/soup.h>

#include "test-utils.h"

SoupServer *server;
SoupURI *base_uri;
GMutex server_mutex;

static void
forget_close (SoupMessage *msg, gpointer user_data)
{
	soup_message_headers_remove (msg->response_headers, "Connection");
}

static void
close_socket (SoupMessage *msg, gpointer user_data)
{
	SoupSocket *sock = user_data;

	soup_socket_disconnect (sock);

	/* But also add the missing data to the message now, so
	 * SoupServer can clean up after itself properly.
	 */
	soup_message_body_append (msg->response_body, SOUP_MEMORY_STATIC,
				  "foo", 3);
}

static void
timeout_socket (SoupSocket *sock, gpointer user_data)
{
	soup_socket_disconnect (sock);
}

static void
timeout_request_started (SoupServer *server, SoupMessage *msg,
			 SoupClientContext *client, gpointer user_data)
{
	SoupSocket *sock;
	GMainContext *context = soup_server_get_async_context (server);
	guint readable;

	sock = soup_client_context_get_socket (client);
	readable = g_signal_connect (sock, "readable",
				    G_CALLBACK (timeout_socket), NULL);
	while (soup_socket_is_connected (sock))
		g_main_context_iteration (context, TRUE);
	g_signal_handler_disconnect (sock, readable);
	g_signal_handlers_disconnect_by_func (server, timeout_request_started, NULL);
}

static void
setup_timeout_persistent (SoupServer *server, SoupSocket *sock)
{
	char buf[1];
	gsize nread;

	/* In order for the test to work correctly, we have to
	 * close the connection *after* the client side writes
	 * the request. To ensure that this happens reliably,
	 * regardless of thread scheduling, we:
	 *
	 *   1. Try to read off the socket now, knowing it will
	 *      fail (since the client is waiting for us to
	 *      return a response). This will cause it to
	 *      emit "readable" later.
	 *   2. Connect to the server's request-started signal.
	 *   3. Run an inner main loop from that signal handler
	 *      until the socket emits "readable". (If we don't
	 *      do this then it's possible the client's next
	 *      request would be ready before we returned to
	 *      the main loop, and so the signal would never be
	 *      emitted.)
	 *   4. Close the socket.
	 */

	soup_socket_read (sock, buf, 1, &nread, NULL, NULL);
	g_signal_connect (server, "request-started",
			  G_CALLBACK (timeout_request_started), NULL);
}

static void
server_callback (SoupServer *server, SoupMessage *msg,
		 const char *path, GHashTable *query,
		 SoupClientContext *context, gpointer data)
{
	/* The way this gets used in the tests, we don't actually
	 * need to hold it through the whole function, so it's simpler
	 * to just release it right away.
	 */
	g_mutex_lock (&server_mutex);
	g_mutex_unlock (&server_mutex);

	if (msg->method != SOUP_METHOD_GET && msg->method != SOUP_METHOD_POST) {
		soup_message_set_status (msg, SOUP_STATUS_NOT_IMPLEMENTED);
		return;
	}

	if (g_str_has_prefix (path, "/content-length/")) {
		gboolean too_long = strcmp (path, "/content-length/long") == 0;
		gboolean no_close = strcmp (path, "/content-length/noclose") == 0;

		soup_message_set_status (msg, SOUP_STATUS_OK);
		soup_message_set_response (msg, "text/plain",
					   SOUP_MEMORY_STATIC, "foobar", 6);
		if (too_long)
			soup_message_headers_set_content_length (msg->response_headers, 9);
		soup_message_headers_append (msg->response_headers,
					     "Connection", "close");

		if (too_long) {
			SoupSocket *sock;

			/* soup-message-io will wait for us to add
			 * another chunk after the first, to fill out
			 * the declared Content-Length. Instead, we
			 * forcibly close the socket at that point.
			 */
			sock = soup_client_context_get_socket (context);
			g_signal_connect (msg, "wrote-chunk",
					  G_CALLBACK (close_socket), sock);
		} else if (no_close) {
			/* Remove the 'Connection: close' after writing
			 * the headers, so that when we check it after
			 * writing the body, we'll think we aren't
			 * supposed to close it.
			 */
			g_signal_connect (msg, "wrote-headers",
					  G_CALLBACK (forget_close), NULL);
		}
		return;
	}

	if (!strcmp (path, "/timeout-persistent")) {
		SoupSocket *sock;

		sock = soup_client_context_get_socket (context);
		setup_timeout_persistent (server, sock);
	}

	soup_message_set_status (msg, SOUP_STATUS_OK);
	soup_message_set_response (msg, "text/plain",
				   SOUP_MEMORY_STATIC, "index", 5);
	return;
}

static void
do_content_length_framing_test (void)
{
	SoupSession *session;
	SoupMessage *msg;
	SoupURI *request_uri;
	goffset declared_length;

	debug_printf (1, "\nInvalid Content-Length framing tests\n");

	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC, NULL);

	debug_printf (1, "  Content-Length larger than message body length\n");
	request_uri = soup_uri_new_with_base (base_uri, "/content-length/long");
	msg = soup_message_new_from_uri ("GET", request_uri);
	soup_session_send_message (session, msg);
	if (msg->status_code != SOUP_STATUS_OK) {
		debug_printf (1, "    Unexpected response: %d %s\n",
			      msg->status_code, msg->reason_phrase);
		errors++;
	} else {
		declared_length = soup_message_headers_get_content_length (msg->response_headers);
		debug_printf (2, "    Content-Length: %lu, body: %s\n",
			      (gulong)declared_length, msg->response_body->data);
		if (msg->response_body->length >= declared_length) {
			debug_printf (1, "    Body length %lu >= declared length %lu\n",
				      (gulong)msg->response_body->length,
				      (gulong)declared_length);
			errors++;
		}
	}
	soup_uri_free (request_uri);
	g_object_unref (msg);

	debug_printf (1, "  Server claims 'Connection: close' but doesn't\n");
	request_uri = soup_uri_new_with_base (base_uri, "/content-length/noclose");
	msg = soup_message_new_from_uri ("GET", request_uri);
	soup_session_send_message (session, msg);
	if (msg->status_code != SOUP_STATUS_OK) {
		debug_printf (1, "    Unexpected response: %d %s\n",
			      msg->status_code, msg->reason_phrase);
		errors++;
	} else {
		declared_length = soup_message_headers_get_content_length (msg->response_headers);
		debug_printf (2, "    Content-Length: %lu, body: %s\n",
			      (gulong)declared_length, msg->response_body->data);
		if (msg->response_body->length != declared_length) {
			debug_printf (1, "    Body length %lu != declared length %lu\n",
				      (gulong)msg->response_body->length,
				      (gulong)declared_length);
			errors++;
		}
	}
	soup_uri_free (request_uri);
	g_object_unref (msg);

	soup_test_session_abort_unref (session);
}

static void
request_started_socket_collector (SoupSession *session, SoupMessage *msg,
				  SoupSocket *socket, gpointer user_data)
{
	SoupSocket **sockets = user_data;
	int i;

	debug_printf (2, "      msg %p => socket %p\n", msg, socket);
	for (i = 0; i < 4; i++) {
		if (!sockets[i]) {
			/* We ref the socket to make sure that even if
			 * it gets disconnected, it doesn't get freed,
			 * since our checks would get messed up if the
			 * slice allocator reused the same address for
			 * two consecutive sockets.
			 */
			sockets[i] = g_object_ref (socket);
			return;
		}
	}

	debug_printf (1, "      socket queue overflowed!\n");
	errors++;
	soup_session_cancel_message (session, msg, SOUP_STATUS_CANCELLED);
}

static void
do_timeout_test_for_session (SoupSession *session)
{
	SoupMessage *msg;
	SoupSocket *sockets[4] = { NULL, NULL, NULL, NULL };
	SoupURI *timeout_uri;
	int i;

	g_signal_connect (session, "request-started",
			  G_CALLBACK (request_started_socket_collector),
			  &sockets);

	debug_printf (1, "    First message\n");
	timeout_uri = soup_uri_new_with_base (base_uri, "/timeout-persistent");
	msg = soup_message_new_from_uri ("GET", timeout_uri);
	soup_uri_free (timeout_uri);
	soup_session_send_message (session, msg);
	if (msg->status_code != SOUP_STATUS_OK) {
		debug_printf (1, "      Unexpected response: %d %s\n",
			      msg->status_code, msg->reason_phrase);
		errors++;
	}
	if (sockets[1]) {
		debug_printf (1, "      Message was retried??\n");
		errors++;
		sockets[1] = sockets[2] = sockets[3] = NULL;
	}
	g_object_unref (msg);

	debug_printf (1, "    Second message\n");
	msg = soup_message_new_from_uri ("GET", base_uri);
	soup_session_send_message (session, msg);
	if (msg->status_code != SOUP_STATUS_OK) {
		debug_printf (1, "      Unexpected response: %d %s\n",
			      msg->status_code, msg->reason_phrase);
		errors++;
	}
	if (sockets[1] != sockets[0]) {
		debug_printf (1, "      Message was not retried on existing connection\n");
		errors++;
	} else if (!sockets[2]) {
		debug_printf (1, "      Message was not retried after disconnect\n");
		errors++;
	} else if (sockets[2] == sockets[1]) {
		debug_printf (1, "      Message was retried on closed connection??\n");
		errors++;
	} else if (sockets[3]) {
		debug_printf (1, "      Message was retried again??\n");
		errors++;
	}
	g_object_unref (msg);

	for (i = 0; sockets[i]; i++)
		g_object_unref (sockets[i]);
}

static void
do_persistent_connection_timeout_test (void)
{
	SoupSession *session;

	debug_printf (1, "\nUnexpected timing out of persistent connections\n");

	debug_printf (1, "  Async session\n");
	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC, NULL);
	do_timeout_test_for_session (session);
	soup_test_session_abort_unref (session);

	debug_printf (1, "  Sync session\n");
	session = soup_test_session_new (SOUP_TYPE_SESSION_SYNC, NULL);
	do_timeout_test_for_session (session);
	soup_test_session_abort_unref (session);
}

static GMainLoop *max_conns_loop;
static int msgs_done;
static guint quit_loop_timeout;
#define MAX_CONNS 2
#define TEST_CONNS (MAX_CONNS * 2)

static gboolean
idle_start_server (gpointer data)
{
	g_mutex_unlock (&server_mutex);
	return FALSE;
}

static gboolean
quit_loop (gpointer data)
{
	quit_loop_timeout = 0;
	g_main_loop_quit (max_conns_loop);
	return FALSE;
}

static void
max_conns_request_started (SoupSession *session, SoupMessage *msg,
			   SoupSocket *socket, gpointer user_data)
{
	if (++msgs_done == MAX_CONNS) {
		if (quit_loop_timeout)
			g_source_remove (quit_loop_timeout);
		quit_loop_timeout = g_timeout_add (100, quit_loop, NULL);
	}
}

static void
max_conns_message_complete (SoupSession *session, SoupMessage *msg, gpointer user_data)
{
	if (++msgs_done == TEST_CONNS)
		g_main_loop_quit (max_conns_loop);
}

static void
do_max_conns_test_for_session (SoupSession *session)
{
	SoupMessage *msgs[TEST_CONNS];
	int i;

	max_conns_loop = g_main_loop_new (NULL, TRUE);

	g_mutex_lock (&server_mutex);

	g_signal_connect (session, "request-started",
			  G_CALLBACK (max_conns_request_started), NULL);
	msgs_done = 0;
	for (i = 0; i < TEST_CONNS; i++) {
		msgs[i] = soup_message_new_from_uri ("GET", base_uri);
		g_object_ref (msgs[i]);
		soup_session_queue_message (session, msgs[i],
					    max_conns_message_complete, NULL);
	}

	g_main_loop_run (max_conns_loop);
	if (msgs_done != MAX_CONNS) {
		debug_printf (1, "  Queued %d connections out of max %d?",
			      msgs_done, MAX_CONNS);
		errors++;
	}
	g_signal_handlers_disconnect_by_func (session, max_conns_request_started, NULL);

	msgs_done = 0;
	g_idle_add (idle_start_server, NULL);
	quit_loop_timeout = g_timeout_add (1000, quit_loop, NULL);
	g_main_loop_run (max_conns_loop);

	for (i = 0; i < TEST_CONNS; i++) {
		if (!SOUP_STATUS_IS_SUCCESSFUL (msgs[i]->status_code)) {
			debug_printf (1, "    Message %d failed? %d %s\n",
				      i, msgs[i]->status_code,
				      msgs[i]->reason_phrase ? msgs[i]->reason_phrase : "-");
			errors++;
		}
	}

	if (msgs_done != TEST_CONNS) {
		/* Clean up so we don't get a spurious "Leaked
		 * session" error.
		 */
		for (i = 0; i < TEST_CONNS; i++)
			soup_session_cancel_message (session, msgs[i], SOUP_STATUS_CANCELLED);
		g_main_loop_run (max_conns_loop);
	}

	g_main_loop_unref (max_conns_loop);
	if (quit_loop_timeout)
		g_source_remove (quit_loop_timeout);

	for (i = 0; i < TEST_CONNS; i++)
		g_object_unref (msgs[i]);
}

static void
do_max_conns_test (void)
{
	SoupSession *session;

	debug_printf (1, "\nExceeding max-conns\n");

	debug_printf (1, "  Async session\n");
	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC,
					 SOUP_SESSION_MAX_CONNS, MAX_CONNS,
					 NULL);
	do_max_conns_test_for_session (session);
	soup_test_session_abort_unref (session);

	debug_printf (1, "  Sync session\n");
	session = soup_test_session_new (SOUP_TYPE_SESSION_SYNC,
					 SOUP_SESSION_MAX_CONNS, MAX_CONNS,
					 NULL);
	do_max_conns_test_for_session (session);
	soup_test_session_abort_unref (session);
}

GMainLoop *loop;

static void
np_request_started (SoupSession *session, SoupMessage *msg,
		    SoupSocket *socket, gpointer user_data)
{
	SoupSocket **save_socket = user_data;

	*save_socket = g_object_ref (socket);
}

static void
np_request_unqueued (SoupSession *session, SoupMessage *msg,
		     gpointer user_data)
{
	SoupSocket *socket = *(SoupSocket **)user_data;

	if (soup_socket_is_connected (socket)) {
		debug_printf (1, "    socket is still connected\n");
		errors++;
	}

	g_main_loop_quit (loop);
}

static void
do_non_persistent_test_for_session (SoupSession *session)
{
	SoupMessage *msg;
	SoupSocket *socket = NULL;

	loop = g_main_loop_new (NULL, FALSE);

	g_signal_connect (session, "request-started",
			  G_CALLBACK (np_request_started),
			  &socket);
	g_signal_connect (session, "request-unqueued",
			  G_CALLBACK (np_request_unqueued),
			  &socket);

	msg = soup_message_new_from_uri ("GET", base_uri);
	soup_message_headers_append (msg->request_headers, "Connection", "close");
	g_object_ref (msg);
	soup_session_queue_message (session, msg, NULL, NULL);
	g_main_loop_run (loop);

	if (msg->status_code != SOUP_STATUS_OK) {
		debug_printf (1, "      Unexpected response: %d %s\n",
			      msg->status_code, msg->reason_phrase);
		errors++;
	}
	g_object_unref (msg);
}

static void
do_non_persistent_connection_test (void)
{
	SoupSession *session;

	debug_printf (1, "\nNon-persistent connections are closed immediately\n");

	debug_printf (1, "  Async session\n");
	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC, NULL);
	do_non_persistent_test_for_session (session);
	soup_test_session_abort_unref (session);

	debug_printf (1, "  Sync session\n");
	session = soup_test_session_new (SOUP_TYPE_SESSION_SYNC, NULL);
	do_non_persistent_test_for_session (session);
	soup_test_session_abort_unref (session);
}

static void
do_non_idempotent_test_for_session (SoupSession *session)
{
	SoupMessage *msg;
	SoupSocket *sockets[4] = { NULL, NULL, NULL, NULL };
	int i;

	g_signal_connect (session, "request-started",
			  G_CALLBACK (request_started_socket_collector),
			  &sockets);

	debug_printf (2, "    GET\n");
	msg = soup_message_new_from_uri ("GET", base_uri);
	soup_session_send_message (session, msg);
	if (msg->status_code != SOUP_STATUS_OK) {
		debug_printf (1, "      Unexpected response: %d %s\n",
			      msg->status_code, msg->reason_phrase);
		errors++;
	}
	if (sockets[1]) {
		debug_printf (1, "      Message was retried??\n");
		errors++;
		sockets[1] = sockets[2] = sockets[3] = NULL;
	}
	g_object_unref (msg);

	debug_printf (2, "    POST\n");
	msg = soup_message_new_from_uri ("POST", base_uri);
	soup_session_send_message (session, msg);
	if (msg->status_code != SOUP_STATUS_OK) {
		debug_printf (1, "      Unexpected response: %d %s\n",
			      msg->status_code, msg->reason_phrase);
		errors++;
	}
	if (sockets[1] == sockets[0]) {
		debug_printf (1, "      Message was sent on existing connection!\n");
		errors++;
	}
	if (sockets[2]) {
		debug_printf (1, "      Too many connections used...\n");
		errors++;
	}
	g_object_unref (msg);

	for (i = 0; sockets[i]; i++)
		g_object_unref (sockets[i]);
}

static void
do_non_idempotent_connection_test (void)
{
	SoupSession *session;

	debug_printf (1, "\nNon-idempotent methods are always sent on new connections\n");

	debug_printf (1, "  Async session\n");
	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC, NULL);
	do_non_idempotent_test_for_session (session);
	soup_test_session_abort_unref (session);

	debug_printf (1, "  Sync session\n");
	session = soup_test_session_new (SOUP_TYPE_SESSION_SYNC, NULL);
	do_non_idempotent_test_for_session (session);
	soup_test_session_abort_unref (session);
}

int
main (int argc, char **argv)
{
	test_init (argc, argv, NULL);

	server = soup_test_server_new (TRUE);
	soup_server_add_handler (server, NULL, server_callback, "http", NULL);
	base_uri = soup_uri_new ("http://127.0.0.1/");
	soup_uri_set_port (base_uri, soup_server_get_port (server));

	do_content_length_framing_test ();
	do_persistent_connection_timeout_test ();
	do_max_conns_test ();
	do_non_persistent_connection_test ();
	do_non_idempotent_connection_test ();

	soup_uri_free (base_uri);
	soup_test_server_quit_unref (server);

	test_cleanup ();
	return errors != 0;
}
