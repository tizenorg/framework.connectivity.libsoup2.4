/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-adaptive-timeout.c
 *
 * Copyright (C) 2012 Samsung Electronics
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include "soup-adaptive-timeout-private.h"
#include <sqlite3.h>

enum {
	ADAPTIVE_TIMEOUT_COL_ID,
	ADAPTIVE_TIMEOUT_COL_HOST,
	ADAPTIVE_TIMEOUT_COL_STATUS,
	ADAPTIVE_TIMEOUT_COL_TIMEOUT
};

static sqlite3 *adaptiveTimeoutdb = NULL;

static gboolean
soup_adaptive_timeout_open_db(sqlite3 **db)
{
	if (sqlite3_open ("/opt/usr/apps/org.tizen.browser/data/.webkit/soupData/cookie/.ahtdb.db", db)) {
		sqlite3_close (*db);
		*db = NULL;
		return TRUE;
	}
	return FALSE;
}

void
soup_adaptive_timeout_close_db(void)
{
	if(adaptiveTimeoutdb) {
		sqlite3_close (adaptiveTimeoutdb);
		adaptiveTimeoutdb = NULL;
	}
}

static int
soup_adaptive_timeout_callback (void *data, int argc, char **argv, char **colname)
{
	char *host;
	char *status, *timeout;
	SoupAdaptiveTimeout *adaptiveTimeoutData;

	host = argv[ADAPTIVE_TIMEOUT_COL_HOST];
	status = argv[ADAPTIVE_TIMEOUT_COL_STATUS];
	timeout = argv[ADAPTIVE_TIMEOUT_COL_TIMEOUT];
	if(data != NULL)
	{
		adaptiveTimeoutData = (SoupAdaptiveTimeout *)data;
		adaptiveTimeoutData->status_code= atoi(status);
		adaptiveTimeoutData->timeout = atoi(timeout);
	}

	return 0;
}

static void
soup_adaptive_timeout_try_create_table (sqlite3 *db)
{
	char *error = NULL;

	if (sqlite3_exec (db, ADAPTIVE_TIMEOUT_CREATE_TABLE, NULL, NULL, &error)) {
		g_warning ("Failed to execute query: %s", error);
		sqlite3_free (error);
	}
}

static gboolean
soup_adaptive_timeout_exec_query_create_table(sqlite3 *db,
				  const char *sql,
				  gboolean try_create,
				  int (*soup_adaptive_timeout_callback)(void*,int,char**,char**),
				  void *argument)
{
	char *error = NULL;

	if (try_create) {
		if (sqlite3_exec (db, sql, soup_adaptive_timeout_callback, argument, &error)) {
			try_create = FALSE;
			soup_adaptive_timeout_try_create_table (db);
			sqlite3_free (error);
			error = NULL;
		} else {
			g_warning ("Failed to execute query: %s", error);
			sqlite3_free (error);
			return FALSE;
		}
	}

	if (sqlite3_exec (db, sql, soup_adaptive_timeout_callback, argument, &error)) {
		g_warning ("Failed to execute query: %s", error);
		sqlite3_free (error);
		return FALSE;
	}

	return TRUE;
}

gboolean
soup_adaptive_timeout_exec_query(const char *sql, SoupAdaptiveTimeout *data, gboolean tryCreate)
{
	gboolean status = FALSE;

	if(adaptiveTimeoutdb == NULL)
	{
		if(soup_adaptive_timeout_open_db(&adaptiveTimeoutdb))
		{
			return status;
		}
	}
	status = soup_adaptive_timeout_exec_query_create_table(adaptiveTimeoutdb, sql, tryCreate, soup_adaptive_timeout_callback, data);

	return status;
}

void
soup_adaptive_timeout_change_timeout(SoupConnection *conn, int timeout)
{
	g_object_set(conn, "timeout", timeout, NULL);
	g_object_notify (G_OBJECT (conn), "state");
}

static void
soup_adaptive_timeout_insert_to_db(char *host, int status, int timeout)
{
	char *query = NULL;

	query = sqlite3_mprintf (ADAPTIVE_TIMEOUT_QUERY_DELETE, host);
	soup_adaptive_timeout_exec_query(query, NULL, FALSE);
	sqlite3_free (query);

	query = sqlite3_mprintf (ADAPTIVE_TIMEOUT_QUERY_INSERT,
					 host,
					 status,
					 timeout);
	soup_adaptive_timeout_exec_query(query, NULL, TRUE);
	sqlite3_free (query);
}

void
soup_adaptive_timeout_delete_from_db(char *host)
{
	char *query = NULL;

	query = sqlite3_mprintf (ADAPTIVE_TIMEOUT_QUERY_DELETE, host);
	soup_adaptive_timeout_exec_query(query, NULL, FALSE);
	sqlite3_free (query);
}

void
soup_adaptive_timeout_set_dead_link_data(SoupMessageQueueItem *item, guint status, int timeout)
{
	SoupURI *uri = soup_message_get_uri(item->msg);
	soup_adaptive_timeout_insert_to_db(uri->host, status, timeout);
}

void
soup_adaptive_timeout_get_dead_link_data(char *host, SoupAdaptiveTimeout *deadLinkData)
{
	char *query = NULL;

	query = sqlite3_mprintf (ADAPTIVE_TIMEOUT_QUERY_HOST, host);
	soup_adaptive_timeout_exec_query(query, deadLinkData, TRUE);
	sqlite3_free (query);
}

