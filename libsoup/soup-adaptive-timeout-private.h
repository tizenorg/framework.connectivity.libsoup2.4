/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-adaptive-timeout-private.h:
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

#ifndef SOUP_ADAPTIVE_TIMEOUT_PRIVATE_H
#define SOUP_ADAPTIVE_TIMEOUT_PRIVATE_H 1

#include "soup-uri.h"
#include "soup-types.h"
#include "soup-session-async.h"
#include "soup-message-queue.h"

G_BEGIN_DECLS

typedef struct {
	guint status_code;
	guint timeout;
} SoupAdaptiveTimeout;


#define ADAPTIVE_TIMEOUT_QUERY_ALL "SELECT id, host, status, timeout FROM tizen_aht;"
#define ADAPTIVE_TIMEOUT_QUERY_HOST "SELECT id, host, status, timeout FROM tizen_aht WHERE host=%Q;"
#define ADAPTIVE_TIMEOUT_CREATE_TABLE "CREATE TABLE tizen_aht (id INTEGER PRIMARY KEY, host TEXT, status INTEGER, timeout INTEGER)"
#define ADAPTIVE_TIMEOUT_QUERY_INSERT "INSERT INTO tizen_aht VALUES(NULL, %Q, %d, %d);"
#define ADAPTIVE_TIMEOUT_QUERY_DELETE "DELETE FROM tizen_aht WHERE host=%Q;"

gboolean soup_adaptive_timeout_exec_query(const char *sql, SoupAdaptiveTimeout *data, gboolean tryCreate);


void soup_adaptive_timeout_change_timeout(SoupConnection *conn, int timeout);
void soup_adaptive_timeout_delete_from_db(char *host);
void soup_adaptive_timeout_set_dead_link_data(SoupMessageQueueItem *item, guint status, int timeout);
void soup_adaptive_timeout_get_dead_link_data(char *currUri, SoupAdaptiveTimeout *deadLinkData);
void soup_adaptive_timeout_remove_dead_link(SoupSession *session, char *host);
void soup_adaptive_timeout_set_dead_link_running_status(SoupSession *session, char *host, gboolean is_probing);
int  soup_adaptive_timeout_get_dead_link_running_status(SoupSession *session, char *host);
void soup_adaptive_timeout_close_db(void);

G_END_DECLS

#endif /* SOUP_ADAPTIVE_TIMEOUT_PRIVATE_H */
