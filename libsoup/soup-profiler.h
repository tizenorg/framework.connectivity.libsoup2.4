/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-profiler.h:
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

#ifndef SOUP_PROFILER_H
#define SOUP_PROFILER_H 1

#include <libsoup/soup-types.h>
#include "soup-misc.h"
#include <gio/gio.h>
#include <stdio.h>
#include <sys/time.h>

G_BEGIN_DECLS

typedef enum {
	SOUP_PROFILE_CONN_REQUESTED,
	SOUP_PROFILE_CONN_CONNECTED,
	SOUP_PROFILE_CONN_CLOSED,
	SOUP_PROFILE_CONN_CHANGED
} ProfileConnectionStateEnum;

typedef struct {
	SoupConnectionState     state;
	struct timeval          time_stamp;
	char                    *using_uri;
} ProfileConnectionState;

typedef struct {
	char    *delegate_uri;
	guint   delegate_hit_count;
	guint   conn_count_before;
	guint   conn_count_after;
	guint   conn_count_current;
	GSList  *connected_entry; /* data : ProfileEntry */
	GSList  *non_connected_entry_for_hit_ratio; /* data : ProfileEntry */
	GSList  *non_connected_entry_for_host_idle_conn; /* data : ProfileEntry */
	GSList  *non_connected_entry_for_max_conn; /* data : ProfileEntry */
	guint   delay_count_for_print;

	guint   ref_count;
} PreconnectionProfile;

typedef enum {
	PROFILE_ENTRY_TYPE_CONNECTED,
	PROFILE_ENTRY_TYPE_NON_CONNECTED
} ProfileEntryType;

typedef enum {
	PROFILE_ENTRY_REASON_NONE,
	PROFILE_ENTRY_REASON_HIT_RATIO,
	PROFILE_ENTRY_REASON_HOST_IDLE_CONN,
	PROFILE_ENTRY_REASON_MAX_CONN
} ProfileEntryReason;

typedef struct {
	PreconnectionProfile    *profile;
	guint                   hit_count;
	char                    *uri;
	struct timeval          requested_time;
	struct timeval          connected_time;
	struct timeval          closed_time;
	guint                   how_many_used;
	GSList                  *conn_state_list; /* data : ProfileConnectionState * */

	guint                   ref_count;
} ProfileEntry;

ProfileConnectionState *new_profile_connection_state (void);
void free_profile_connection_state (gpointer data);

ProfileEntry *insert_new_profile_entry (PreconnectionProfile *profile, char *uri, guint hit_count, ProfileEntryType type, ProfileEntryReason reason);
ProfileEntry *new_profile_entry (char *uri, guint hit_count);
void free_profile_entry (ProfileEntry *entry);
ProfileEntry *ref_profile_entry (ProfileEntry *entry);
ProfileEntry *unref_profile_entry (gpointer data);

PreconnectionProfile *new_profile1 (char *uri, guint16 hit_count, guint   conn_count_before);
void free_profile1 (PreconnectionProfile *profile);
PreconnectionProfile *ref_profile (PreconnectionProfile *profile);
PreconnectionProfile *unref_profile (gpointer data);

void print_connection_profile1 (GSList *list, FILE *fd_summary, FILE *fd_detail);
void print_connection_profile (GSList *list);
GSList * check_and_print_profile (GSList *profile_list);

char *convert_conn_state_to_string (SoupConnectionState state);

void soup_profiler_insert_connection_state (ProfileEntry *profile_entry, SoupConnection *conn, ProfileConnectionStateEnum state);

G_END_DECLS

#endif /* SOUP_PROFILER_H */
