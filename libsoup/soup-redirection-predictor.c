/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-redirection-predictor.c
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
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "soup-redirection-predictor-private.h"

#define LIBSOUP_USE_UNSTABLE_REQUEST_API

#include "soup-uri.h"
#include "soup-session.h"
#include "soup-session-feature.h"
#include "soup-cache.h"
#include "soup-cache-private.h"
#include "soup-content-sniffer.h"
#include "soup-http-input-stream.h"
#include "soup-headers.h"
#include "TIZEN.h"

#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

static SoupSessionFeatureInterface *soup_redirection_predictor_default_feature_interface;
static void soup_redirection_predictor_session_feature_init (SoupSessionFeatureInterface *feature_interface, gpointer interface_data);

typedef struct _WkextRpInfo {
    const char *method;
    int method_len;
    const char *scheme;
    int scheme_len;

    int status_code;
    const char *location;
    int location_len;
    const char *cookie;
    int cookie_len;
} WkextRpInfo;

typedef enum {
	PREDICT_CHAIN_ENTRY_TYPE_USE_CACHE,
	PREDICT_CHAIN_ENTRY_TYPE_LOAD_FROM_NETWORK
} PredictChainEntryType;

typedef enum {
	REDIRECTION_PREDICT_TYPE_CACHEABLE,
	REDIRECTION_PREDICT_TYPE_PREDICTABLE,
	REDIRECTION_PREDICT_TYPE_UNPREDICTABLE
} RedirectionPredictType;

typedef struct _RedirectionHistoryEntry {
	char *redirected_url;
	char *reason_phrase;
	guint16 status_code;
	RedirectionPredictType redirection_predict_type;
	SoupMessageHeaders *response_headers;
} RedirectionHistoryEntry;

typedef struct _PredictChainEntry {
	SoupMessage *prediction_msg;
	PredictChainEntryType expecting_type;
	gboolean is_result_msg;
	gboolean is_valid;
	gboolean is_finished_msg;
} PredictChainEntry;

typedef struct _SoupRedirectionPredictChain {
	SoupSession *session;
	SoupMessage *original_msg;
	GList *predict_chain_entries;
	GHashTable *entry_table;
	GQueue *chunk_queue;
	gboolean is_valid;
} SoupRedirectionPredictChain;

struct _SoupRedirectionPredictorPrivate {
	char *redirection_predictor_dir;
	SoupSession *session;
	GHashTable *history_table;
	GHashTable *blacklist_table;

	void *ext_handle;
	int (*rp_is_predictable)(WkextRpInfo *);
	int (*rp_is_valid)(WkextRpInfo *, WkextRpInfo *);
};

enum {
	PROP_0,
	PROP_REDIRECTION_PREDICTOR_DIR
};

static const char *redirection_blacklist_table[] = {
	"tinyurl.com", "pic.twitter.com", "t.co", "twitter.com", "www.cdiscount.com",
	NULL
};

typedef struct _FixedRedirectionHistoryEntry {
	char *url;
	char *redirected_url;
	char *reason_phrase;
	guint16 status_code;
	RedirectionPredictType redirection_predict_type;
} FixedRedirectionHistoryEntry;

static const FixedRedirectionHistoryEntry fixed_redirection_history_table[] = {
	{"http://www.webmd.com/", "http://www.m.webmd.com/default.htm", "Found", 302, REDIRECTION_PREDICT_TYPE_PREDICTABLE},
};

#define SOUP_REDIRECTION_PREDICTOR_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), SOUP_TYPE_REDIRECTION_PREDICTOR, SoupRedirectionPredictorPrivate))
#define SOUP_REDIRECTION_PREDICTOR_MAX_REDIRECTION_COUNT 20

G_DEFINE_TYPE_WITH_CODE (SoupRedirectionPredictor, soup_redirection_predictor, G_TYPE_OBJECT,
							G_IMPLEMENT_INTERFACE (SOUP_TYPE_SESSION_FEATURE,
							soup_redirection_predictor_session_feature_init))

static int
soup_redirection_predictor_extention_is_predictable (SoupRedirectionPredictor *redirection_predictor, WkextRpInfo *info)
{
	SoupRedirectionPredictorPrivate *priv;
	char *error = NULL;

	priv = SOUP_REDIRECTION_PREDICTOR_GET_PRIVATE (redirection_predictor);
	if (!priv)
		return 0;

	if (!priv->ext_handle) {
		dlerror (); // clear error
		priv->ext_handle = dlopen ("libewebkit2-ext.so", RTLD_LAZY);
		if (!priv->ext_handle) {
			TIZEN_LOGE ("no handle [%s]", dlerror ());
			return 0;
		}
	}

	if (!priv->rp_is_predictable) {
		dlerror (); // clear error
		priv->rp_is_predictable = dlsym (priv->ext_handle, "wkext_rp_is_predictable");
		if ((error = dlerror ()) != NULL) {
			TIZEN_LOGE ("no sym [%s]", error);
			return 0;
		}
	}

	return priv->rp_is_predictable (info);
}

static gboolean
soup_redirection_predictor_extention_is_valid (SoupSession *session, WkextRpInfo *org, WkextRpInfo *predicted)
{
	SoupRedirectionPredictor *redirection_predictor = NULL;
	SoupRedirectionPredictorPrivate *priv;
	char *error = NULL;
	int is_valid = 0;
	gboolean ret = FALSE;

	redirection_predictor = (SoupRedirectionPredictor *)soup_session_get_feature (session, SOUP_TYPE_REDIRECTION_PREDICTOR);
	if (!redirection_predictor)
		return FALSE;

	priv = SOUP_REDIRECTION_PREDICTOR_GET_PRIVATE (redirection_predictor);
	if (!priv)
		return FALSE;

	if (!priv->ext_handle) {
		dlerror (); // clear error
		priv->ext_handle = dlopen ("libewebkit2-ext.so", RTLD_LAZY);
		if (!priv->ext_handle) {
			TIZEN_LOGE ("no handle [%s]", dlerror ());
			return FALSE;
		}
	}

	if (!priv->rp_is_valid) {
		dlerror (); // clear error
		priv->rp_is_valid = dlsym (priv->ext_handle, "wkext_rp_is_valid");
		if ((error = dlerror ()) != NULL) {
			TIZEN_LOGE ("no sym [%s]", error);
			return FALSE;
		}
	}

	is_valid = priv->rp_is_valid (org, predicted);
	if (is_valid % 10)
		ret = TRUE;

	return ret;
}

static void
predict_chain_entry_free (gpointer user_data)
{
	PredictChainEntry *entry = (PredictChainEntry *)user_data;

	g_object_unref (entry->prediction_msg);
	g_slice_free (PredictChainEntry, entry);
}


static void
predict_chain_free (SoupRedirectionPredictChain *redirection_predict_chain)
{
	g_object_unref (redirection_predict_chain->session);
	g_object_unref (redirection_predict_chain->original_msg);

	if (redirection_predict_chain->entry_table)
		g_hash_table_destroy (redirection_predict_chain->entry_table);
	if (redirection_predict_chain->predict_chain_entries)
		g_list_free_full (redirection_predict_chain->predict_chain_entries, (GDestroyNotify) predict_chain_entry_free);

	if (redirection_predict_chain->chunk_queue) {
		g_queue_foreach (redirection_predict_chain->chunk_queue, (GFunc) soup_buffer_free, NULL);
		g_queue_free (redirection_predict_chain->chunk_queue);
	}
}

static void
free_history_table (gpointer data)
{
	RedirectionHistoryEntry *redirection_history_entry = (RedirectionHistoryEntry *)data;

	if (redirection_history_entry->redirected_url)
		g_free(redirection_history_entry->redirected_url);

	if (redirection_history_entry->reason_phrase)
		g_free(redirection_history_entry->reason_phrase);

	if (redirection_history_entry->response_headers)
		soup_message_headers_free (redirection_history_entry->response_headers);
}

static void
soup_redirection_predictor_init (SoupRedirectionPredictor *redirection_predictor)
{
	SoupRedirectionPredictorPrivate *priv = SOUP_REDIRECTION_PREDICTOR_GET_PRIVATE(redirection_predictor);
	int i = 0;
	priv->session = NULL;
	priv->history_table = g_hash_table_new_full (g_str_hash, g_str_equal,
							(GDestroyNotify)g_free, (GDestroyNotify)free_history_table);

	for (i = 0 ; i < G_N_ELEMENTS (fixed_redirection_history_table) ; i++) {
		RedirectionHistoryEntry *redirection_history_entry = g_slice_new0 (RedirectionHistoryEntry);

		redirection_history_entry->redirected_url = g_strdup(fixed_redirection_history_table[i].redirected_url);
		redirection_history_entry->reason_phrase = g_strdup(fixed_redirection_history_table[i].reason_phrase);
		redirection_history_entry->status_code = fixed_redirection_history_table[i].status_code;
		redirection_history_entry->redirection_predict_type = fixed_redirection_history_table[i].redirection_predict_type;

		redirection_history_entry->response_headers = soup_message_headers_new (SOUP_MESSAGE_HEADERS_RESPONSE);
		soup_message_headers_append(redirection_history_entry->response_headers, "Location", fixed_redirection_history_table[i].redirected_url);

		g_hash_table_insert (priv->history_table, g_strdup (fixed_redirection_history_table[i].url), redirection_history_entry);

	}

	priv->blacklist_table = g_hash_table_new (g_str_hash, g_str_equal);
	i = 0;
	while (redirection_blacklist_table[i] != NULL) {
		g_hash_table_insert (priv->blacklist_table,
				(gpointer)redirection_blacklist_table[i],
				GUINT_TO_POINTER (1));
		++i;
	}
}

static void
soup_redirection_predictor_set_property (GObject *object, guint prop_id,
							const GValue *value, GParamSpec *pspec)
{
	SoupRedirectionPredictorPrivate *priv = SOUP_REDIRECTION_PREDICTOR_GET_PRIVATE(object);

	switch (prop_id) {
		case PROP_REDIRECTION_PREDICTOR_DIR:
			priv->redirection_predictor_dir = g_value_dup_string (value);
			break;
		default:
			G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
			break;
	}
}

static void
soup_redirection_predictor_get_property (GObject *object, guint prop_id,
							GValue *value, GParamSpec *pspec)
{
	SoupRedirectionPredictorPrivate *priv = SOUP_REDIRECTION_PREDICTOR_GET_PRIVATE(object);

	switch (prop_id) {
	case PROP_REDIRECTION_PREDICTOR_DIR:
		g_value_set_string (value, priv->redirection_predictor_dir);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
soup_redirection_predictor_finalize (GObject *object)
{
	SoupRedirectionPredictorPrivate *priv = SOUP_REDIRECTION_PREDICTOR_GET_PRIVATE(object);

	g_free (priv->redirection_predictor_dir);
	g_hash_table_destroy (priv->history_table);
	g_hash_table_destroy (priv->blacklist_table);

	if (priv->ext_handle) {
		dlclose (priv->ext_handle);

		priv->rp_is_predictable = NULL;
		priv->rp_is_valid = NULL;
		priv->ext_handle = NULL;
	}

	G_OBJECT_CLASS (soup_redirection_predictor_parent_class)->finalize (object);
}

static void
soup_redirection_predictor_class_init (SoupRedirectionPredictorClass *redirection_predictor_class)
{
	GObjectClass *gobject_class = (GObjectClass *)redirection_predictor_class;

	gobject_class->finalize = soup_redirection_predictor_finalize;
	gobject_class->set_property = soup_redirection_predictor_set_property;
	gobject_class->get_property = soup_redirection_predictor_get_property;

	g_object_class_install_property (gobject_class, PROP_REDIRECTION_PREDICTOR_DIR,
										g_param_spec_string ("redirection-predictor-dir",
										"Redirection Predictor directory",
										"The directory to store the history for redirection predictor files",
										NULL,
										G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_type_class_add_private (redirection_predictor_class, sizeof (SoupRedirectionPredictorPrivate));
}

SoupRedirectionPredictor *
soup_redirection_predictor_new (const char *redirection_predictor_dir)
{
	return g_object_new (SOUP_TYPE_REDIRECTION_PREDICTOR,
							"redirection-predictor-dir", redirection_predictor_dir,
							NULL);
}

static void
soup_redirection_predictor_message_headers_copy (SoupMessageHeaders *src_hdrs, SoupMessageHeaders *dest_hdrs)
{
	SoupMessageHeadersIter iter;
	const char *hname, *value;

	soup_message_headers_iter_init (&iter, src_hdrs);
	while (soup_message_headers_iter_next (&iter, &hname, &value))
		soup_message_headers_replace (dest_hdrs, hname, value);
}

typedef struct {
	SoupSessionFeature *feature;
	gulong got_headers_handler;
} RequestHelper;

static gboolean
get_redirection_predictability_phase1 (SoupRedirectionPredictor *redirection_predictor, SoupMessage *msg)
{
	SoupURI *msg_uri;
	WkextRpInfo *info = NULL;
	int ext_is_predictable = 0;

	msg_uri = soup_message_get_uri (msg);

	info = g_slice_new0 (WkextRpInfo);
	if (!info)
		return FALSE;

	info->method = msg->method;
	info->method_len = info->method ? strlen (info->method) : 0;

	info->scheme = msg_uri->scheme;
	info->scheme_len = info->scheme ? strlen (info->scheme) : 0;

	info->location = soup_message_headers_get_one (msg->response_headers, "Location");
	info->location_len = info->location ? strlen (info->location) : 0;

	info->status_code = msg->status_code;

	ext_is_predictable = soup_redirection_predictor_extention_is_predictable (redirection_predictor, info);
	g_slice_free (WkextRpInfo, info);

	if (ext_is_predictable % 10)
		return TRUE;

	return FALSE;
}

static RedirectionPredictType
get_redirection_predictability (SoupRedirectionPredictor *redirection_predictor, SoupMessage *msg)
{
	gboolean is_predictable_phase1 = 0;
	const char *cache_control;

	is_predictable_phase1 = get_redirection_predictability_phase1 (redirection_predictor, msg);
	if (!is_predictable_phase1) {
		SoupRedirectionPredictorPrivate *priv;
		char *msg_url;

		priv = SOUP_REDIRECTION_PREDICTOR_GET_PRIVATE (redirection_predictor);
		msg_url = soup_uri_to_string (soup_message_get_uri (msg), FALSE);
		g_hash_table_remove (priv->history_table, g_strdup (msg_url));
		g_free (msg_url);
		return REDIRECTION_PREDICT_TYPE_UNPREDICTABLE;
	}

	cache_control = soup_message_headers_get (msg->response_headers, "Cache-Control");
	if (cache_control) {
		GHashTable *hash;
		gpointer value;
		int max_age = -1;

		hash = soup_header_parse_param_list (cache_control);
		if (g_hash_table_lookup_extended (hash, "no-store", NULL, NULL)) {
			soup_header_free_param_list (hash);
			return REDIRECTION_PREDICT_TYPE_PREDICTABLE;
		}

		if (g_hash_table_lookup_extended (hash, "no-cache", NULL, NULL)) {
			soup_header_free_param_list (hash);
			return REDIRECTION_PREDICT_TYPE_PREDICTABLE;
		}

		if (g_hash_table_lookup_extended (hash, "max-age", NULL, &value) && value) {
			max_age = (int)MIN (g_ascii_strtoll (value, NULL, 10), G_MAXINT32);
			if (!max_age) {
				soup_header_free_param_list (hash);
				return REDIRECTION_PREDICT_TYPE_PREDICTABLE;
			}
		}
		soup_header_free_param_list (hash);
	}

	if (msg->status_code == 301)
		return REDIRECTION_PREDICT_TYPE_CACHEABLE;

	return REDIRECTION_PREDICT_TYPE_PREDICTABLE;
}

static void
msg_got_headers_cb (SoupMessage *msg, gpointer user_data)
{
	SoupRedirectionPredictor *redirection_predictor;
	RequestHelper *helper;
	SoupRedirectionPredictorPrivate *priv;
	RedirectionPredictType redirection_predict_type;
	RedirectionHistoryEntry *redirection_history_entry;
	const char *location;
	char *msg_url;
	SoupURI *location_uri;
#if ENABLE(TIZEN_IGNORE_HOST_CHECK_FOR_TEL_SCHEME)
	const char *loc;
	SoupURI *loc_uri;
#endif

	helper = (RequestHelper *)user_data;
	redirection_predictor = SOUP_REDIRECTION_PREDICTOR (helper->feature);
	priv = SOUP_REDIRECTION_PREDICTOR_GET_PRIVATE (redirection_predictor);
	g_signal_handlers_disconnect_by_func (msg, msg_got_headers_cb, user_data);
	g_slice_free (RequestHelper, helper);

#if ENABLE(TIZEN_IGNORE_HOST_CHECK_FOR_TEL_SCHEME)
	loc = soup_message_headers_get_one (msg->response_headers, "Location");
	if (!loc)
		return;

	loc_uri = soup_uri_new_with_base (soup_message_get_uri (msg), loc);
	if (!loc_uri || !(loc_uri->scheme == SOUP_URI_SCHEME_HTTP || loc_uri->scheme == SOUP_URI_SCHEME_HTTPS)) {
		if (loc_uri)
			soup_uri_free (loc_uri);
		return;
	} else
		soup_uri_free (loc_uri);
#endif

	redirection_predict_type = get_redirection_predictability (redirection_predictor, msg);

	if (redirection_predict_type == REDIRECTION_PREDICT_TYPE_UNPREDICTABLE)
		return;
	else {      //REDIRECT_CACHEABLE or REDIRECT_PREDICTABLE
		redirection_history_entry = g_slice_new0 (RedirectionHistoryEntry);

		redirection_history_entry->redirection_predict_type = redirection_predict_type;

		location = soup_message_headers_get_one (msg->response_headers,"Location");
		location_uri = soup_uri_new_with_base (soup_message_get_uri (msg), location);
		redirection_history_entry->redirected_url = soup_uri_to_string (location_uri, FALSE);
		redirection_history_entry->status_code = msg->status_code;
		if (msg->reason_phrase)
			redirection_history_entry->reason_phrase = g_strdup (msg->reason_phrase);

		if (redirection_predict_type == REDIRECTION_PREDICT_TYPE_CACHEABLE) {
			redirection_history_entry->response_headers = soup_message_headers_new (SOUP_MESSAGE_HEADERS_RESPONSE);
			soup_redirection_predictor_message_headers_copy (msg->response_headers, redirection_history_entry->response_headers);
			soup_message_headers_remove (redirection_history_entry->response_headers, "Content-Length");
		}

		msg_url = soup_uri_to_string (soup_message_get_uri (msg), FALSE);
		g_hash_table_insert (priv->history_table, g_strdup (msg_url), redirection_history_entry);
		g_free (msg_url);
		soup_uri_free (location_uri);
	}
}

static void
request_started (SoupSessionFeature *feature, SoupSession *session,
					SoupMessage *msg, SoupSocket *socket)
{
	RequestHelper *helper = g_slice_new0 (RequestHelper);
	helper->feature = feature;
	helper->got_headers_handler = g_signal_connect (msg, "got-headers", G_CALLBACK (msg_got_headers_cb), helper);
}

static void
attach (SoupSessionFeature *feature, SoupSession *session)
{
	SoupRedirectionPredictor *redirection_predictor = SOUP_REDIRECTION_PREDICTOR (feature);
	SoupRedirectionPredictorPrivate *priv = SOUP_REDIRECTION_PREDICTOR_GET_PRIVATE (redirection_predictor);

	g_return_if_fail (priv != NULL);

	priv->session = session;
	soup_redirection_predictor_default_feature_interface->attach (feature, session);
}

static void
detach (SoupSessionFeature *feature, SoupSession *session)
{
	soup_redirection_predictor_default_feature_interface->detach (feature, session);
}

static void
soup_redirection_predictor_session_feature_init (SoupSessionFeatureInterface *feature_interface,
													gpointer interface_data)
{
	soup_redirection_predictor_default_feature_interface =
		g_type_default_interface_peek (SOUP_TYPE_SESSION_FEATURE);

	feature_interface->attach = attach;
	feature_interface->detach = detach;
	feature_interface->request_started = request_started;
}

static RedirectionHistoryEntry *
soup_redirection_predictor_has_redirection_history (SoupRedirectionPredictor *redirection_predictor, char *url)
{
	SoupRedirectionPredictorPrivate *priv;
	GHashTable *history_table, *blacklist_table;
	RedirectionHistoryEntry *redirection_history_entry;
	SoupURI *new_uri = soup_uri_new (url);

	priv = SOUP_REDIRECTION_PREDICTOR_GET_PRIVATE (redirection_predictor);
	g_return_val_if_fail (priv != NULL, NULL);

	blacklist_table = priv->blacklist_table;
	if (new_uri && new_uri->host && g_hash_table_lookup (blacklist_table, new_uri->host)) {
		soup_uri_free (new_uri);
		return NULL;
	}

	if (new_uri)
		soup_uri_free (new_uri);

	history_table = priv->history_table;
	redirection_history_entry = g_hash_table_lookup (history_table, url);

	if (!redirection_history_entry)
		return NULL;

	return redirection_history_entry;
}

static void
soup_redirection_predictor_send_redirection_cache (RedirectionHistoryEntry *redirection_history_entry, SoupMessage *original_msg)
{
	SoupURI *new_uri;
	SoupMessageHeaders *response_headers = redirection_history_entry->response_headers;
	guint16 status_code = redirection_history_entry->status_code;
	char *reason_phrase = NULL;

	if (redirection_history_entry->reason_phrase)
		reason_phrase = redirection_history_entry->reason_phrase;

	if (reason_phrase)
		soup_message_set_status_full (original_msg, status_code, reason_phrase);
	else
		soup_message_set_status (original_msg, status_code);

	soup_message_headers_clear (original_msg->response_headers);
	soup_redirection_predictor_message_headers_copy (response_headers, original_msg->response_headers);

	soup_message_got_headers (original_msg);

	new_uri = soup_uri_new (redirection_history_entry->redirected_url);
	soup_message_set_uri (original_msg, new_uri);
	soup_message_restarted (original_msg);
	soup_uri_free (new_uri);
}

static SoupRedirectionPredictChain *
soup_redirection_predictor_predict_chain_new (SoupSession *session, SoupMessage *original_msg)
{
	SoupRedirectionPredictChain *predict_chain;

	predict_chain = g_slice_new0 (SoupRedirectionPredictChain);
	predict_chain->session = g_object_ref (session);
	predict_chain->original_msg = g_object_ref (original_msg);
	predict_chain->chunk_queue = g_queue_new ();
	predict_chain->is_valid = FALSE;
	predict_chain->entry_table = g_hash_table_new (g_direct_hash, g_direct_equal);

	return predict_chain;
}

static PredictChainEntry *
predict_chain_entry_new (char *url)
{
	PredictChainEntry *chain_entry;

	chain_entry = g_slice_new0 (PredictChainEntry);
	chain_entry->prediction_msg = soup_message_new (SOUP_METHOD_GET, url);
	chain_entry->expecting_type = PREDICT_CHAIN_ENTRY_TYPE_LOAD_FROM_NETWORK;
	chain_entry->is_result_msg = FALSE;
	chain_entry->is_valid = FALSE;
	chain_entry->is_finished_msg = FALSE;

	return chain_entry;
}

static void
soup_redirection_predictor_copy_response_message (SoupMessage *src_msg, SoupMessage *dst_msg)
{
	if (!dst_msg->response_headers)
		return;

	soup_message_headers_clear (dst_msg->response_headers);

	soup_redirection_predictor_message_headers_copy (src_msg->response_headers, dst_msg->response_headers);

	if (dst_msg->reason_phrase) {
		g_free (dst_msg->reason_phrase);
		dst_msg->reason_phrase = NULL;
	}

	if(src_msg->reason_phrase)
		soup_message_set_status_full (dst_msg, src_msg->status_code, src_msg->reason_phrase);
	else
		soup_message_set_status (dst_msg, src_msg->status_code);
}

static PredictChainEntry *
soup_redirection_predictor_lookup_chain_entry (GHashTable *entry_table, SoupMessage *msg)
{
	gpointer entry_msg;
	gpointer result;

	if (g_hash_table_lookup_extended (entry_table, msg, &entry_msg, &result)) {
		if (!entry_msg)
			return NULL;
		return result;
	}
	else
		return NULL;
}

static gboolean
soup_redirection_predictor_message_has_main_resource (SoupMessage *msg, SoupRedirectionPredictChain *predict_chain)
{
	PredictChainEntry *entry;

	entry = soup_redirection_predictor_lookup_chain_entry (predict_chain->entry_table, msg);
	g_return_val_if_fail (entry != NULL, FALSE);

	if(entry->is_result_msg)
		return TRUE;
	else
		return FALSE;
}

static gboolean
soup_redirection_predictor_update_chain_validation (SoupRedirectionPredictChain *predict_chain)
{
	GList *list = predict_chain->predict_chain_entries;
	PredictChainEntry *entry;

	while(list) {
		entry = (PredictChainEntry *) list->data;
		if (!entry->is_valid) {
			return FALSE;
		} else
			list = g_list_next (list);
	}

	predict_chain->is_valid = TRUE;
	return TRUE;
}

static void
soup_redirection_predictor_predict_chain_append_entry (SoupRedirectionPredictChain *predict_chain, PredictChainEntry *chain_entry, gboolean needs_cache);

static void
soup_redirection_predictor_prediction_message_is_finished (SoupSession *session, SoupMessage *prediction_msg, gpointer user_data);

static void
soup_redirection_predictor_emit_signals (SoupRedirectionPredictChain *predict_chain)
{
	GList *list = predict_chain->predict_chain_entries;
	PredictChainEntry *prediction_entry = NULL;
	PredictChainEntry *location_entry = NULL;

	SoupMessage *original_msg, *prediction_msg, *location_msg;
	SoupBuffer *chunk_buffer = NULL;
	int list_length, i;

	original_msg = predict_chain->original_msg;

	list_length = g_list_length (list);

	for (i = 0; i < list_length; ++i) {
		prediction_entry = (PredictChainEntry *) g_list_nth_data (list, i);
		prediction_msg = prediction_entry->prediction_msg;

		soup_redirection_predictor_copy_response_message (prediction_msg, original_msg);
		soup_message_set_flags (original_msg, soup_message_get_flags (prediction_msg) & ~SOUP_MESSAGE_NO_REDIRECT);
		soup_message_got_headers (original_msg);

		if (i+1 < list_length) {
			location_entry = (PredictChainEntry *) g_list_nth_data (list, i+1);
			location_msg = location_entry->prediction_msg;
			soup_message_set_uri (original_msg, soup_message_get_uri (location_msg));
			soup_message_restarted (original_msg);
		}
	}

	if (soup_session_get_feature_for_message (predict_chain->session, SOUP_TYPE_CONTENT_SNIFFER, original_msg)) {
		const char *content_type = soup_message_headers_get (original_msg->response_headers, "Content-Type");
		soup_message_content_sniffed (original_msg, content_type, NULL);
	}

	while (!g_queue_is_empty (predict_chain->chunk_queue)) {
		chunk_buffer = g_queue_pop_head (predict_chain->chunk_queue);
		soup_message_got_chunk (original_msg, chunk_buffer);
		soup_buffer_free (chunk_buffer);
		chunk_buffer = NULL;
	}

	if (prediction_entry && prediction_entry->is_finished_msg) {
		soup_message_finished (original_msg);
		if (prediction_entry->expecting_type == PREDICT_CHAIN_ENTRY_TYPE_USE_CACHE)
			soup_redirection_predictor_prediction_message_is_finished (predict_chain->session, prediction_entry->prediction_msg, predict_chain);
	}
}

static void
soup_redirection_predictor_cancel (SoupRedirectionPredictChain *predict_chain, SoupMessage *msg)
{
	SoupSession *session = predict_chain->session;
	GList *list = predict_chain->predict_chain_entries;
	PredictChainEntry *entry;
	SoupBuffer *chunk_buffer = NULL;

	entry = soup_redirection_predictor_lookup_chain_entry (predict_chain->entry_table, msg);

	list = g_list_find (list, entry);
	list = g_list_next (list);
	while (list) {
		entry = (PredictChainEntry *) list->data;
		if (entry->is_result_msg)
			entry->is_result_msg = FALSE;
		if(!entry->is_finished_msg)
			soup_session_cancel_message (session, entry->prediction_msg, SOUP_STATUS_CANCELLED);
		g_hash_table_remove (predict_chain->entry_table, entry->prediction_msg);
		list = g_list_remove (list, entry);
	}

	while (!g_queue_is_empty (predict_chain->chunk_queue)) {
			chunk_buffer = g_queue_pop_head (predict_chain->chunk_queue);
			soup_buffer_free (chunk_buffer);
			chunk_buffer = NULL;
	}
}

static void
soup_redirection_predictor_send_new_prediction_message (SoupRedirectionPredictChain *predict_chain, SoupMessage *msg)
{
	PredictChainEntry *current_entry, *chain_entry;
	SoupURI *new_uri;
	const char *location;
	char *new_url;

	current_entry = soup_redirection_predictor_lookup_chain_entry (predict_chain->entry_table, msg);
	current_entry->is_valid = TRUE;

	location = soup_message_headers_get_one (msg->response_headers, "Location");
	g_return_if_fail (location != NULL);

	new_uri = soup_uri_new_with_base (soup_message_get_uri (msg), location);
	g_return_if_fail (new_uri != NULL);

	new_url = soup_uri_to_string (new_uri, FALSE);
	g_return_if_fail (new_url != NULL);

	chain_entry = predict_chain_entry_new (new_url);
	soup_uri_free (new_uri);
	g_free (new_url);

	chain_entry->is_result_msg = TRUE;

	soup_redirection_predictor_predict_chain_append_entry (predict_chain, chain_entry, TRUE);
	g_hash_table_insert (predict_chain->entry_table, chain_entry->prediction_msg, chain_entry);

	if (chain_entry->expecting_type == PREDICT_CHAIN_ENTRY_TYPE_USE_CACHE) {
		if (soup_redirection_predictor_update_chain_validation (predict_chain)) {
			soup_redirection_predictor_emit_signals (predict_chain);
			soup_redirection_predictor_prediction_message_is_finished (predict_chain->session, chain_entry->prediction_msg, predict_chain);
		}
	} else
		soup_session_queue_message (predict_chain->session, chain_entry->prediction_msg, soup_redirection_predictor_prediction_message_is_finished, predict_chain);
}

static gboolean
soup_redirection_predictor_check_validation_with_headers (SoupRedirectionPredictChain *predict_chain, SoupMessage *msg)
{
	GList *list = predict_chain->predict_chain_entries;
	PredictChainEntry *current_entry, *next_entry;
	gboolean is_valid = FALSE;
	WkextRpInfo *org;
	WkextRpInfo *predicted;

	current_entry = soup_redirection_predictor_lookup_chain_entry (predict_chain->entry_table, msg);
	g_return_val_if_fail (current_entry != NULL, FALSE);

	list = g_list_find(list, current_entry);
	if ((list = g_list_next (list))) {
		org = g_slice_new0 (WkextRpInfo);
		predicted = g_slice_new0 (WkextRpInfo);

		org->location = soup_message_headers_get_one (msg->response_headers, "Location");
		org->location_len = org->location ? strlen (org->location) : 0;
		org->status_code = msg->status_code;
		org->cookie = soup_message_headers_get_list (msg->response_headers, "Set-Cookie");
		org->cookie_len = org->cookie ? strlen (org->cookie) : 0;

		next_entry = (PredictChainEntry *) list->data;
		predicted->location = soup_uri_to_string (soup_message_get_uri (next_entry->prediction_msg), FALSE);
		predicted->location_len = predicted->location ? strlen (predicted->location) : 0;
		predicted->cookie = soup_message_headers_get_list (next_entry->prediction_msg->response_headers, "Set-Cookie");
		predicted->cookie_len = predicted->cookie ? strlen (predicted->cookie) : 0;

		is_valid = soup_redirection_predictor_extention_is_valid (predict_chain->session, org, predicted);

		g_free ((gpointer)predicted->location);
		g_slice_free (WkextRpInfo, org);
		g_slice_free (WkextRpInfo, predicted);

		if (is_valid)
			current_entry->is_valid = TRUE;

		if (SOUP_STATUS_IS_SUCCESSFUL (msg->status_code))
			current_entry->is_result_msg = TRUE;
	} else {
		current_entry->is_valid = TRUE;
		is_valid = TRUE;
	}

	return is_valid;
}

static void
soup_redirection_predictor_got_headers (SoupMessage *prediction_msg, SoupRedirectionPredictChain *predict_chain)
{
	GList *list;
	SoupMessage *original_msg;

	list = predict_chain->predict_chain_entries;
	original_msg = predict_chain->original_msg;

	if (soup_redirection_predictor_check_validation_with_headers (predict_chain, prediction_msg)) {
		if (soup_redirection_predictor_update_chain_validation (predict_chain)) {
			soup_redirection_predictor_emit_signals (predict_chain);
		}
	} else {
		soup_redirection_predictor_cancel (predict_chain, prediction_msg);
		if (soup_redirection_predictor_update_chain_validation (predict_chain)) { //200
			soup_redirection_predictor_emit_signals (predict_chain);
			return;
		}
		if (SOUP_STATUS_IS_REDIRECTION (prediction_msg->status_code)) {
			soup_redirection_predictor_send_new_prediction_message (predict_chain, prediction_msg);
		}
	}
}

static void
soup_redirection_predictor_got_chunk (SoupMessage *prediction_msg, SoupBuffer *chunk_buffer, SoupRedirectionPredictChain *predict_chain)
{
	SoupMessage *original_msg = predict_chain->original_msg;

	if (chunk_buffer->length == 0)
		return;

	if (soup_redirection_predictor_message_has_main_resource(prediction_msg, predict_chain)) {
		if (predict_chain->is_valid) {
			soup_message_got_chunk (original_msg, chunk_buffer);
		} else {
			g_queue_push_tail (predict_chain->chunk_queue, soup_buffer_copy (chunk_buffer));
		}
	}
}

static void
soup_redirection_predictor_restarted (SoupMessage *prediction_msg, SoupRedirectionPredictChain *predict_chain)
{
	SoupMessage *original_msg = predict_chain->original_msg;

	if (predict_chain->is_valid) {
		if (soup_redirection_predictor_message_has_main_resource(prediction_msg, predict_chain)) {
			soup_message_set_uri (original_msg, soup_message_get_uri (prediction_msg));
			soup_message_restarted (original_msg);
		}
	}
}

static void
soup_redirection_predictor_finished (SoupMessage *prediction_msg, SoupRedirectionPredictChain *predict_chain)
{
	SoupMessage *original_msg = predict_chain->original_msg;

	if (predict_chain->is_valid) {
		if (soup_redirection_predictor_message_has_main_resource(prediction_msg, predict_chain))
			soup_message_finished (original_msg);
	}

}

static gboolean
soup_redirection_predictor_is_finished (SoupRedirectionPredictChain *predict_chain)
{
	GList *list = predict_chain->predict_chain_entries;
	PredictChainEntry *entry;

	while (list) {
		entry = (PredictChainEntry *) list->data;
		if (!entry->is_finished_msg) {
			return FALSE;
		} else
			list = g_list_next (list);
	}
	return TRUE;
}

static void
soup_redirection_predictor_prediction_message_is_finished (SoupSession *session, SoupMessage *prediction_msg, gpointer user_data)
{
	SoupRedirectionPredictChain *predict_chain;
	PredictChainEntry *chain_entry;

	predict_chain = (SoupRedirectionPredictChain *)user_data;
	chain_entry = soup_redirection_predictor_lookup_chain_entry (predict_chain->entry_table, prediction_msg);
	g_return_if_fail (chain_entry != NULL);

	if (chain_entry->expecting_type == PREDICT_CHAIN_ENTRY_TYPE_LOAD_FROM_NETWORK) {
		chain_entry->is_finished_msg = TRUE;

		g_signal_handlers_disconnect_by_func (prediction_msg,
												G_CALLBACK (soup_redirection_predictor_got_headers), predict_chain);
		g_signal_handlers_disconnect_by_func (prediction_msg,
												G_CALLBACK (soup_redirection_predictor_got_chunk), predict_chain);
		g_signal_handlers_disconnect_by_func (prediction_msg,
												G_CALLBACK (soup_redirection_predictor_restarted), predict_chain);
		g_signal_handlers_disconnect_by_func (prediction_msg,
												G_CALLBACK (soup_redirection_predictor_finished), predict_chain);
	}

	if (soup_redirection_predictor_is_finished(predict_chain)) {
		predict_chain_free (predict_chain);
	}
}

static void
soup_redirection_predictor_predict_chain_append_entry (SoupRedirectionPredictChain *predict_chain, PredictChainEntry *chain_entry, gboolean needs_cache)
{
	SoupSession *session;
	SoupCache *cache;
	SoupMessage *prediction_msg;
	SoupCacheResponse response;
	SoupBuffer *msg_body;

	prediction_msg = chain_entry->prediction_msg;

	soup_redirection_predictor_message_headers_copy (predict_chain->original_msg->request_headers,
												prediction_msg->request_headers);
	g_return_if_fail (prediction_msg->request_headers);

	g_object_ref (prediction_msg);

	session = predict_chain->session;
	cache = (SoupCache *)soup_session_get_feature (session, SOUP_TYPE_CACHE);
	if (cache && needs_cache) {
		response = soup_cache_has_response (cache, prediction_msg);
		if (response == SOUP_CACHE_RESPONSE_FRESH) {
			msg_body = soup_cache_get_response (cache, prediction_msg);
			g_return_if_fail (msg_body != NULL);

			g_queue_push_tail (predict_chain->chunk_queue, msg_body);
			g_return_if_fail (predict_chain->chunk_queue != NULL);

			chain_entry->expecting_type = PREDICT_CHAIN_ENTRY_TYPE_USE_CACHE;
			chain_entry->is_result_msg = TRUE;
			chain_entry->is_valid = TRUE;
			chain_entry->is_finished_msg = TRUE;
			predict_chain->predict_chain_entries = g_list_append (predict_chain->predict_chain_entries, chain_entry);

			return;
		}
	}

	g_signal_connect (prediction_msg, "got_headers",
				G_CALLBACK (soup_redirection_predictor_got_headers), predict_chain);
	g_signal_connect (prediction_msg, "got_chunk",
				G_CALLBACK (soup_redirection_predictor_got_chunk), predict_chain);
	g_signal_connect (prediction_msg, "restarted",
				G_CALLBACK (soup_redirection_predictor_restarted), predict_chain);
	g_signal_connect (prediction_msg, "finished",
				G_CALLBACK (soup_redirection_predictor_finished), predict_chain);

	predict_chain->predict_chain_entries = g_list_append (predict_chain->predict_chain_entries, chain_entry);
}

static SoupRedirectionPredictChain *
soup_redirection_predictor_make_predict_chain (SoupRedirectionPredictor *redirection_predictor,
											SoupRedirectionPredictChain *predict_chain,
											char *url)
{
	PredictChainEntry *chain_entry;
	RedirectionHistoryEntry *redirection_history_entry;
	char *original_url, *predicted_url;
	int redirection_count = 0;

	original_url = soup_uri_to_string (soup_message_get_uri (predict_chain->original_msg), FALSE);
	chain_entry = predict_chain_entry_new (original_url);
	g_free (original_url);

	soup_redirection_predictor_predict_chain_append_entry (predict_chain, chain_entry, FALSE);
	g_hash_table_insert (predict_chain->entry_table, chain_entry->prediction_msg, chain_entry);

	predicted_url = url;
	while (1) {
		if (predicted_url) {
			chain_entry = predict_chain_entry_new (predicted_url);
			soup_redirection_predictor_predict_chain_append_entry (predict_chain, chain_entry, TRUE);
			g_hash_table_insert (predict_chain->entry_table, chain_entry->prediction_msg, chain_entry);
			redirection_history_entry = soup_redirection_predictor_has_redirection_history (redirection_predictor, predicted_url);
			if (redirection_history_entry && redirection_history_entry->redirection_predict_type == REDIRECTION_PREDICT_TYPE_PREDICTABLE) {
				predicted_url = redirection_history_entry->redirected_url;
			} else {
				predicted_url = NULL;
			}
			redirection_count++;
			if (redirection_count >= SOUP_REDIRECTION_PREDICTOR_MAX_REDIRECTION_COUNT) {
				predict_chain_entry_free (predict_chain);
				return NULL;
			}
			continue;
		} else {
			chain_entry->is_result_msg = TRUE;
			break;
		}
	}

	return predict_chain;
}

static void
soup_redirection_predictor_queue_prediction_messages (SoupRedirectionPredictChain *predict_chain)
{
	GList *list = predict_chain->predict_chain_entries;
	PredictChainEntry *entry;
	SoupMessageFlags flags;

	flags = soup_message_get_flags (predict_chain->original_msg);
	while (list) {
		entry = (PredictChainEntry *)list->data;
		if (entry->expecting_type == PREDICT_CHAIN_ENTRY_TYPE_LOAD_FROM_NETWORK) {
			if (!entry->is_result_msg) {
				flags |= SOUP_MESSAGE_NO_REDIRECT;
				soup_message_set_flags (entry->prediction_msg, flags);
			}
			soup_session_queue_message (predict_chain->session, entry->prediction_msg, soup_redirection_predictor_prediction_message_is_finished, predict_chain);
		}
		list = g_list_next (list);
	}
}

static gboolean
soup_redirection_predictor_send_prediction_async (SoupRedirectionPredictor *redirection_predictor, RedirectionHistoryEntry *redirection_history_entry, SoupMessage *original_msg)
{
	SoupSession *session;
	char *predicted_url;

	SoupRedirectionPredictChain *predict_chain;

	SoupRedirectionPredictorPrivate *priv;
	priv = SOUP_REDIRECTION_PREDICTOR_GET_PRIVATE (redirection_predictor);
	session = priv->session;


	predict_chain = soup_redirection_predictor_predict_chain_new (session, original_msg);
	g_return_val_if_fail (predict_chain != NULL, FALSE);

	predicted_url = redirection_history_entry->redirected_url;
	predict_chain = soup_redirection_predictor_make_predict_chain (redirection_predictor, predict_chain, predicted_url);
	g_return_val_if_fail (predict_chain != NULL, FALSE);

	soup_redirection_predictor_queue_prediction_messages (predict_chain);

	return TRUE;
}

gboolean
soup_redirection_predictor_has_prediction (SoupRedirectionPredictor *redirection_predictor,
										SoupMessage          *original_msg)
{
	RedirectionHistoryEntry *redirection_history_entry = NULL;
	RedirectionPredictType redirection_predict_type;
	char *url;
	int redirection_count = 0;

	while (1) {
		url = soup_uri_to_string (soup_message_get_uri (original_msg), FALSE);
		redirection_history_entry = soup_redirection_predictor_has_redirection_history (redirection_predictor, url);
		if (redirection_history_entry) {
			redirection_predict_type = redirection_history_entry->redirection_predict_type;
			if (redirection_predict_type == REDIRECTION_PREDICT_TYPE_CACHEABLE) {
				if (redirection_count >= SOUP_REDIRECTION_PREDICTOR_MAX_REDIRECTION_COUNT) {
					original_msg->status_code = SOUP_STATUS_TOO_MANY_REDIRECTS;
					original_msg->reason_phrase = g_strdup ("Too many redirects");
					g_free (url);
					return TRUE;
				}
				redirection_count++;
				soup_redirection_predictor_send_redirection_cache (redirection_history_entry, original_msg);
				g_free (url);
				continue;
			}
			if (redirection_predict_type == REDIRECTION_PREDICT_TYPE_PREDICTABLE) {
				if (!soup_redirection_predictor_send_prediction_async (redirection_predictor, redirection_history_entry, original_msg)) {
					original_msg->status_code = SOUP_STATUS_TOO_MANY_REDIRECTS;
					original_msg->reason_phrase = g_strdup ("Too many redirects");
				}
				g_free (url);
				return TRUE;
			}
		}
		break;
	}
	g_free (url);

	return FALSE;
}
