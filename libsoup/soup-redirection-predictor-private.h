/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-redirection-predictor-private.h:
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

#ifndef SOUP_REDIRECTION_PREDICTOR_PRIVATE_H
#define SOUP_REDIRECTION_PREDICTOR_PRIVATE_H 1

#include <libsoup/soup-types.h>
#include <libsoup/soup-message-headers.h>
#include <gio/gio.h>

G_BEGIN_DECLS

#define SOUP_TYPE_REDIRECTION_PREDICTOR            (soup_redirection_predictor_get_type ())
#define SOUP_REDIRECTION_PREDICTOR(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SOUP_TYPE_REDIRECTION_PREDICTOR, SoupRedirectionPredictor))
#define SOUP_REDIRECTION_PREDICTOR_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SOUP_TYPE_REDIRECTION_PREDICTOR, SoupRedirectionPredictorClass))
#define SOUP_IS_REDRECTION_PREDICTOR(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SOUP_TYPE_REDIRECTION_PREDICTOR))
#define SOUP_IS_REDRECTION_PREDICTOR_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), SOUP_TYPE_REDIRECTION_PREDICTOR))
#define SOUP_REDIRECTION_PREDICTOR_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SOUP_TYPE_REDIRECTION_PREDICTOR, SoupRedirectionPredictorClass))

//#define SOUP_STATUS_IS_REDIRECTION_PREDICTABLE (status)      ((status) == 302)


typedef struct _SoupRedirectionPredictor SoupRedirectionPredictor;
typedef struct _SoupRedirectionPredictorPrivate SoupRedirectionPredictorPrivate;

struct _SoupRedirectionPredictor {
	GObject parent_instance;

	SoupRedirectionPredictorPrivate *priv;
};

typedef struct {
	GObjectClass parent_class;

} SoupRedirectionPredictorClass;

GType               soup_redirection_predictor_get_type            (void);
SoupRedirectionPredictor       *soup_redirection_predictor_new     (const char *redirection_predictor_dir);

gboolean soup_redirection_predictor_has_prediction (SoupRedirectionPredictor *redirection_predictor,
														SoupMessage          *original_msg);

G_END_DECLS

#endif /* SOUP_REDIRECTION_PREDICTOR_PRIVATE_H */
