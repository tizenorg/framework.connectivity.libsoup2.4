/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2013 Samsung Electronics Co., Ltd. All rights reserved.
 */

#ifndef SOUP_MESSAGE_IO_SPDY_PRIVATE_H
#define SOUP_MESSAGE_IO_SPDY_PRIVATE_H 1

#include <spindly/spindly.h>
#include "soup-message.h"
#include "soup-message-private.h"
#include "soup-types.h"

void soup_message_io_spdy_client    (SoupMessageQueueItem      *item,
				SoupMessageParseHeadersFn  parse_headers_cb,
				gpointer                   headers_data,
				SoupMessageCompletionFn    completion_cb,
				gpointer                   user_data);

void soup_message_io_spdy_cleanup	(SoupMessage	*msg);
void soup_message_io_spdy_stop		(SoupMessage	*msg);
void soup_message_io_spdy_finished	(SoupMessage	*msg);

#endif /* SOUP_MESSAGE_IO_SPDY_PRIVATE_H */
