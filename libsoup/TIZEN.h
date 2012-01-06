/*
 * TIZEN.h
 *
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd.
 */

#ifndef TIZEN_H
#define TIZEN_H

#define ENABLE(TIZEN_FEATURE) (defined ENABLE_##TIZEN_FEATURE  && ENABLE_##TIZEN_FEATURE)

#define ENABLE_TIZEN_FIX_PACK_ENTRY 1
#define ENABLE_TIZEN_FIX_CONTENT_SNIFFER_PATTERN 1
#define ENABLE_TIZEN_FIX_PAUSE_MESSAGE 1

#endif //#ifndef TIZEN_H
