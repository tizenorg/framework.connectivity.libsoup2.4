#ifndef TIZEN_H
#define TIZEN_H

#define ENABLE(TIZEN_FEATURE) (defined ENABLE_##TIZEN_FEATURE  && ENABLE_##TIZEN_FEATURE)

#define ENABLE_TIZEN_EXT 1
#define ENABLE_TIZEN_CERTIFICATE_FILE_SET 1 /*Shobhita Agarwal and Sungman Kim: Initialize the tls_db based on a timer at browser launch.*/
#define ENABLE_TIZEN_UPDATE_CORRECTED_INITIAL_AGE_FOR_CACHE 1 /*Seonah Moon: Update current initial age when libsoup receive 304 not modified message*/
#define ENABLE_TIZEN_UPDATE_CACHE_ENTRY_CONTENT_TYPE_HEADER 1 /* Raveendra Karu : Update Cache entry's Content-Type header value with sniffed Content-Type value */
#define ENABLE_TIZEN_USER_AGENT_CHECK_IN_CACHE 1 /* Praveen : Add user agent check to cache */
#define ENABLE_TIZEN_DATA_URI_WITHOUT_MEDIA_TYPE 1 /* Raveendra Karu : To decode data properly in data url if there is no media type specified */
#define ENABLE_TIZEN_HANDLE_MALFORMED_MAX_AGE_HEADER 1 /* Raveendra Karu : Handling malformed max-age cache-control value (ex: "Cache-Control: private,max-age") of the request headers */
#define ENABLE_TIZEN_FIX_PACK_ENTRY 1 /*Kwangtae Ko : Fix the utf-8 encoding problem in pack_entry*/
#define ENABLE_TIZEN_FIX_CACHE_DUMP 1 /*Kwangtae Ko : Fix the soup_cache_dump() not to exist a soup. cache2 file when there is no SoupCacheEntry */
#define ENABLE_TIZEN_ON_AUTHENTICATION_REQUESTED 1 /*Sungman Kim, Raveendra Karu : Modify the authentication signal handling method */
#define ENABLE_TIZEN_HANDLING_307_REDIRECTION 1 /*Raveendra Karu : Handling redirection (307) of POST, GET responses*/

#if ENABLE(TIZEN_DLOG)

#ifndef LOG_TAG
#define LOG_TAG "libsoup" /* This LOG_TAG should be defined before including dlog.h. Because dlog.h is using it. */
#endif

#include <dlog.h>

#define TIZEN_LOGD(fmt, args...) LOGD(fmt, ##args)
#define TIZEN_LOGI(fmt, args...) LOGI(fmt, ##args)
#define TIZEN_LOGW(fmt, args...) LOGW(fmt, ##args)
#define TIZEN_LOGE(fmt, args...) LOGE(fmt, ##args)
#define TIZEN_LOGE_IF(cond, fmt, args...) LOGE_IF(cond, fmt, ##args)

#define TIZEN_SECURE_LOGD(fmt, args...) SECURE_LOGD(fmt, ##args)
#define TIZEN_SECURE_LOGI(fmt, args...) SECURE_LOGI(fmt, ##args)
#define TIZEN_SECURE_LOGW(fmt, args...) SECURE_LOGW(fmt, ##args)
#define TIZEN_SECURE_LOGE(fmt, args...) SECURE_LOGE(fmt, ##args)

#else

#define TIZEN_LOGD(fmt, args...)
#define TIZEN_LOGI(fmt, args...)
#define TIZEN_LOGW(fmt, args...)
#define TIZEN_LOGE(fmt, args...)
#define TIZEN_LOGE_IF(cond, fmt, args...)

#define TIZEN_SECURE_LOGD(fmt, args...)
#define TIZEN_SECURE_LOGI(fmt, args...)
#define TIZEN_SECURE_LOGW(fmt, args...)
#define TIZEN_SECURE_LOGE(fmt, args...)

#endif // ENABLE(TIZEN_DLOG)

#endif //#ifndef TIZEN_H


