#ifndef TIZEN_H
#define TIZEN_H

#define ENABLE(TIZEN_FEATURE) (defined ENABLE_##TIZEN_FEATURE  && ENABLE_##TIZEN_FEATURE)

#define ENABLE_TIZEN_FIX_PACK_ENTRY 1               /*Kwangtae Ko : Fix the utf-8 encoding problem in pack_entry*/
#define ENABLE_TIZEN_FIX_CONTENT_SNIFFER_PATTERN 1  /*Taesoo Jun : Update the types_table using content-sniffer*/
#define ENABLE_TIZEN_UNLIMITED_PENDING_CONNECTIONS 1  /*Kwangtae Ko : Disable limiting the number of pending connections to enhance the network performance*/
#define ENABLE_TIZEN_USE_CURRENT_SYSTEM_DATETIME 1  /*DongJae KIM : soup-date-is-past checking value, using Current System Year*/
#define ENABLE_TIZEN_FIX_CACHE_DUMP 1 /*Kwangtae Ko : Fix the soup_cache_dump() not to exist a soup.cache2 file when there is no SoupCacheEntry */
#define ENABLE_TIZEN_ON_AUTHENTICATION_REQUESTED 1 /*Sungman Kim : Modify the authentication signal handling method */
#define ENABLE_TIZEN_FIX_PARSING_COOKIE_FOR_HTTPONLY_AND_SECURE 1  /*Raveendra Karu : when logging in to live.com it is redirecting to login page again instead of profile page
				skip_value() interface implemented, used instead of parse_value() for cases "secure" and "httponly" in method parse_one_cookie
				This is done to ensure that the pointer p moves to the beginning of next attribute for that particular cookie. */
#define ENABLE_TIZEN_CHECK_SOCKET_EXISTS_BEFORE_USE_IT 1 /*Kwangtae Ko : error checking about SoupSocket when soup_socket_is_ssl(). */
#define ENABLE_TIZEN_ADD_LOCK_OF_ASYNC_SESSION 1 /*Kwangtae Ko : Add lock of SoupSessionAsync for thread-safe when queue_message() is called from multiple-threads*/

#define ENABLE_TIZEN_REDIRECTION_PREDICTOR 1 /*Kwangtae Ko*/
#define ENABLE_TIZEN_FILTER_INVALID_PROXY_ADDR 1 /*Keunsoon Lee : Filtering invalid proxy address like "0.0.0.0" or "http:///" */

#define ENABLE_TIZEN_ADAPTIVE_HTTP_TIMEOUT 0 /*Raveendra Karu : Implementing adaptive http timed out for dead links. */
#define ENABLE_TIZEN_SOCKET_TIMEDOUT_ERROR  1 /*Raveendra Karu : Added to check the error is because of host unreachable or socket timeout out  */
#define ENABLE_TIZEN_COOKIE_VALIDATION_IN_REDIRECTION_PREDICTION  1 /*Raveendra Karu : Added "Set-Cookie" validation to check whether history entry prediction message "Set-Cookie" value and the redirected message "Set-Cookie" value are equal or not */
#define ENABLE_TIZEN_FIX_RESPONSE_HEADERS_LINEFEED 1 /*Raveendra Karu : Adding Carriage return (\r) and Line feed (\n) for the response headers if server doesnt add */
#define ENABLE_TIZEN_HANDLING_307_REDIRECTION 1 /*Raveendra Karu : Handling redirection (307) of POST, GET responses*/
#define ENABLE_TIZEN_IGNORE_HOST_CHECK_FOR_TEL_SCHEME 1 /*Raveendra Karu : Ignoring host check if the url redirected to a tel: scheme url, Not adding redirected url to redirection predictor if it is not of http / https scheme. */
#define ENABLE_TIZEN_UPDATE_CACHE_ENTRY_CONTENT_TYPE_HEADER 1 /*Raveendra Karu : Update Cache entry's Content-Type header value*/
#define ENABLE_TIZEN_CERTIFICATE_FILE_SET 1 /*Shobhita Agarwal and Sungman Kim: Initialize the tls_db based on a timer at browser launch.*/
#define ENABLE_TIZEN_CACHE_FILE_SIZE_VALIDATION 1 /*Praveen : Validate soup cache files on disk for non-zero size when requested*/
#define ENABLE_TIZEN_URI_NORMALIZATION_FOR_QUERY 0 /* Daehyun Yoo : This is about for query part in URI, if the normalization policy is changed. */
#define ENABLE_TIZEN_ADD_NULL_CHECK_ON_QUEUE_ITEM 1 /* Keunsoon Lee : Add null check on soup_message_queue_item_unref() to defend P131002-04573. Probably the crash is because of memory corruption on another library besides of libsoup, but add defense code until finding it. */
/* Workaround patch*/
#define ENABLE_TIZEN_SOUP_MESSAGE_PAUSE_SET_FLAG 1 /*Sungman : To allow SoupMessage pause only in case of set specific flag */
#define ENABLE_TIZEN_NOT_TO_CACHE_DNS_FOR_EMPTY_HOST 1 /* Keunsoon Lee : Original libsoup keeps SoupAddr for DNS cache for 5 minutes if host hashtable has no connection. But, we should clear the DNS cache if bearer is changed. So, clear DNS cache on host hash table and lean on connman's DNS cache. */
#define ENABLE_TIZEN_USER_AGENT_CHECK_IN_CACHE 1 /* Praveen : Add user agent check to cache */
#define ENABLE_TIZEN_CACHE_ENTRY_VALIDATED_SET 1 /*Raveendra Karu : To set cache entry's being_validated to FALSE in case of conditional request's response is not SOUP_STATUS_NOT_MODIFIED which ensures that cache entry will be overwritten with new data */
#define ENABLE_TIZEN_DATA_URI_WITHOUT_MEDIA_TYPE 1 /* Raveendra Karu : To decode data properly in data url if there is no media type specified */
#define ENABLE_TIZEN_STORE_SESSION_COOKIE 1 /* Raveendra Karu : To store session cookies (with no expires value) also in cookie database for 1 hour */
#define ENABLE_TIZEN_HANDLE_MALFORMED_MAX_AGE_HEADER 1 /* Raveendra Karu : Handling malformed max-age cache-control value (ex: "Cache-Control: private,max-age") of the request headers */


#if ENABLE(TIZEN_USE_CURRENT_SYSTEM_DATETIME)
void      soup_date_get_current_system_year     (void);
#endif

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


