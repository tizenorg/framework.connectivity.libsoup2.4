#ifndef TIZEN_H
#define TIZEN_H

#define ENABLE(TIZEN_FEATURE) (defined ENABLE_##TIZEN_FEATURE  && ENABLE_##TIZEN_FEATURE)

#define ENABLE_TIZEN_FIX_PARSING_COOKIE_FOR_HTTPONLY_AND_SECURE 1  /*Raveendra Karu : when logging in to live.com it is redirecting to login page again instead of profile page skip_value() interface implemented, used instead of parse_value() for cases "secure" and "httponly" in method parse_one_cookie. This is done to ensure that the pointer p moves to the beginning of next attribute for that particular cookie. */
#define ENABLE_TIZEN_ON_AUTHENTICATION_REQUESTED 1 /*Sungman Kim : Modify the authentication signal handling method */
#define ENABLE_TIZEN_FIX_RESPONSE_HEADERS_LINEFEED 0 /*Raveendra Karu : Adding Carriage return (\r) and Line feed (\n) for the response headers if server doesn't add */
#define ENABLE_TIZEN_CERTIFICATE_FILE_SET 1 /*Sungman Kim : apply the lazy initialization. The certificate file set is delayed until first https request*/

#if ENABLE(TIZEN_DLOG)

#ifndef LOG_TAG
#define LOG_TAG "libsoup" /* This LOG_TAG should be defined before including dlog.h. Because dlog.h is using it. */
#endif

#include <dlog.h>

#define TIZEN_LOGD(fmt, args...) LOGD("[%s: %s: %d] "fmt, (rindex(__FILE__, '/') ? rindex(__FILE__, '/') + 1 : __FILE__), __FUNCTION__, __LINE__, ##args)
#define TIZEN_LOGI(fmt, args...) LOGI("[%s: %s: %d] "fmt, (rindex(__FILE__, '/') ? rindex(__FILE__, '/') + 1 : __FILE__), __FUNCTION__, __LINE__, ##args)
#define TIZEN_LOGW(fmt, args...) LOGW("[%s: %s: %d] "fmt, (rindex(__FILE__, '/') ? rindex(__FILE__, '/') + 1 : __FILE__), __FUNCTION__, __LINE__, ##args)
#define TIZEN_LOGE(fmt, args...) LOGE("[%s: %s: %d] "fmt, (rindex(__FILE__, '/') ? rindex(__FILE__, '/') + 1 : __FILE__), __FUNCTION__, __LINE__, ##args)
#define TIZEN_LOGE_IF(cond, fmt, args...) LOGE_IF(cond, "[%s: %s: %d] "fmt, (rindex(__FILE__, '/') ? rindex(__FILE__, '/') + 1 : __FILE__), __FUNCTION__, __LINE__, ##args)

#endif // ENABLE(TIZEN_DLOG)

#endif

