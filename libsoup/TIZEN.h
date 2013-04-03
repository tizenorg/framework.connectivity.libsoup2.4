#ifndef TIZEN_H
#define TIZEN_H

#define ENABLE(TIZEN_FEATURE) (defined ENABLE_##TIZEN_FEATURE  && ENABLE_##TIZEN_FEATURE)

#define ENABLE_TIZEN_FIX_PARSING_COOKIE_FOR_HTTPONLY_AND_SECURE 1  /*Raveendra Karu : when logging in to live.com it is redirecting to login page again instead of profile page skip_value() interface implemented, used instead of parse_value() for cases "secure" and "httponly" in method parse_one_cookie. This is done to ensure that the pointer p moves to the beginning of next attribute for that particular cookie. */
#define ENABLE_TIZEN_ON_AUTHENTICATION_REQUESTED 1 /*Sungman Kim : Modify the authentication signal handling method */
#define ENABLE_TIZEN_FIX_RESPONSE_HEADERS_LINEFEED 1 /*Raveendra Karu : Adding Carriage return (\r) and Line feed (\n) for the response headers if server doesn't add */
#define ENABLE_TIZEN_CERTIFICATE_FILE_SET 1 /*Sungman Kim : apply the lazy initialization. The certificate file set is delayed until first https request*/

#endif

