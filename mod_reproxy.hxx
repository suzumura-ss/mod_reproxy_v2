/* 
 * Copyright 2010 Toshiyuki Suzumura
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#ifndef __INCLUDE_MOD_REPROXY__
#define __INCLUDE_MOD_REPROXY__

extern "C" {  // for ap_mpm.h
  #include "httpd.h"
  #include "http_protocol.h"
  #include "http_config.h"
  #include "http_request.h"
  #include "http_log.h"
  #include "ap_config.h"
  #include "ap_mpm.h"
  #include "apr_strings.h"
  #include <curl/curl.h>
}

#define AP_LOG_VERBOSE(rec, fmt, ...) //ap_log_rerror(APLOG_MARK, APLOG_DEBUG,  0, rec, fmt, ##__VA_ARGS__)
#define AP_LOG_DEBUG(rec, fmt, ...) ap_log_rerror(APLOG_MARK, APLOG_DEBUG,  0, rec, fmt, ##__VA_ARGS__)
#define AP_LOG_INFO(rec, fmt, ...)  ap_log_rerror(APLOG_MARK, APLOG_INFO,   0, rec, "[reproxy] " fmt, ##__VA_ARGS__)
#define AP_LOG_WARN(rec, fmt, ...)  ap_log_rerror(APLOG_MARK, APLOG_WARNING,0, rec, "[reproxy] " fmt, ##__VA_ARGS__)
#define AP_LOG_ERR(rec, fmt, ...)   ap_log_rerror(APLOG_MARK, APLOG_ERR,    0, rec, "[reproxy] " fmt, ##__VA_ARGS__)

extern "C" {
  APU_DECLARE(apr_bucket*)  curl_bucket_create(const char* url, apr_off_t& len, apr_bucket_alloc_t*, request_rec*);
  APU_DECLARE(apr_bucket*)  curl_next_bucket_create(apr_bucket*, apr_off_t& len);
  APU_DECLARE(apr_bucket*)  curl_end_bucket_create(apr_bucket*);
}

#endif // __INCLUDE_MOD_REPROXY__
