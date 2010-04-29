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

#include "mod_reproxy.hxx"

#define REPROXY   "X-Reproxy-URL"

static const char X_REPROXY[] = REPROXY;
extern "C" module AP_MODULE_DECLARE_DATA reproxy_module;

struct reproxy_conf {
  int   enabled;
};

//
// Utils.
//
static const char* get_and_unset_header(apr_table_t* tbl, const char* key)
{
  const char* value = apr_table_get(tbl, key);
  if(value) apr_table_unset(tbl, key);
  return value;
}
  

static void unset_header(request_rec* rec, const char* key)
{
  apr_table_unset(rec->headers_out, key);
  apr_table_unset(rec->err_headers_out, key);
}


//
// Output filter.
//
static apr_status_t reproxy_output_filter(ap_filter_t* f, apr_bucket_brigade* in_bb)
{
  request_rec* rec =f->r;
  const char* reproxy_url;

  AP_LOG_VERBOSE(rec, "Incoming %s.", __FUNCTION__);

  // Pass thru by request types.
  if(rec->status!=HTTP_OK || rec->main!=NULL || rec->header_only
    || (rec->handler!= NULL && strcmp(rec->handler, "default-handler") == 0)) goto PASS_THRU;

  AP_LOG_VERBOSE(rec, "-- Checking responce headers.");

  // Obtain and erase x-reproxy-url header or pass through.
  reproxy_url = get_and_unset_header(rec->headers_out, X_REPROXY);
  if(reproxy_url== NULL || reproxy_url[0]=='\0') {
    reproxy_url = get_and_unset_header(rec->err_headers_out, X_REPROXY);
  }
  if(reproxy_url==NULL || reproxy_url[0]=='\0') goto PASS_THRU;


  AP_LOG_VERBOSE(rec, "-- Creating reproxy buckets.");

  // Drop all content and headers related.
  while(!APR_BRIGADE_EMPTY(in_bb)) {
    apr_bucket* b = APR_BRIGADE_FIRST(in_bb);
    apr_bucket_delete(b);
  }
  rec->eos_sent = 0;
  rec->clength = 0;
  unset_header(rec, "Content-Length");
  //unset_header(rec, "Content-Type");
  unset_header(rec, "Content-Encoding");
  unset_header(rec, "Last-Modified");
  unset_header(rec, "ETag");


  // Start reproxy bucket.
  {
    apr_off_t content_length = 0;
    apr_bucket* b = curl_bucket_create(reproxy_url, content_length, in_bb->bucket_alloc, rec);
    if(b) {
      APR_BRIGADE_INSERT_TAIL(in_bb, b);
      while(content_length>0) {
        AP_LOG_VERBOSE(rec, "  curl_next_bucket_create(b, %llu)", content_length);
        APR_BRIGADE_INSERT_TAIL(in_bb, curl_next_bucket_create(b, content_length));
      }
      APR_BRIGADE_INSERT_TAIL(in_bb, curl_end_bucket_create(b));
      APR_BRIGADE_INSERT_TAIL(in_bb, apr_bucket_eos_create(in_bb->bucket_alloc));
    } else {
      AP_LOG_ERR(rec, "curl_bucket_create() failed - %d", rec->status);
      ap_send_error_response(rec, rec->status);
    }
  }
  AP_LOG_VERBOSE(rec, "-- Create done.");
 
 
PASS_THRU:
  AP_LOG_VERBOSE(rec, "-- Filter done.");
  ap_remove_output_filter(f);
  return ap_pass_brigade(f->next, in_bb);
}


// Add output filter if it is enabled.
static void reproxy_insert_output_filter(request_rec* rec)
{
  AP_LOG_VERBOSE(rec, "Incoming %s.", __FUNCTION__);
  reproxy_conf* conf = (reproxy_conf*)ap_get_module_config(rec->per_dir_config, &reproxy_module);
  if(conf->enabled) ap_add_output_filter(X_REPROXY, NULL, rec, rec->connection);
}


//
// Configurators, and Register.
// 
static void* config_create(apr_pool_t* p, char* path)
{
  reproxy_conf* conf = (reproxy_conf*)apr_palloc(p, sizeof(reproxy_conf));
  conf->enabled = FALSE;

  return conf;
}

static const command_rec config_cmds[] = {
  AP_INIT_FLAG(X_REPROXY, (cmd_func)ap_set_flag_slot, (void*)APR_OFFSETOF(reproxy_conf, enabled), OR_OPTIONS, "{On|Off}"),
  { NULL },
};

static void register_hooks(apr_pool_t *p)
{
  ap_register_output_filter(X_REPROXY, reproxy_output_filter, NULL, AP_FTYPE_CONTENT_SET);
  ap_hook_insert_filter(reproxy_insert_output_filter, NULL, NULL, APR_HOOK_FIRST);
}


// Dispatch list for API hooks.
module AP_MODULE_DECLARE_DATA reproxy_module = {
  STANDARD20_MODULE_STUFF, 
  config_create,  // create per-dir    config structures.
  NULL,           // merge  per-dir    config structures.
  NULL,           // create per-server config structures.
  NULL,           // merge  per-server config structures.
  config_cmds,    // table of config file commands.
  register_hooks  // register hooks.
};
