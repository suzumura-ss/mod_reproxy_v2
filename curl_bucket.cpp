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

#include <pthread.h>
#include "mod_reproxy.hxx"


class CurlBucket {
public:
  CurlBucket(const char* url, apr_off_t& len, request_rec* r, apr_bucket* b);
  virtual ~CurlBucket();

  static void destroy_(void* v);
  static apr_status_t read_(apr_bucket* e, const char** str, apr_size_t* len, apr_read_type_e block);
  static const apr_bucket_type_t bucketdef;
  static const apr_bucket_type_t bucketend;

  apr_status_t read_header(apr_table_t*& res);
  apr_status_t read(apr_bucket* e, const char** str, apr_size_t* len, apr_read_type_e block);

private:
  static void* curl_thread(void* _this);
  static size_t curl_header_cb(const void* ptr, size_t size, size_t nmemb, void* _this);
  static size_t curl_write_cb(const void* ptr, size_t size, size_t nmemb, void* _this);

  apr_status_t translate_over_limit(apr_bucket* e, const char** str, apr_size_t* len, apr_read_type_e block);
  apr_status_t translate_under_limit(apr_bucket* e, const char** str, apr_size_t* len, apr_read_type_e block);
  apr_status_t translate_eof(apr_bucket* e, const char** str, apr_size_t* len, apr_read_type_e block);

  CURL* curl;
  char* url;
  request_rec* rec;
  apr_bucket_alloc_t* bucket_alloc;
  apr_off_t length;   // Remaining bytes to read.

  // Data translator from curl to bucket.
  pthread_cond_t  cond;
  pthread_mutex_t cond_mutex;
  pthread_t thread;           // curl thread.
  pthread_mutex_t mutex;
  bool      curl_is_end;      // [Locked] true when curl is end.
  CURLcode  curl_code;        // [Locked] curl result code.
  char*     transfer_data;    // [Locked] Data body.
  apr_off_t transfer_remain;  // [Locked] Data remain length.
  apr_off_t transfer_offset;  // [Locked] Data offset to bucket.

  // Reproxy responses.
  //int r_status;         // response status
};
static const char HTTP1[] = "HTTP/1.";
static const char CONTENT_LENGTH[] = "Content-Length";
static const char CONTENT_RANGE[] = "Content-Range";
static const char CONTENT_TYPE[]   = "Content-Type";
static const char VERSION[] = "mod_reproxy/2.0";
static apr_status_t read_noop(apr_bucket* e, const char** str, apr_size_t* len, apr_read_type_e block)
{
  *str = "";
  *len = 0;
  return APR_SUCCESS;
}


//
//== Static methods ==
//

// Create curl bucket.
APU_DECLARE(apr_bucket*) curl_bucket_create(const char* url,
                                              apr_off_t& len, apr_bucket_alloc_t *list, request_rec* r)
{
  apr_bucket* b = (apr_bucket*)apr_bucket_alloc(sizeof(*b), list);

  APR_BUCKET_INIT(b);
  b->free = apr_bucket_free;
  b->list = list;
  b->type = &CurlBucket::bucketdef;
  b->start = 0;
  b->data = new CurlBucket(url, len, r, b);
  AP_LOG_VERBOSE(r, "new CurlBucket() => %d", r->status);
  if(r->status!=HTTP_OK && r->status!=HTTP_PARTIAL_CONTENT) {
    delete (CurlBucket*)b->data;
    apr_bucket_free(b);
    return NULL;
  }
 
  return b;
}

// Create 'next' bucket.
APU_DECLARE(apr_bucket*) curl_next_bucket_create(apr_bucket* c, apr_off_t& len)
{
  apr_bucket* b = (apr_bucket*)apr_bucket_alloc(sizeof(*b), c->list);

  APR_BUCKET_INIT(b);
  b->free = c->free;
  b->list = c->list;
  b->type = &CurlBucket::bucketdef;
  if(len>APR_BUCKET_BUFF_SIZE) {
    b->length = APR_BUCKET_BUFF_SIZE;
    len -= APR_BUCKET_BUFF_SIZE;
  } else {
    b->length = len;
    len = 0;
  }
  b->start = 0;
  b->data = c->data;
 
  return b;
}

// Create 'end' bucket.
APU_DECLARE(apr_bucket*) curl_end_bucket_create(apr_bucket* c)
{
  apr_bucket* b = (apr_bucket*)apr_bucket_alloc(sizeof(*b), c->list);

  APR_BUCKET_INIT(b);
  b->free = c->free;
  b->list = c->list;
  b->type = &CurlBucket::bucketend;
  b->length = 0;
  b->start = 0;
  b->data = c->data;
 
  return b;
}



// Destroy curl bucket.
void CurlBucket::destroy_(void* p)
{
  CurlBucket* self = (CurlBucket*)p;
  delete self;
}


// Read from url (curl bucket).
apr_status_t CurlBucket::read_(apr_bucket* e, const char** str, apr_size_t* len, apr_read_type_e block)
{
  CurlBucket* c = (CurlBucket*)e->data;
  return c->read(e, str, len, block);
}



// libcurl bucket definition.
const apr_bucket_type_t CurlBucket::bucketdef = {
  "LIBCURL", 5, apr_bucket_type_t::APR_BUCKET_DATA,
  apr_bucket_destroy_noop,
  CurlBucket::read_,
  apr_bucket_setaside_notimpl, 
  apr_bucket_split_notimpl,
  apr_bucket_copy_notimpl
};
const apr_bucket_type_t CurlBucket::bucketend = {
  "LIBCURL_E", 5, apr_bucket_type_t::APR_BUCKET_DATA,
  CurlBucket::destroy_,
  read_noop,
  apr_bucket_setaside_notimpl, 
  apr_bucket_split_notimpl,
  apr_bucket_copy_notimpl
};




//
// == Class methods ==
//

// Constructer
CurlBucket::CurlBucket(const char* u, apr_off_t& len, request_rec* r, apr_bucket* b)
{
  curl = curl_easy_init();
  url  = apr_pstrdup(r->pool, u);
  rec  = r;
  bucket_alloc = b->list;

  // Setup curl.
  int threaded_mpm;
  ap_mpm_query(AP_MPMQ_IS_THREADED, &threaded_mpm);
  curl_easy_setopt(curl, CURLOPT_NOSIGNAL, threaded_mpm);
  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);
  curl_easy_setopt(curl, CURLOPT_WRITEHEADER, this);
  curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, curl_header_cb);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, this);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
  curl_easy_setopt(curl, CURLOPT_USERAGENT, apr_psprintf(rec->pool, "%s, %s", VERSION, curl_version()));
  const char*range = apr_table_get(rec->headers_out, CONTENT_RANGE);
  if(range) {
    apr_table_unset(rec->headers_out, CONTENT_RANGE);
    apr_off_t s, e, l;
    if(sscanf(range, "bytes=%llu-%llu/%llu", &s, &e, &l)==3) {
      curl_easy_setopt(curl, CURLOPT_RANGE, apr_psprintf(rec->pool, "%llu-%llu", s, e));
    } else
    if(sscanf(range, "bytes=-%llu/%llu", &e, &l)==2) {
      curl_easy_setopt(curl, CURLOPT_RANGE, apr_psprintf(rec->pool, "-%llu", e));
    }
    if(sscanf(range, "bytes=%llu-/%llu", &s, &l)==2) {
      curl_easy_setopt(curl, CURLOPT_RANGE, apr_psprintf(rec->pool, "%llu-", s));
    }
  }

  // Setup curl-thread
  pthread_cond_init(&cond, NULL);
  pthread_mutex_init(&cond_mutex, NULL);
  pthread_mutex_init(&mutex, NULL);
  curl_is_end = false;
  curl_code = CURLE_OK;
  transfer_data = NULL;
  transfer_remain = 0;
  transfer_offset = 0;

  // Start curl-thread, and wait read headers.
  pthread_create(&thread, NULL, curl_thread, this);
  pthread_cond_wait(&cond, &cond_mutex);

  // Setup Content-Length.
  const char* v = apr_table_get(rec->headers_out, CONTENT_LENGTH);
  if(v) apr_strtoff(&length, v, NULL, 10);
  if(length>APR_BUCKET_BUFF_SIZE) {
    b->length = APR_BUCKET_BUFF_SIZE;
    len = length - APR_BUCKET_BUFF_SIZE;
  } else {
    b->length = length;
    len = 0;
  }  

  // Setup Content-Type
  //v = apr_table_get(rec->headers_out, CONTENT_TYPE);
  //if(v) ap_set_content_type(rec, v);
}


// Destructer
CurlBucket::~CurlBucket()
{
  AP_LOG_VERBOSE(rec, "Joining curl thread - this=0x%llx", (apr_off_t)this);
  pthread_join(thread, NULL);
  pthread_mutex_destroy(&mutex);
  pthread_mutex_destroy(&cond_mutex);
  pthread_cond_destroy(&cond);
  curl_easy_cleanup(curl);
}


// Some data is read. Translate to bucket less than APR_BUCKET_BUFF_SIZE.
apr_status_t CurlBucket::translate_under_limit(apr_bucket* e, const char** str, apr_size_t* len, apr_read_type_e block)
{
  *len = transfer_remain;
  *str = (char*)apr_bucket_alloc(*len, e->list);
  memcpy((void*)*str, transfer_data + transfer_offset, *len);
  apr_bucket_free(transfer_data);
  transfer_data = NULL;
  transfer_remain = 0;
  transfer_offset = 0;
  length -= *len;

  return APR_SUCCESS;
}


// Too long data is read. Translate to bucket just APR_BUCKET_BUFF_SIZE, and append new bucket.
apr_status_t CurlBucket::translate_over_limit(apr_bucket* e, const char** str, apr_size_t* len, apr_read_type_e block)
{
  *len = APR_BUCKET_BUFF_SIZE;
  *str = (char*)apr_bucket_alloc(*len, e->list);
  memcpy((void*)*str, transfer_data + transfer_offset, *len);
  transfer_remain -= *len;
  transfer_offset += *len;
  APR_BUCKET_INSERT_AFTER(e, curl_next_bucket_create(e, length));

  return APR_SUCCESS;
}


// curl is end. Set final response to request_rec.
apr_status_t CurlBucket::translate_eof(apr_bucket* e, const char** str, apr_size_t* len, apr_read_type_e block)
{
  apr_status_t rv = APR_SUCCESS;

  *len = length = e->length = 0;
  if(transfer_data) apr_bucket_free(transfer_data);
  transfer_data = NULL;
  transfer_remain = 0;
  transfer_offset = 0;
  AP_LOG_VERBOSE(rec, "read data FINALLY");

  switch(curl_code) {
  case CURLE_OK:
    rv = APR_EOF;
    //rec->status = r_status;
    break;
  case CURLE_OPERATION_TIMEOUTED:
    rv = APR_TIMEUP;
    //rec->status = HTTP_GATEWAY_TIME_OUT;
    break;
  default:
    rv = APR_NOTFOUND;
    //rec->status = HTTP_BAD_GATEWAY;
    break;
  }
  if(rec->status!=HTTP_OK) {
    AP_LOG_ERR(rec, "CURL failed - status=%d, %s(%d)", rec->status, curl_easy_strerror(curl_code), curl_code);
  }

  return rv;
}


// Read from url.
apr_status_t CurlBucket::read(apr_bucket* e, const char** str, apr_size_t* len, apr_read_type_e block)
{
  // block := APR_BLOCK_READ or APR_NONBLOCK_READ
  *str = NULL;

  // To read into `buf` from `this` just `*len` bytes.
  //    * When it failed, call apr_bucket_free(buf) and return rv(!=APR_SUCCESS).
  //      Finally, substruct `*len` from `length`.
  //    * When CURL is EOF, set e->length=0 and rv=APR_SUCCESS.
  apr_status_t rv = APR_SUCCESS;

  do {
    bool incoming_datas = false;
    pthread_mutex_lock(&mutex);
    {
      if(curl_is_end || transfer_data) incoming_datas = true;
    }
    pthread_mutex_unlock(&mutex);

    if(!incoming_datas) {
      AP_LOG_VERBOSE(rec, "Waiting transfer data. length=%llu", length);
      pthread_cond_wait(&cond, &cond_mutex);
      AP_LOG_VERBOSE(rec, "==> [%d] remain=%llu, offset=%llu", curl_is_end, transfer_remain, transfer_offset);
    }

    pthread_mutex_lock(&mutex);
    {
      if(transfer_remain > APR_BUCKET_BUFF_SIZE) {
        rv = translate_over_limit(e, str, len, block);
      } else
      if(transfer_remain > 0) {
        rv = translate_under_limit(e, str, len, block);
      } else
      if(curl_is_end) {
        rv = translate_eof(e, str, len, block);
      } else {
        // Data is not read yet.
      }
    }
    pthread_mutex_unlock(&mutex);
  } while(!curl_is_end && *str==NULL);

  if(*str) {
    // Change the current bucket to refer to what we read.
    apr_bucket_heap_make(e, *str, *len, apr_bucket_free);
  }

  // Return results.
  return APR_SUCCESS;
}


void* CurlBucket::curl_thread(void* _this)
{
  CurlBucket* self = (CurlBucket*)_this;

  AP_LOG_VERBOSE(self->rec, "Starting curl_easy_perform.");
  CURLcode code = curl_easy_perform(self->curl);
  switch(code) {
  case CURLE_OK:
    self->rec->status = code;
    break;
  case CURLE_OPERATION_TIMEOUTED:
    self->rec->status = HTTP_GATEWAY_TIME_OUT;
    break;
  default:
    self->rec->status = HTTP_BAD_GATEWAY;
    break;
  }
  pthread_mutex_lock(&self->mutex);
  {
    self->curl_is_end = true;
    self->curl_code = code;
  }
  pthread_mutex_unlock(&self->mutex);
  pthread_cond_signal(&self->cond);
  AP_LOG_VERBOSE(self->rec, "curl_easy_perform finalized.");

  return NULL;
}


size_t CurlBucket::curl_header_cb(const void* _ptr, size_t size, size_t nmemb, void* _this)
{
  struct key {
    const char* s;
    size_t      n;
  };
  static const key list[] = {
    { CONTENT_LENGTH, sizeof(CONTENT_LENGTH)-1 }, // "Content-Length: 1000"
    { CONTENT_RANGE,  sizeof(CONTENT_RANGE) -1 }, // "Content-Range: bytes=0-499/20000"
    { CONTENT_TYPE,   sizeof(CONTENT_TYPE)  -1 }, // "Content-Type: text/plain"
    { NULL, 0 }
  };

  CurlBucket* self = (CurlBucket*)_this;
  request_rec* rec = self->rec;
  const char* ptr = (const char*)_ptr;
  apr_off_t len = size*nmemb;

  if(strncmp(ptr, "\r\n", 2)==0) {
    // End of header. Signal to restart 'curl_bucket_create'.
    pthread_cond_signal(&self->cond);
    return nmemb;
  }

  AP_LOG_VERBOSE(rec, "[CURL] %s", apr_pstrndup(rec->pool, ptr, len));

  if(strncmp(ptr, HTTP1, sizeof(HTTP1)-1)==0) {
    // "HTTP/1.1 200 OK"
    AP_LOG_DEBUG(rec, "[CURL] %s", apr_pstrndup(rec->pool, ptr, len));
    int minor_ver, status;
    if(sscanf(ptr, "HTTP/1.%d %d ", &minor_ver, &status)==2) {
      self->rec->status = /*self->r_status =*/ status;
    }
    return nmemb;
  }

  for(const key* t=&list[0]; t->s!=NULL; t++) {
    if(strncasecmp(ptr, t->s, t->n)==0) {
      const char* s = ptr + t->n;
      const char* e = ptr + len - 1;
      for(; s <= e; e--) { if(*e!='\r' && *e!='\n') break; }
      for(; s <= e; s++) { if(*s!=' '  && *s!='\t' && *s!=':') break; }
      if(s<=e) {
        char* v = apr_pstrndup(rec->pool, s, e-s+1);
        apr_table_set(rec->headers_out, t->s, v);
        AP_LOG_DEBUG(rec, "[CURL] %s => '%s'", t->s, v);
      }
      return nmemb;
    }
  }

  return nmemb;
}


size_t CurlBucket::curl_write_cb(const void* ptr, size_t size, size_t nmemb, void* _this)
{
  CurlBucket* self = (CurlBucket*)_this;
  apr_off_t len = size*nmemb;

  if(nmemb==0) return 0;

  // Copy 'len' bytes from ptr to bucket.
  while(1) {
    pthread_mutex_lock(&self->mutex);
    if(self->transfer_data==NULL) break;

    // Switch to bucket thread.
    pthread_mutex_unlock(&self->mutex);
    pthread_cond_signal(&self->cond);
  }

  AP_LOG_VERBOSE(self->rec, "[CURL] body %llu bytes read.", len);

  // Load to self->transfer_data
  self->transfer_data = (char*)apr_bucket_alloc(len, self->bucket_alloc);
  memcpy(self->transfer_data, ptr, len);
  self->transfer_remain = len;
  self->transfer_offset = 0;
 
  pthread_mutex_unlock(&self->mutex);
  pthread_cond_signal(&self->cond);

  return nmemb;
}
