/* SPDX-License-Identifier: Apache-2.0 */

#ifndef HF_CJSON_H
#include "cJSON.h"
#else
#include HF_CJSON_H
#endif

#ifndef HF_CURL_H
#include <curl/curl.h>
#else
#include HF_CURL_H
#endif

// These are examples given by huggingface corporation.
// curl -X POST http://localhost:8000/api/generate/ -d '{"inputs": "",
//

#define HF_LOCALHOST_ENDPOINT "http://localhost:8000/api/generate/"
#define HF_API_ENDPOINT "https://api-inference.huggingface.co/models/"

typedef struct {
  char *buf;
  size_t len;
  size_t cap;
} _hf_strbuf;

static inline void hf_strbuf_free(void *buf) { free(((_hf_strbuf *)buf)->buf); }

static inline void cj_delete(void *item) { cJSON_Delete((cJSON *)item); }

static inline size_t hf_curl_write_callback(char *ptr, size_t size,
                                            size_t nmemb, void *userdata) {
  printf("%p %zu %zu %p\n", ptr, size, nmemb, userdata);
  size_t realsize = size * nmemb;
  _hf_strbuf *buf = (_hf_strbuf *)userdata;
  if (buf->len + realsize > buf->cap) {
    buf->cap = buf->cap * 2 + realsize + 1;
    buf->buf = (char *)realloc(buf->buf, buf->cap);
    if (!buf->buf) {
      return 0;
    }
  }
  memcpy(buf->buf + buf->len, ptr, realsize);
  buf->len += realsize;
  return realsize;
}

// Returns # of completions, which is 0 on failure.
static inline size_t hf_complete(char *hf_api_key, char *endpoint,
                                 char *content_before, char *content_after,
                                 size_t max_completions, char **completions) {

  if (!hf_api_key | !endpoint | !content_before | !content_after |
      !max_completions | !completions)
    return 0;

  int num_results = 0;
  size_t num_cleanup_entries = 0;
  struct {
    void *ptr;
    void (*fp)(void *);
  } cleanup_entries[64];
  memset(cleanup_entries, 0, sizeof(cleanup_entries));
#define _hf_cleanup() goto cleanup
#define _hf_cleanup_push(f, p)                                                 \
  do {                                                                         \
    cleanup_entries[num_cleanup_entries].ptr = (p);                            \
    cleanup_entries[num_cleanup_entries].fp = (f);                             \
    num_cleanup_entries++;                                                     \
  } while (0)

  const char *start_token = "{start token}";
  const char *middle_token = "{middle token}";
  const char *end_token = "{end token}";

  const char *auth_bearer = "Authorization: Bearer ";

  CURL *curl;
  char *req_content_buf;
  struct curl_slist *headers = NULL;
  cJSON *req_json = cJSON_CreateObject();
  cJSON *req_parameters = cJSON_CreateObject();
  char *req_json_str;
  char *auth_header;

  const size_t initial_cap = 4096 * 10;
  _hf_strbuf response_strbuf = {NULL, 0, initial_cap};
  cJSON *cj_error = NULL;
  cJSON *response_json = NULL;
  char *response_json_str = NULL;

  curl = curl_easy_init();
  if (!curl)
    _hf_cleanup();
  _hf_cleanup_push(curl_easy_cleanup, curl);

  response_strbuf.buf = (char *)malloc(initial_cap);
  if (!response_strbuf.buf)
    _hf_cleanup();
  _hf_cleanup_push(hf_strbuf_free, &response_strbuf);

  req_content_buf = (char *)malloc(
      strlen(content_before) + strlen(content_after) + strlen(start_token) +
      strlen(end_token) + strlen(middle_token) + 1);
  if (!req_content_buf)
    _hf_cleanup();
  _hf_cleanup_push(free, req_content_buf);
  strcpy(req_content_buf, start_token);
  strcat(req_content_buf, content_before);
  strcat(req_content_buf, middle_token);
  strcat(req_content_buf, content_after);
  strcat(req_content_buf, end_token);

  if (!cJSON_AddStringToObject(req_json, "inputs", req_content_buf))
    _hf_cleanup();
  if (!cJSON_AddNumberToObject(req_parameters, "max_new_tokens",
                               max_completions)) _hf_cleanup();
  if (!cJSON_AddItemToObject(req_json, "parameters", req_parameters))
    _hf_cleanup();

  req_json_str = cJSON_Print(req_json);
  if (!req_json_str)
    _hf_cleanup();
  _hf_cleanup_push(free, req_json_str);

  auth_header = (char *)malloc(strlen(auth_bearer) + strlen(hf_api_key) + 1);
  if (!auth_header)
    _hf_cleanup();
  _hf_cleanup_push(free, auth_header);
  strcpy(auth_header, auth_bearer);
  strcat(auth_header, hf_api_key);

  // init headers
  if (!(headers = curl_slist_append(headers, "Content-Type: application/json")))
    _hf_cleanup();
  if (!(headers = curl_slist_append(headers, "Accept: application/json")))
    _hf_cleanup();
  if (!(headers = curl_slist_append(headers, auth_header)))
    _hf_cleanup();

  if (curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers))
    _hf_cleanup();
  if (curl_easy_setopt(curl, CURLOPT_URL, endpoint))
    _hf_cleanup();
  if (curl_easy_setopt(curl, CURLOPT_POSTFIELDS, req_json_str))
    _hf_cleanup();
  if (curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, hf_curl_write_callback))
    _hf_cleanup();
  if (curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_strbuf))
    _hf_cleanup();
  if (curl_easy_perform(curl))
    _hf_cleanup();

  // parse response json
  response_json = cJSON_Parse(response_strbuf.buf);
  if (!response_json)
    _hf_cleanup();
  _hf_cleanup_push(cj_delete, response_json);

  response_json_str = cJSON_Print(response_json);
  if (!response_json_str)
    _hf_cleanup();
  _hf_cleanup_push(free, response_json_str);
  puts(response_json_str);

  cj_error = cJSON_GetObjectItemCaseSensitive(response_json, "error");
  if (cj_error) {
    printf("Error: %s\n", cj_error->valuestring);
    _hf_cleanup();
  }

cleanup:
  for (size_t i = 0; i < num_cleanup_entries; i++)
    cleanup_entries[i].fp(cleanup_entries[i].ptr);
  return num_results;
}