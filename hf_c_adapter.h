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

#define HF_LOCALHOST_ENDPOINT(port) "http://localhost:" port "/api/generate/"
#define HF_REMOTE_ENDPOINT(id) "https://api-inference.huggingface.co/models/" id
#define HF_REMOTE_ENDPOINT_ID_STARCODER_BASE "bigcode/starcoderbase"
#define HF_REMOTE_ENDPOINT_ID_STARCODER_PYTHON "bigcode/starcoder"
#define HF_DEFAULT_TEMP 0.2
#define HF_DEFAULT_TOP_P 0.95
#define HF_DEFAULT_TIMEOUT_MS 10000

typedef struct {
  char *buf;
  size_t len;
  size_t cap;
} _hf_strbuf;

static inline void hf_strbuf_free(void *buf) { free(((_hf_strbuf *)buf)->buf); }
static inline void cj_delete(void *item) { cJSON_Delete((cJSON *)item); }
static inline void sl_free(void *sl) {
  curl_slist_free_all((struct curl_slist *)sl);
}

static inline size_t hf_curl_write_callback(char *ptr, size_t size,
                                            size_t nmemb, void *userdata) {
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
                                 long timeout_ms, char *content_before,
                                 char *content_after, double temperature,
                                 double top_p, size_t max_new_tokens,
                                 size_t max_completions, char **completions) {

  if (!hf_api_key | !endpoint | !content_before | !content_after |
      !max_completions | !max_new_tokens | timeout_ms < 0 | !completions)
    return 0;

#define _hf_cleanup() goto cleanup
#define _hf_cleanup_push(f, p)                                                 \
  do {                                                                         \
    cleanup_entries[num_cleanup_entries].ptr = (p);                            \
    cleanup_entries[num_cleanup_entries].fp = (f);                             \
    num_cleanup_entries++;                                                     \
  } while (0)
  size_t num_cleanup_entries = 0;
  struct {
    void *ptr;
    void (*fp)(void *);
  } cleanup_entries[64];
  memset(cleanup_entries, 0, sizeof(cleanup_entries));

  // https://github.com/huggingface/huggingface-vscode/issues/33
  const char *start_token = "<fim_prefix>";
  const char *middle_token = "<fim_middle>";
  const char *end_token = "<fim_suffix>";
  const char *end_of_text_token = "<|endoftext|>";
  const char *auth_bearer = "Authorization: Bearer ";

  size_t num_results = 0;

  CURL *curl;
  char *req_content_buf;
  struct curl_slist *headers = NULL;
  cJSON *req_json;
  cJSON *req_parameters;
  char *req_json_str;
  char *auth_header;

  const size_t initial_respbuf_cap = 4096 * 10;
  _hf_strbuf response_strbuf = {NULL, 0, 0};
  cJSON *cj_error;
  cJSON *response_json_arr;
  char *response_json_str;

  curl = curl_easy_init();
  if (!curl)
    _hf_cleanup();
  _hf_cleanup_push(curl_easy_cleanup, curl);

  req_json = cJSON_CreateObject();
  if (!req_json)
    _hf_cleanup();
  _hf_cleanup_push(cj_delete, req_json);

  req_parameters = cJSON_CreateObject();
  if (!req_parameters)
    _hf_cleanup();
  // Will be cleaned up as part of previous cleanup push.

  response_strbuf.buf = (char *)malloc(initial_respbuf_cap);
  response_strbuf.cap = initial_respbuf_cap;
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
  strcat(req_content_buf, end_token); // Intentional, lmao.
  strcat(req_content_buf, content_after);
  strcat(req_content_buf, middle_token);

  if (!cJSON_AddStringToObject(req_json, "inputs", req_content_buf))
    _hf_cleanup();
  if (!cJSON_AddNumberToObject(req_parameters, "max_completions",
                               max_completions))
    _hf_cleanup();
  if (!cJSON_AddNumberToObject(req_parameters, "max_new_tokens",
                               max_new_tokens))
    _hf_cleanup();
  if (!cJSON_AddNumberToObject(req_parameters, "temperature", temperature))
    _hf_cleanup();
  if (!cJSON_AddNumberToObject(req_parameters, "top_p", top_p))
    _hf_cleanup();
  if (!cJSON_AddItemToObject(req_json, "parameters", req_parameters))
    _hf_cleanup();

  req_json_str = cJSON_Print(req_json);
  if (!req_json_str)
    _hf_cleanup();
  _hf_cleanup_push(free, req_json_str);
  puts(req_json_str);

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
  _hf_cleanup_push(sl_free, headers);

  if (curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers))
    _hf_cleanup();
  if (curl_easy_setopt(curl, CURLOPT_URL, endpoint))
    _hf_cleanup();
  if (curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, timeout_ms))
    _hf_cleanup();
  if (curl_easy_setopt(curl, CURLOPT_POSTFIELDS, req_json_str))
    _hf_cleanup();
  if (curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, hf_curl_write_callback))
    _hf_cleanup();
  if (curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_strbuf))
    _hf_cleanup();

  // Make request (blocking)
  if (curl_easy_perform(curl))
    _hf_cleanup();

  response_json_arr = cJSON_Parse(response_strbuf.buf);
  if (!response_json_arr)
    _hf_cleanup();
  _hf_cleanup_push(cj_delete, response_json_arr);

  response_json_str = cJSON_Print(response_json_arr);
  if (!response_json_str)
    _hf_cleanup();
  _hf_cleanup_push(free, response_json_str);
  puts(response_json_str);

  cj_error = cJSON_GetObjectItemCaseSensitive(response_json_arr, "error");
  if (cj_error)
    _hf_cleanup();

  // Get content
  if (!cJSON_IsArray(response_json_arr))
    _hf_cleanup();
  for (size_t i = 0; i < cJSON_GetArraySize(response_json_arr); i++) {
    // Get generated text for each completion
    cJSON *item = cJSON_GetArrayItem(response_json_arr, i);
    if (!item)
      _hf_cleanup();
    cJSON *generated_text =
        cJSON_GetObjectItemCaseSensitive(item, "generated_text");
    if (!generated_text || !cJSON_IsString(generated_text))
      _hf_cleanup();

    // Return generated from each completion
    if (num_results >= max_completions)
      _hf_cleanup();

    // Grab the string from the response
    char *fullstr = strdup(generated_text->valuestring);
    if (!fullstr)
      _hf_cleanup();

    // Remove content before middle_token.
    {
      char *i = req_content_buf;
      char *j = fullstr;

      // check fullstr starts with req_content_buf
      for (; *i != '\0'; ++i, ++j) {
        if (*i != *j)
          _hf_cleanup();
      } //* effect: j += strlen(req_content_buf);

      memmove(fullstr, j, strlen(j) + 1);
    }

    // Remove end_token.
    char *eot = strstr(fullstr, end_of_text_token);
    if (eot)
      *eot = '\0';

    completions[num_results++] = fullstr;
  }

cleanup:
  for (size_t i = 0; i < num_cleanup_entries; i++)
    cleanup_entries[i].fp(cleanup_entries[i].ptr);
  return num_results;
}
