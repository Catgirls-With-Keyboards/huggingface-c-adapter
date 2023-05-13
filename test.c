/* SPDX-License-Identifier: Apache-2.0 */

#include "hf_c_adapter.h"

#include <errno.h>
#include <stdio.h>

static char *read_file(char *fname) {
  FILE *f = fopen(fname, "r");
  if (f == NULL) {
    printf("Error opening file %s\n", fname);
    return NULL;
  }

  fseek(f, 0, SEEK_END);
  long fsize = ftell(f);
  fseek(f, 0, SEEK_SET);

  char *content = malloc(fsize + 1);
  fread(content, 1, fsize, f);
  fclose(f);

  content[fsize] = 0;
  return content;
}

int main(void) {
  // Read api key from file.
  char *api_key = read_file("test_api_key.txt");
  char *endpoint = HF_API_ENDPOINT;

  char *before = "Before_";
  char *after = "_After";

  #define MAX_COMPLETIONS 5
  char *completions[MAX_COMPLETIONS];
  size_t num_completions = hf_complete(api_key, endpoint, before, after, MAX_COMPLETIONS, completions);
  if (!num_completions) {
    printf("Error in completion.\nErrno: %s\n", strerror(errno));
    return 1;
  }
}