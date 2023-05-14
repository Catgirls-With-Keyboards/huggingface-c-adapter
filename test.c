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

#define MAX_COMPLETIONS 5
#define MAX_NEW_TOKENS 60

int main(void) {
  // Read api key from file.
  char *api_key = read_file("test_api_key.txt");

  char *endpoint = HF_REMOTE_ENDPOINT(HF_REMOTE_ENDPOINT_ID_STARCODER_BASE);

  char *before = "// forkbomb.c : Crashes ur machine uwu <3\n#include <unistd.h>\n\nint main(void) {";
  char *after = "}\n";

  char *completions[MAX_COMPLETIONS];
  size_t num_completions = hf_complete(
      api_key, endpoint, HF_DEFAULT_TIMEOUT_MS, before, after, HF_DEFAULT_TEMP,
      HF_DEFAULT_TOP_P, MAX_NEW_TOKENS, MAX_COMPLETIONS, completions);
  free(api_key);

  if (!num_completions)
    return fprintf(stderr, "Error in completion.\n"), 1;
  for (size_t i = 0; i < num_completions; i++) {
    printf("Completion %zu: %s\n", i + 1, completions[i]);
    free(completions[i]);
  }
}