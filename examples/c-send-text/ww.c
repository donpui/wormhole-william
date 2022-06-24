#include "libwormhole_william.h"

#include <stdio.h>
#include <stdlib.h>

typedef context struct {
  int64_t useful_value;
}

int main(void) {
    uintptr_t client = (void *)NewClient();

    char *msg = "Hello world";
    char *codeOut = (char *) malloc(sizeof(char) * 100);

    context ctx = {
      .useful_value = 100
    };

    int status = ClientSendText(ctx, client, msg, &codeOut, some_callback);
    if (status != 0) {
        fprintf(stderr, "error sending text message\n");
    }
    FreeClient(client);

    free(codeOut);
    return 0;
}

void some_callback(void *ctx, result_t *result, int32_t err_code) {
  printf("ctx.useful_value: %d\n", ((context *)ctx)->useful_value);
  printf("error code: %d; error string: %s\n", result->err_code, result->err_string);
  printf("result->file: %p\n", result->file);
  printf("result->file->length: %d\n", result->file-> length);
  printf("result->file->data: %p\n", result->file->data);
}