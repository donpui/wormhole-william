#include "client.h"

#include <stdlib.h>

void call_update_progress(wrapped_context_t *context) {
  context->impl.update_progress(context->clientCtx, &context->progress);
}

void call_notify(wrapped_context_t *context) {
  context->impl.notify(context->clientCtx, &context->result);
}

void call_notify_codegen(wrapped_context_t *context) {
  context->impl.notify_codegen(context->clientCtx, &context->codegen_result);
}

void call_log(wrapped_context_t *context, char *msg) {
  context->impl.log(context->clientCtx, msg);
}

void call_update_metadata(wrapped_context_t *context) {
  context->impl.update_metadata(context->clientCtx, &context->metadata);
}

char *call_write(wrapped_context_t *context, uint8_t *buffer, int length) {
  return context->impl.write(context->clientCtx, buffer, length);
}

read_result_t call_read(wrapped_context_t *context, uint8_t *buffer,
                        int length) {
  return context->impl.read(context->clientCtx, buffer, length);
}

seek_result_t call_seek(wrapped_context_t *context, int64_t offset,
                        int32_t whence) {
  return context->impl.seek(context->clientCtx, offset, whence);
}

void free_file_metadata(file_metadata_t *fmd) {
  if (fmd != NULL) {
    if (fmd->file_name != NULL) {
      free(fmd->file_name);
    }
    free(fmd);
  }
}

void free_result(result_t *result) {
  if (result != NULL) {
    if (result->err_string != NULL) {
      free(result->err_string);
    }

    if (result->received_text != NULL) {
      free(result->received_text);
    }

    free(result);
  }
}

void free_codegen_result(codegen_result_t *result) {
  if (result != NULL) {
    if (result->result_type == CodeGenSuccessful) {
      free(result->generated.code);
    } else {
      free(result->error.error_string);
    }
    free(result);
  }
}

void free_wrapped_context(wrapped_context_t *wctx) {
  if (wctx != NULL) {
    if (wctx->codegen_result.result_type == CodeGenSuccessful &&
        wctx->codegen_result.generated.code != NULL) {
      free(wctx->codegen_result.generated.code);
    } else if (wctx->codegen_result.error.error_string != NULL) {
      free(wctx->codegen_result.error.error_string);
    }

    if (wctx->result.result_type == Success &&
        wctx->result.received_text != NULL) {
      free(wctx->result.received_text);
    } else if (wctx->result.err_string != NULL) {
      free(wctx->result.err_string);
    }

    if (wctx->clientCtx != NULL && wctx->impl.free_client_ctx != NULL) {
      wctx->impl.free_client_ctx(wctx->clientCtx);
    }

    if (wctx->config.app_id != NULL) {
      free(wctx->config.app_id);
    }

    if (wctx->config.rendezvous_url != NULL) {
      free(wctx->config.rendezvous_url);
    }

    if (wctx->config.transit_relay_url != NULL) {
      free(wctx->config.transit_relay_url);
    }

    free(wctx);
  }
}
