#include <stdbool.h>
#include <stdint.h>

#ifndef CLIENT_INCLUDED
#define CLIENT_INCLUDED

#if defined(_WIN32) || defined(_WIN64)
#define DLL_EXPORT __attribute__((dllexport))
#else
#define DLL_EXPORT
#endif

typedef void *client_context_t;

typedef struct {
  char *app_id;
  char *rendezvous_url;
  char *transit_relay_url;
  int32_t passphrase_length;
} client_config_t;

typedef struct {
  int64_t length;
  char *file_name;
} file_metadata_t;

typedef enum {
  Success = 0,
  SendFileError = 1,
  ReceiveFileError = 2,
  SendTextError = 3,
  ReceiveTextError = 4,
  TransferRejected = 5,
  TransferCancelled = 6,
  WrongCode = 7,
} result_type_t;

typedef struct {
  result_type_t result_type;
  char *err_string;
  char *received_text;
} result_t;

typedef enum {
  CodeGenSuccessful = 0,
  FailedToGetClient = 1,
  CodeGenerationFailed = 2
} codegen_result_type_t;

typedef struct {
  codegen_result_type_t result_type;
  struct {
    char *error_string;
  } error;
  struct {
    char *code;
    int32_t transfer_id;
  } generated;
} codegen_result_t;

typedef struct {
  int64_t transferred_bytes;
  int64_t total_bytes;
} progress_t;

typedef struct {
  int64_t bytes_read;
  const char *error_msg;
} read_result_t;

typedef struct {
  int64_t current_offset;
  const char *error_msg;
} seek_result_t;

typedef void (*notifyf)(void *context, result_t *result);
typedef void (*notifycodegenf)(void *context, codegen_result_t *result);
typedef void (*update_progressf)(void *context, progress_t *progress);

typedef void (*update_metadataf)(void *context, file_metadata_t *metadata);

typedef read_result_t (*readf)(void *context, uint8_t *buffer, int length);
typedef seek_result_t (*seekf)(void *context, int64_t offset, int32_t whence);
typedef char *(*writef)(void *context, uint8_t *buffer, int length);

typedef void (*logf)(void *context, char *message);

typedef struct {
  readf read;
  seekf seek;
  update_progressf update_progress;
  notifyf notify;
  notifycodegenf notify_codegen;
  update_metadataf update_metadata;
  writef write;
  void (*free_client_ctx)(client_context_t t);
  logf log;
} client_impl_t;

typedef struct _wrapped_context_t {
  client_context_t clientCtx;

  client_impl_t impl;
  client_config_t config;

  progress_t progress;
  result_t result;
  codegen_result_t codegen_result;
  file_metadata_t metadata;
} wrapped_context_t;

void call_notify(wrapped_context_t *context);
void call_notify_codegen(wrapped_context_t *context);
void call_update_progress(wrapped_context_t *context);
void call_update_metadata(wrapped_context_t *context);

read_result_t call_read(wrapped_context_t *context, uint8_t *buffer,
                        int32_t length);
seek_result_t call_seek(wrapped_context_t *context, int64_t offset,
                        int32_t whence);
char *call_write(wrapped_context_t *context, uint8_t *buffer, int32_t length);

void call_log(wrapped_context_t *context, char *msg);

DLL_EXPORT void free_wrapped_context(wrapped_context_t *wctx);
DLL_EXPORT void free_codegen_result(codegen_result_t *codegen_result);
#endif
