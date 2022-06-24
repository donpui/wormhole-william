//go:build cgo
// +build cgo

package main

import (
	"fmt"
	"strings"
	"unsafe"

	"github.com/psanford/wormhole-william/wormhole"
)

// #include <stdlib.h>
// #include "client.h"
import "C"

const (
	ERR_CONTEXT_CANCELLED    = "context canceled"
	ERR_BROKEN_PIPE          = "write: broken pipe"
	ERR_UNEXPECTED_EOF       = "unexpected EOF"
	ERR_TRANSFER_REJECTED    = "transfer rejected"
	ERR_FAILED_TO_GET_READER = "failed to get reader"
	ERR_WRONG_CODE           = "decrypt message failed"
)

const (
	DEFAULT_APP_ID                      = "lothar.com/wormhole/text-or-file-xfer"
	DEFAULT_RENDEZVOUS_URL              = "ws://relay.magic-wormhole.io:4000/v1"
	DEFAULT_TRANSIT_RELAY_URL           = "tcp:transit.magic-wormhole.io:4001"
	DEFAULT_PASSPHRASE_COMPONENT_LENGTH = 2
)

type PendingTransfer interface {
	Log(message string, args ...interface{})
	UpdateProgress(done int64, total int64)
	NotifyError(result C.result_type_t, errorMessage string)
	UpdateMetadata(fileName string, length int64)
	Write(bytes unsafe.Pointer, length int) error
	Read(buffer *C.uint8_t, length int) (int, error)
	Seek(offset int64, whence int) (int64, error)
	NotifySuccess()
	TextReceived(text string)
	Finalize()
	NotifyCodeGenerationFailure(errorCode C.codegen_result_type_t, errorMessage string)
	NotifyCodeGenerated(code string)
	NewClient() *wormhole.Client
	Reference() unsafe.Pointer
}

// TODO when the original error type contains more information than
// the error message, refactor this
func extractErrorCode(fallback C.result_type_t, errorMessage string) C.result_type_t {
	if fallback == C.SendFileError {
		if strings.Contains(errorMessage, ERR_BROKEN_PIPE) ||
			strings.Contains(errorMessage, ERR_CONTEXT_CANCELLED) {
			return C.TransferCancelled
		} else if strings.Contains(errorMessage, ERR_WRONG_CODE) {
			return C.WrongCode
		}
	} else if fallback == C.ReceiveFileError {
		if strings.Contains(errorMessage, ERR_UNEXPECTED_EOF) ||
			strings.Contains(errorMessage, ERR_CONTEXT_CANCELLED) ||
			strings.Contains(errorMessage, ERR_FAILED_TO_GET_READER) {
			return C.TransferCancelled
		} else if strings.Contains(errorMessage, ERR_WRONG_CODE) {
			return C.WrongCode
		}
	}

	if strings.Contains(errorMessage, ERR_TRANSFER_REJECTED) {
		return C.TransferRejected
	}

	return fallback
}

func (wctx *C.wrapped_context_t) Log(message string, args ...interface{}) {
	messageC := C.CString(fmt.Sprintf(message, args...))
	C.call_log(wctx, messageC)
	C.free(unsafe.Pointer(messageC))
}

func (wctx *C.wrapped_context_t) UpdateProgress(done int64, total int64) {
	wctx.progress.transferred_bytes = C.int64_t(done)
	wctx.progress.total_bytes = C.int64_t(total)
	C.call_update_progress(wctx)
}

func (wctx *C.wrapped_context_t) NotifyError(result C.result_type_t, errorMessage string) {
	wctx.Log("Error: ErrorCode:%d %s", int(result), errorMessage)
	wctx.result.result_type = extractErrorCode(result, errorMessage)
	wctx.result.err_string = C.CString(errorMessage)
	C.call_notify(wctx)
}

func (wctx *C.wrapped_context_t) UpdateMetadata(fileName string, length int64) {
	wctx.Log("Updating metadata. Filename:%s, length:%d", fileName, length)
	wctx.metadata.length = C.int64_t(length)
	wctx.metadata.file_name = C.CString(fileName)
	C.call_update_metadata(wctx)
}

func (wctx *C.wrapped_context_t) Write(bytes unsafe.Pointer, length int) error {
	errorMsg := C.call_write(wctx, (*C.uint8_t)(bytes), C.int32_t(length))

	if unsafe.Pointer(errorMsg) != nil {
		defer C.free(unsafe.Pointer(errorMsg))
		return fmt.Errorf("Failed to write to file: %s", C.GoString(errorMsg))
	}

	return nil
}

func (wctx *C.wrapped_context_t) NotifySuccess() {
	wctx.result.result_type = C.Success
	C.call_notify(wctx)
}

func (wctx *C.wrapped_context_t) TextReceived(text string) {
	wctx.result.result_type = C.Success
	wctx.result.received_text = C.CString(text)
	C.call_notify(wctx)
}

func (wctx *C.wrapped_context_t) Read(buffer *C.uint8_t, length int) (int, error) {
	result := C.call_read(wctx, buffer, C.int(length))
	if result.error_msg != nil {
		defer C.free(unsafe.Pointer(result.error_msg))
		return -1, fmt.Errorf(C.GoString(result.error_msg))
	} else {
		return int(result.bytes_read), nil
	}
}

func (wctx *C.wrapped_context_t) Seek(offset int64, whence int) (int64, error) {
	result := C.call_seek(wctx, C.int64_t(offset), C.int32_t(whence))

	if result.error_msg != nil {
		defer C.free(unsafe.Pointer(result.error_msg))
		return -1, fmt.Errorf(C.GoString(result.error_msg))
	} else {
		return int64(result.current_offset), nil
	}
}

func (wctx *C.wrapped_context_t) NotifyCodeGenerated(code string) {
	wctx.Log("Code generated: %s", code)
	wctx.codegen_result.result_type = C.CodeGenSuccessful
	wctx.codegen_result.generated.code = C.CString(code)
	C.call_notify_codegen(wctx)
}

func (wctx *C.wrapped_context_t) NotifyCodeGenerationFailure(errorCode C.codegen_result_type_t, errorMessage string) {
	wctx.Log("Code generation failed. error code:%d, error message:%s", errorCode, errorMessage)
	wctx.codegen_result.result_type = errorCode
	wctx.codegen_result.error.error_string = C.CString(errorMessage)
	C.call_notify_codegen(wctx)
}

func (wctx *C.wrapped_context_t) Finalize() {
	wctx.Log("Finalizing context at %d", int(uintptr(unsafe.Pointer(wctx))))
	C.free_wrapped_context(wctx)
}

func (wctx *C.wrapped_context_t) NewClient() *wormhole.Client {
	client := &wormhole.Client{
		AppID:                     DEFAULT_APP_ID,
		RendezvousURL:             DEFAULT_RENDEZVOUS_URL,
		TransitRelayURL:           DEFAULT_TRANSIT_RELAY_URL,
		PassPhraseComponentLength: DEFAULT_PASSPHRASE_COMPONENT_LENGTH,
	}

	if wctx.config.app_id != nil {
		client.AppID = C.GoString(wctx.config.app_id)
	}

	if wctx.config.rendezvous_url != nil {
		client.RendezvousURL = C.GoString(wctx.config.rendezvous_url)
	}

	if wctx.config.transit_relay_url != nil {
		client.TransitRelayURL = C.GoString(wctx.config.transit_relay_url)
	}

	if wctx.config.passphrase_length == 0 {
		client.PassPhraseComponentLength = int(wctx.config.passphrase_length)
	}
	return client
}

func (wctx *C.wrapped_context_t) Reference() unsafe.Pointer {
	return unsafe.Pointer(wctx)
}
