//go:build cgo
// +build cgo

package main

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"unsafe"

	"github.com/psanford/wormhole-william/wormhole"
)

// #include <stdlib.h>
// #include "client.h"
import "C"

func main() {

}

type Command int

const (
	DOWNLOAD Command = 0
	REJECT   Command = 1
	CANCEL   Command = 2
)

type transferContext struct {
	Commands   chan Command
	CancelFunc context.CancelFunc
}

type clientWithContext struct {
	appContext PendingTransfer
	client     *wormhole.Client
}

var pendingTransfers map[unsafe.Pointer]transferContext = map[unsafe.Pointer]transferContext{}

func addPendingTransfer(transferRef unsafe.Pointer, cancelFunc context.CancelFunc) {
	pendingTransfers[transferRef] = transferContext{
		Commands:   make(chan Command),
		CancelFunc: cancelFunc,
	}
}

//export Finalize
func Finalize(transfer *C.wrapped_context_t) {
	transfer.Log("Finalizing transfer: %p", transfer)
	transferContext, ok := pendingTransfers[unsafe.Pointer(transfer)]
	if !ok {
		panic("Finalizing an invalid transfer")
	}
	close(transferContext.Commands)
	delete(pendingTransfers, unsafe.Pointer(transfer))
	transfer.Finalize()
}

func sendText(transfer PendingTransfer, msg string) {
	ctx := context.Background()

	code, status, err := transfer.NewClient().SendText(ctx, msg)

	if err != nil {
		transfer.NotifyCodeGenerationFailure(C.CodeGenerationFailed, err.Error())
		return
	}

	transfer.NotifyCodeGenerated(code)

	go func() {
		s := <-status
		if s.Error != nil {
			transfer.NotifyError(C.SendTextError, s.Error.Error())
		} else if s.OK {
			transfer.NotifySuccess()
		} else {
			transfer.NotifyError(C.SendTextError, "Unknown error")
		}
	}()
}

//export ClientSendText
func ClientSendText(transfer *C.wrapped_context_t, msgC *C.char) {
	msg := C.GoString(msgC)
	go sendText(transfer, msg)
}

func sendFile(transfer PendingTransfer, fileName string) {
	ctx, cancel := context.WithCancel(context.Background())
	addPendingTransfer(transfer.Reference(), cancel)
	transferRef := transfer.Reference()

	reader := NewNativeReader(transfer)

	code, status, err := transfer.NewClient().SendFile(ctx, fileName, reader, true, wormhole.WithProgress(transfer.UpdateProgress))

	if err != nil {
		transfer.NotifyCodeGenerationFailure(C.CodeGenerationFailed, err.Error())
		return
	}

	transfer.NotifyCodeGenerated(code)

	go func() {
		for msg := range pendingTransfers[transferRef].Commands {
			switch msg {
			case CANCEL:
				reader.Close()
				// TODO this is sent because the current implementation of the client
				// does not put an error when the context is cancelled before the
				// transfer has started
				// This can be removed if/when the client implements that behaviour
				status <- wormhole.SendResult{
					Error: fmt.Errorf(ERR_CONTEXT_CANCELLED),
				}
				pendingTransfers[transferRef].CancelFunc()
			}
		}
	}()

	go func() {
		s := <-status
		if s.Error != nil {
			transfer.NotifyError(C.SendFileError, s.Error.Error())
		} else if s.OK {
			transfer.NotifySuccess()
		} else {
			transfer.NotifyError(C.SendFileError, "Unknown error")
		}
	}()
}

//export ClientSendFile
func ClientSendFile(transfer *C.wrapped_context_t, fileNameC *C.char) {
	fileName := C.GoString(fileNameC)
	go sendFile(transfer, fileName)
}

func receiveText(transfer PendingTransfer, code string) {
	ctx := context.Background()

	msg, err := transfer.NewClient().Receive(ctx, code, false)
	if err != nil {
		transfer.NotifyError(C.ReceiveTextError, err.Error())
		return
	}

	data, err := ioutil.ReadAll(msg)
	if err != nil {
		transfer.NotifyError(C.ReceiveTextError, err.Error())
		return
	}

	transfer.TextReceived(string(data))
}

//export ClientRecvText
func ClientRecvText(transfer *C.wrapped_context_t, codeC *C.char) {
	code := C.GoString(codeC)
	go receiveText(transfer, code)
}

func recvFile(transfer PendingTransfer, code string) {
	ctx, cancelFunc := context.WithCancel(context.Background())
	addPendingTransfer(transfer.Reference(), cancelFunc)
	downloadId := transfer.Reference()

	msg, err := transfer.NewClient().Receive(ctx, code, true, wormhole.WithProgress(transfer.UpdateProgress))

	if err != nil {
		transfer.NotifyError(C.ReceiveFileError, err.Error())
		return
	}

	transfer.UpdateMetadata(msg.Name, msg.UncompressedBytes64)

	download := func() {
		c_buffer := C.malloc(MAX_READ_BUFFER_LEN)
		defer C.free(c_buffer)

		buffer := make([]byte, MAX_READ_BUFFER_LEN)

		var bytesRead int

		for bytesRead, err = msg.Read(buffer); bytesRead > 0 && err == nil; bytesRead, err = msg.Read(buffer) {
			for i := 0; i < bytesRead; i++ {
				index := (*C.uint8_t)(unsafe.Pointer(uintptr(unsafe.Pointer(c_buffer)) + uintptr(i)))
				*index = C.uint8_t(buffer[i])
			}

			if err = transfer.Write(c_buffer, bytesRead); err != nil {
				break
			}
		}

		if err != nil && err != io.EOF {
			transfer.NotifyError(C.ReceiveFileError, err.Error())
			return
		}

		transfer.NotifySuccess()
	}

	reject := func() {
		msg.Reject()
		transfer.NotifyError(C.TransferRejected, "Transfer rejected")
	}

	go func() {
		for response := range pendingTransfers[downloadId].Commands {
			switch response {
			case DOWNLOAD:
				go download()
			case REJECT:
				reject()
			case CANCEL:
				pendingTransfers[downloadId].CancelFunc()
			}
		}
	}()
}

//export ClientRecvFile
func ClientRecvFile(pendingTransfer *C.wrapped_context_t, codeC *C.char) {
	code := C.GoString(codeC)
	go recvFile(pendingTransfer, code)
}

//export AcceptDownload
func AcceptDownload(transferRef unsafe.Pointer) {
	pendingTransfers[transferRef].Commands <- DOWNLOAD
}

//export RejectDownload
func RejectDownload(transferRef unsafe.Pointer) {
	pendingTransfers[transferRef].Commands <- REJECT
}

//export CancelTransfer
func CancelTransfer(transferRef unsafe.Pointer) {
	pendingTransfers[transferRef].Commands <- CANCEL
}
