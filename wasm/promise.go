//go:build js && wasm
// +build js,wasm

package wasm

import (
	"syscall/js"
)

type ResolveFn = func(interface{})
type RejectFn = func(error)
type PromiseFn = func(ResolveFn, RejectFn)

func NewPromise(fn PromiseFn) js.Value {
	constructor := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		// TODO: error handling!!!
		resolve := func(val interface{}) {
			args[0].Invoke(val)
		}
		reject := func(err error) {
			args[1].Invoke(err.Error())
		}

		go func() {
			fn(resolve, reject)
		}()
		return nil
	})
	jsPromise := js.Global().Get("Promise").New(constructor)
	constructor.Release()
	return jsPromise
}
