// +build js,wasm

package wasm

import "syscall/js"

func init() {
	// make things available in JS global scope (i.e. `window` in browsers).
	wormholeObj := js.Global().Get("Object").New()
	clientObj := js.Global().Get("Object").New()

	clientObj.Set("newClient", js.FuncOf(NewClient))
	clientObj.Set("free", js.FuncOf(Client_free))
	clientObj.Set("sendText", js.FuncOf(Client_SendText))
	clientObj.Set("sendFile", js.FuncOf(Client_SendFile))
	clientObj.Set("recvText", js.FuncOf(Client_RecvText))
	clientObj.Set("recvFile", js.FuncOf(Client_RecvFile))

	wormholeObj.Set("Client", clientObj)
	js.Global().Set("Wormhole", wormholeObj)
}
