// +build js,wasm

package main

// NB: see definitions.go's init function
import _ "github.com/psanford/wormhole-william/wasm"

func main() {
	// block to keep the wasm module API available
	<-make(chan struct{})
}
