//go:build !js && !wasm
// +build !js,!wasm

package main

import (
	"fmt"
	"os"

	"github.com/psanford/wormhole-william/cmd"
)

func main() {
	err := cmd.Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}
}
