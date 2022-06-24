//go:build !js && !wasm
// +build !js,!wasm

package cmd

import (
	"os"

	"github.com/psanford/wormhole-william/version"
	"github.com/psanford/wormhole-william/wormhole"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:     "wormhole-william",
	Short:   "Create a wormhole and transfer files through it.",
	Version: version.AgentVersion,
	Long: `Create a (magic) Wormhole and communicate through it.

  Wormholes are created by speaking the same magic CODE in two different
  places at the same time. Wormholes are secure against anyone who doesn't
  use the same code.`,
}

var (
	appID           string
	relayURL        string
	transitHelper   string
	verify          bool
	hideProgressBar bool
	disableListener bool
)

func Execute() error {
	rootCmd.PersistentFlags().StringVar(&relayURL, "relay-url", wormhole.DefaultRendezvousURL, "rendezvous relay to use")
	if relayURL == "" {
		relayURL = os.Getenv("WORMHOLE_RELAY_URL")
	}

	rootCmd.PersistentFlags().StringVar(&transitHelper, "transit-helper", wormhole.DefaultTransitRelayURL, "relay server url")
	if transitHelper == "" {
		transitHelper = os.Getenv("WORMHOLE_TRANSITSERVER_URL")
	}

	rootCmd.PersistentFlags().BoolVar(&disableListener, "no-listen", false, "(debug) don't open a listening socket for transit")

	rootCmd.PersistentFlags().StringVar(&appID, "appid", wormhole.WormholeCLIAppID, "AppID to use")

	rootCmd.AddCommand(recvCommand())
	rootCmd.AddCommand(sendCommand())
	rootCmd.AddCommand(completionCommand())
	return rootCmd.Execute()
}
