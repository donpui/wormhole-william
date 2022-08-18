package wormhole

import (
	"errors"
	"encoding/json"
	"encoding/hex"
	"sync"
	"fmt"

	"github.com/psanford/wormhole-william/internal/crypto"
)

type dilationProtocol struct {
	versions        []string
	state           DilationState
	stateMu         sync.Mutex
	role            Role
	side            string
	phase           int
	phaseMu         sync.Mutex
	// XXX: The type should have a channel to receive input events
	// and messages from I/O shell and a channel to send output
	// events and messages. These output events can be thought of
	// as commands on what the I/O layer needs to do. The timeouts
	// etc are handled in the I/O layer and conveyed to the core
	// via events. Core would produce output events or commands in
	// response. Some of these events/commands may also carry a
	// payload that the command needs to act on. In short, it is a
	// state machine that produces new state and an output in
	// response to inputs.
}

type DilationState int
type Role string

const (
	DilationNotNegotiated DilationState = -1
	DilationImpossible DilationState = iota
	DilationPossible
)

const (
	Leader Role = "Leader"
	Follower Role = "Follower"
)

type pleaseMsg struct {
	// because type is a reserved keyword
	tipe     string     `json:"type"`
	side     string     `json:"side"`
	// XXX: docs rightly talks about a "use-version" field that
	// would calculate the version to use based on the earlier
	// "can-dilate" field in the versions message. But in the
	// python code, it seem to have been omitted. Perhaps it is a
	// good thing to re-instate it in the code.
}

type hints struct {
	tipe      string  `json:"type"`
	priority  float32 `json:"priority"`
	hostname  string  `json:"hostname"`
	port      int     `json:"port"`
}

type connectionHintsMsg struct {
	tipe    string    `json:"type"`
	hints   []hints   `json:"connection-hints"`
}

type dilateAddMsg struct {
	tipe  string `json:"type"`  // "type": "add"
	phase string `json:"phase"` // "phase": "dilate-${n}"
	body  string `json:"body"`  // "body": <encrypted contents>
	// XXX: id? "id": "2-byte hex string"
}

func genSide() string {
	return crypto.RandSideID()
}

func InitDilation() *dilationProtocol {
	mySide := genSide()
	return &dilationProtocol{
		versions: []string{ "1" },
		side: mySide,
	}
}

func (d *dilationProtocol) chooseRole(otherSide string) error {
	if d.side > otherSide {
		d.role = Leader
	} else if d.side < otherSide {
		d.role = Follower
	} else {
		return errors.New("sides shouldn't be equal")
	}
	return nil
}

// like sending a message via mailbox, but instead of numbered phases,
// it will use phase names like "dilate-1", "dilate-2" .. etc
func (d *dilationProtocol) genDilateMsg(payload []byte) ([]byte, error) {
	// everytime, we use the existing "phase" to compute the
	// "dilation-$n" field and then increment it after acquiring
	// the lock.  This is the only function that modifies the
	// dilation phase.
	d.phaseMu.Lock()
	defer d.phaseMu.Unlock()

	var msg dilateAddMsg
	msg.tipe = "add"
	msg.phase = fmt.Sprintf("dilate-%d", d.phase)
	msg.body = hex.EncodeToString(payload)

	d.phase += 1

	return json.Marshal(msg)
}

// once dilation capability is confirmed for both the sides,
// send the "please" message. "please" is how we learn about the
// other side's "side".
func (d *dilationProtocol) genPleaseMsg() ([]byte, error) {
	please := pleaseMsg{
		tipe: "please", // how wasteful! Can't we autogenerate this?
		side: d.side,
	}
	return json.Marshal(please)
}

// sans-io approach: functional core, imperative shell
