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
	managerState    ManagerState
	managerStateMu  sync.Mutex
	managerInputEv  chan ManagerInputEvent
	role            Role
	side            string
	// The code mostly sans-io approach: functional core,
	// imperative shell.
	//
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
type ManagerState int
type ManagerInputEvent int
type ManagerOutputEvent int

const (
	DilationNotNegotiated DilationState = -1
	DilationImpossible DilationState = iota
	DilationPossible
)

const (
	ManagerStateWaiting = iota
	ManagerStateWanting
	ManagerStateConnecting
	ManagerStateConnected
	ManagerStateFlushing
	ManagerStateLonely
	ManagerStateAbandoning
	ManagerStateStopping
	ManagerStateStopped
)

const (
	ManagerInputEventStart = iota
	ManagerInputEventRxPlease
	ManagerInputEventConnectionMade
	ManagerInputEventRxReconnecting
	ManagerInputEventRxReconnect
	ManagerInputEventConnectionLostLeader
	ManagerInputEventConnectionLostFollower
	ManagerInputEventRxHints
	ManagerInputEventStop
)

const (
	ManagerOutputEventSendPlease = iota
	ManagerOutputEventNotifyStopped
	ManagerOutputEventRxHints
	ManagerOutputEventChooseRole
	ManagerOutputEventStartConnectingIgnoreMsg
	ManagerOutputEventUseHints
	ManagerOutputStopConnecting
	ManagerOutputSendReconnecting
	ManagerOutputStartConnecting
	ManagerOutputSendReconnect
	ManagerOutputAbandonConnection
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
func genDilationMsg(payload []byte, phase int) ([]byte, error) {
	// everytime, we use the existing "phase" to compute the
	// "dilation-$n" field. Maintaining the phase needs to happen
	// outside the core as it is state and so has side effects.

	var msg dilateAddMsg
	msg.tipe = "add"
	msg.phase = fmt.Sprintf("dilate-%d", phase)
	msg.body = hex.EncodeToString(payload)

	return json.Marshal(msg)
}

func (d *dilationProtocol) sendDilationMsg() {
	
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

// State -> a -> (State, b) state machines take the current state, an
// input of type a and gives a new state and a new value of type b.
// In our case, the state is in the type dilationProtocol. Input is a
// bytestring. New state would mutate the current state in d. Output
// would be a bunch of functions that operate on input.
//
// XXX: We would run this state machine in a go routine? The input
// could come via a channel then?
//
// XXX: how do we represent the output?
func (d *dilationProtocol) toState(newState ManagerState) {
	d.managerStateMu.Lock()
	defer d.managerStateMu.Unlock()

	d.managerState = newState
}
func (d *dilationProtocol) managerStateMachine() []ManagerOutputEvent {
	event :=  <-d.managerInputEv
	switch event {
	case ManagerInputEventStart:
		// if current state is WAITING, then go to WANTING and
		// send "please" to peer.
		switch d.managerState {
		case ManagerStateWaiting:
			d.toState(ManagerStateWanting)
			// XXX: send please message
			return []ManagerOutputEvent{ ManagerOutputEventSendPlease }
		default:
			// ignore the rest of the events in this state
		}
	case ManagerInputEventRxPlease:
	case ManagerInputEventConnectionMade:
	case ManagerInputEventRxReconnecting:
	case ManagerInputEventRxReconnect:
	case ManagerInputEventConnectionLostLeader:
	case ManagerInputEventConnectionLostFollower:
	case ManagerInputEventRxHints:
	case ManagerInputEventStop:
	default:
	}
}

// receives decrypted dilate-$n payloads (but still in json)
func (d *dilationProtocol) receiveDilationMsg(plaintext []byte) error {
	var result map[string]interface{}

	err := json.Unmarshal(plaintext, &result)
	if err != nil {
		return err
	}

	// the plaintext message could be either a "please",
	// "connection-hints", "reconnect" or "reconnecting" message.
	switch result["type"] {
	case "please": // XXX: handle "please" msg
		// if we are in WANTING state and get the "please"
		// message, then enter "CONNECTING" state and do
		// "choose_role", "start_connecting_ignore_message" it
		// also depends on the role (i.e. whether we are
		// leader or follower).
		if d.role == Leader {
			switch d.managerState {
			case ManagerStateWanting:
				// current state is WANTING and we got
				// please as input. More to a new state
				d.managerStateMu.Lock()
				d.managerState = ManagerStateConnecting
				d.managerStateMu.Unlock()
				// XXX: generate events: choose_role, start_connecting
			default:
				// ignore the rest, continue in the same state.
			}
		}
	case "connection-hints": // XXX: handle "connection-hints" msg
	case "reconnect": // XXX: handle "reconnect" msg
	case "reconnecting": // XXX: handle "reconnecting" msg
	default:
		// XXX: unknown dilation message
	}

	return nil
}

