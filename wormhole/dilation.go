package wormhole

import (
	"errors"
	"github.com/psanford/wormhole-william/internal/crypto"
)

type dilationProtocol struct {
	versions        []string
	state           DilationState
	role            Role
	side            string
	phase           int
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
	ty       string     `json:"type"`
	side     string     `json:"side"`
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
func (d *dilationProtocol) sendDilateMsg() {
	
}
