package wormhole

import (
	"context"
	"encoding/json"
	"testing"
)

func TestDilationVersionsMsgMarshalUnmarshal(t *testing.T) {
	versions := []string{"1"}
	abilities := []string{}
	m := genVersionsPayload(versions, abilities, &appVersionsMsg{})
	jMsg, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("error marshaling the message")
	}

	var dm versionsMsg
	err = json.Unmarshal(jMsg, &dm)
	if err != nil {
		t.Fatal("error unmarshaling the json string")
	}

	if len(dm.CanDilate) != 1 || dm.CanDilate[0] != m.CanDilate[0] {
		t.Fatalf("unserialized value does not match the original")
	}
}

// test dilation capability exchange
func TestDilationCapabilityNegotiation(t *testing.T) {
	ctx := context.Background()

	cc0 := newClientProtocol(ctx, nil, "foobar0", "dilateTest", true)
	if !cc0.areBothSidesDilationCapable([]string{"1"}) {
		t.Fatalf("expected the dilation versions to match")
	}
}

func TestDilationRole(t *testing.T) {
	side1 := "10000"
	d1 := &dilationProtocol{
		versions: []string{"1"},
		side:     side1,
	}

	side2 := "10001"
	d1.chooseRole(side2)
	if d1.role != Follower {
		t.Fatalf("side %s should be leader and side %s should be follower", side1, side2)
	}
}

func TestDilationManagerStateTransition(t *testing.T) {
	d := InitDilation()
	outEvents := d.managerStateMachine(ManagerInputEventStart)

	if len(outEvents) != 1 {
		t.Fatalf("expected please event, but got none")
	}

	if d.getState() != ManagerStateWanting {
		t.Fatalf("expected state to change from WAITING to WANTING with START event")
	}
}
