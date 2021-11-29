package msgs

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestStructTags(t *testing.T) {
	for n, iface := range MsgMap {
		st := reflect.TypeOf(iface)
		for i := 0; i < st.NumField(); i++ {
			field := st.Field(i)
			if field.Name == "Type" {
				tagVal, _ := field.Tag.Lookup("rendezvous_value")
				if tagVal != n {
					t.Errorf("msgMap key / Type struct tag rendezvous_value mismatch: key=%s tag=%s struct=%T", n, tagVal, iface)
				}
			}
		}
	}
}

func TestWelcomeMsgEncode(t *testing.T) {
	welcomeMsg := Welcome{
		Type: "welcome",
		Welcome: WelcomeServerInfo{
			MOTD: "motd",
			PermissionRequired: &PermissionRequiredInfo{
				None: &struct{}{},
				HashCash: &HashCashInfo{
					Bits:     6,
					Resource: "see description",
				},
			},
		},
	}
	b, err := json.Marshal(welcomeMsg)
	if err != nil {
		t.Errorf("welcome msg: error creating message")
	}

	// unmarshall the message back to a struct.
	var unM Welcome
	err = json.Unmarshal(b, &unM)
	if err != nil {
		t.Errorf("welcome msg: error parsing message")
	}

	if *unM.Welcome.PermissionRequired.None != struct{}{} {
		t.Errorf("permission-required: incorrect encoding")
	}

	hk := unM.Welcome.PermissionRequired.HashCash
	if hk.Bits != 6 {
		t.Errorf("hash-cash: incorrect encoding. Got %d, expected 6", hk.Bits)
	}

	expectedResourceStr := welcomeMsg.Welcome.PermissionRequired.HashCash.Resource
	if hk.Resource != expectedResourceStr {
		t.Errorf("hash-cash: incorrect encoding. Got \"%s\", expected \"%s\"", hk.Resource, expectedResourceStr)
	}
}
