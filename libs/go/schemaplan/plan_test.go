package schemaplan

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestReaderRolePlanVersionAndIdentity(t *testing.T) {
	p := Plan{ContractVersion: ContractVersion, Database: "example", Access: Access{ReadOnlyRole: "reader", ReadWriteRole: "writer", Schemas: []string{"public"}}}
	// Captured from the unchanged v1 digest algorithm; v2 must not rewrite old pins.
	const legacy = "sha256:713c26cd61942fd45499bea2670c1de501a8eb5d7d7cdb728f8270fad75cf3da"
	if got := p.ContentDigest(); got != legacy {
		t.Fatalf("v1 digest changed: %s", got)
	}
	raw, err := json.Marshal(p)
	if err != nil || strings.Contains(string(raw), "read-only-roles") {
		t.Fatal("legacy JSON acquired a reader-role field")
	}
	p.ContractVersion = ReaderRolesContractVersion
	empty := p.ContentDigest()
	if empty == legacy {
		t.Fatal("v2 is indistinguishable from v1")
	}
	p.Access.ReadOnlyRoles = []string{"app_reader"}
	first := p.ContentDigest()
	if first == empty {
		t.Fatal("reader role omitted from digest")
	}
	p.Access.ReadOnlyRoles = []string{"other_reader"}
	if p.ContentDigest() == first {
		t.Fatal("changed reader role retained identity")
	}
	p.Access.ReadOnlyRoles = []string{}
	if p.ContentDigest() != empty {
		t.Fatal("empty reader delegation must have one identity")
	}
}
