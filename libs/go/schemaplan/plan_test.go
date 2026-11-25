package schemaplan

import (
	"encoding/json"
	"strings"
	"testing"
)

// Contract versions stated only to be refused: the two this contract once also
// had, and one it never did.
const (
	onceV2      = "codefly.dev/postgres-schema-plan/v2"                  // version-guard:allow refused by name
	onceV3      = "codefly.dev/postgres-schema-plan/v3"                  // version-guard:allow refused by name
	neverIssued = "codefly.dev/postgres-schema-plan/v999-not-a-contract" // version-guard:allow refused by name
)

func directPlan() Plan {
	return Plan{ContractVersion: ContractVersion, Database: "example", Access: Access{ReaderGrants: ReaderGrantsDirect, ReadOnlyRole: "reader", ReadWriteRole: "writer", Schemas: []string{"public"}}}
}

// The reader grants and the delegated roles are part of a plan's identity: no
// two plans that grant differently share a digest, and an empty delegation is
// one identity however it is spelled.
func TestReaderGrantsAndRolesAreInThePlanIdentity(t *testing.T) {
	p := directPlan()
	direct := p.ContentDigest()
	raw, err := json.Marshal(p)
	if err != nil || strings.Contains(string(raw), "read-only-roles") || !strings.Contains(string(raw), `"reader-grants":"direct"`) {
		t.Fatalf("a direct plan is written as %s", raw)
	}
	p.Access.ReaderGrants = ReaderGrantsDelegated
	empty := p.ContentDigest()
	if empty == direct {
		t.Fatal("a delegated plan is indistinguishable from a direct one")
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

// There is one contract version, v1, and it is the current format: a plan
// states its reader grants. A plan as it was once written, where the label
// chose the grants and no field stated them, is refused for what it lacks,
// whatever label it states; so the v1 of that format is never read as direct
// and its v2 and v3 never as delegated. A plan in the current format stating
// any other label (the v2 and v3 this contract once also had) is refused as
// unknown, telling its author to state v1.
func TestThereIsOneContractVersion(t *testing.T) {
	if ContractVersion != "codefly.dev/postgres-schema-plan/v1" {
		t.Fatalf("the contract version is %s", ContractVersion)
	}
	const access = `"read-only-role":"reader","read-write-role":"writer","schemas":["public"],"read-write-roles":null`
	read := func(label, grants string) error {
		t.Helper()
		var p Plan
		decoder := json.NewDecoder(strings.NewReader(`{"contract-version":"` + label + `","database":"example","extensions":null,"lineages":null,"access":{` + grants + access + `},"digest":""}`))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&p); err != nil {
			t.Fatal(err)
		}
		return p.Validate()
	}
	for name, old := range map[string]struct{ label, grants string }{
		"the direct plan once labelled v1":       {ContractVersion, ``},
		"the delegated plan once labelled v2":    {onceV2, `"read-only-roles":["app_reader"],`},
		"the delegated plan once labelled v3":    {onceV3, `"read-only-roles":["app_reader"],`},
		"that delegated plan, relabelled v1":     {ContractVersion, `"read-only-roles":["app_reader"],`},
		"that format under no label":             {"", ``},
		"that format under a label never issued": {neverIssued, ``},
	} {
		err := read(old.label, old.grants)
		if err == nil || !strings.Contains(err.Error(), "access.reader-grants is not stated") || !strings.Contains(err.Error(), "state access.reader-grants as") {
			t.Fatalf("%s: %v", name, err)
		}
	}
	for _, grants := range []string{`"reader-grants":"direct",`, `"reader-grants":"delegated",`, `"reader-grants":"delegated","read-only-roles":["app_reader"],`} {
		if err := read(ContractVersion, grants); err != nil {
			t.Fatalf("a v1 plan stating %s: %v", grants, err)
		}
		for _, other := range []string{onceV2, onceV3, neverIssued, ""} {
			err := read(other, grants)
			if err == nil || !strings.Contains(err.Error(), "which is unknown") || !strings.Contains(err.Error(), "state the contract version as codefly.dev/postgres-schema-plan/v1") {
				t.Fatalf("contract version %q stating %s: %v", other, grants, err)
			}
		}
	}
	for name, grants := range map[string]string{
		"a direct plan naming reader roles":      `"reader-grants":"direct","read-only-roles":["app_reader"],`,
		"a direct plan with an empty delegation": `"reader-grants":"direct","read-only-roles":[],`,
		"a mode this contract does not have":     `"reader-grants":"password-delegated",`,
	} {
		if err := read(ContractVersion, grants); err == nil || !strings.Contains(err.Error(), "access.") {
			t.Fatalf("%s: %v", name, err)
		}
	}
}
