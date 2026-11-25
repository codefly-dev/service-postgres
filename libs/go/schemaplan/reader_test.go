package schemaplan

import "testing"

// Delegation is read from the plan's stated reader grants and from nothing
// else: the label does not choose it, and reader roles enter the identity only
// of a plan that delegates.
func TestReaderDelegationParticipatesInPlanIdentity(t *testing.T) {
	for _, version := range []string{ContractVersion, neverIssued} {
		for _, grants := range []string{ReaderGrantsDirect, ReaderGrantsDelegated, "", "unknown"} {
			p := Plan{ContractVersion: version, Access: Access{ReaderGrants: grants}}
			wants := grants == ReaderGrantsDelegated
			if p.DelegatesReaders() != wants {
				t.Fatalf("reader delegation for %s under %s", grants, version)
			}
			before := p.ContentDigest()
			p.Access.ReadOnlyRoles = []string{"reader"}
			if (p.ContentDigest() != before) != wants {
				t.Fatalf("reader role digest for %s under %s", grants, version)
			}
		}
	}
}
