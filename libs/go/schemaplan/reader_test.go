package schemaplan

import "testing"

func TestReaderDelegationParticipatesInPlanIdentity(t *testing.T) {
	for _, version := range []string{ContractVersion, ReaderRolesContractVersion, PasswordReaderRolesContractVersion, "unknown"} {
		p := Plan{ContractVersion: version}
		wants := version == ReaderRolesContractVersion || version == PasswordReaderRolesContractVersion
		if p.DelegatesReaders() != wants {
			t.Fatalf("reader delegation for %s", version)
		}
		before := p.ContentDigest()
		p.Access.ReadOnlyRoles = []string{"reader"}
		if (p.ContentDigest() != before) != wants {
			t.Fatalf("reader role digest for %s", version)
		}
	}
}
