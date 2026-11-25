// Package schemaplan defines the content-addressed artifact shared by the
// service builder and explicit database bootstrap runners. It contains no secrets.
package schemaplan

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// ContractVersion names the plan. There is one contract: a plan stating any
// other is refused (Validate).
const ContractVersion = "codefly.dev/postgres-schema-plan/v1"

// A plan states how the read-only group gets its authority. The two are
// alternatives an installation selects between, not generations of one format,
// so the choice is a field of the plan and never read from its label.
const (
	// ReaderGrantsDirect gives the read-only group SELECT on the plan's schemas
	// and default SELECT on what the owner creates there.
	ReaderGrantsDirect = "direct"
	// ReaderGrantsDelegated gives the read-only group no table authority of its
	// own: it is a member of exactly Access.ReadOnlyRoles, and a session selects
	// one of them. It holds for password logins and external identities alike.
	// An empty list is no table authority at all, never a fall back to SELECT.
	ReaderGrantsDelegated = "delegated"
)

func (p Plan) DelegatesReaders() bool {
	return p.Access.ReaderGrants == ReaderGrantsDelegated
}

// Validate refuses a plan this contract does not describe. The format first,
// whatever contract version the plan states: a plan that does not state its
// reader grants was written when the label chose them, and reading it as either
// mode would grant or withhold SELECT on a guess. Then the label: there is one.
// It does not check Digest; a reader compares that with ContentDigest itself.
func (p Plan) Validate() error {
	switch p.Access.ReaderGrants {
	case "":
		return fmt.Errorf("access.reader-grants is not stated: this plan is in the format before a plan stated its reader grants; build it again with a current builder, or state access.reader-grants as %q or %q and the contract version as %s", ReaderGrantsDirect, ReaderGrantsDelegated, ContractVersion)
	case ReaderGrantsDirect:
		if p.Access.ReadOnlyRoles != nil {
			return fmt.Errorf("access.read-only-roles is stated with access.reader-grants %q: only a %q plan names reader roles", ReaderGrantsDirect, ReaderGrantsDelegated)
		}
	case ReaderGrantsDelegated:
	default:
		return fmt.Errorf("access.reader-grants is %q; it is %q or %q", p.Access.ReaderGrants, ReaderGrantsDirect, ReaderGrantsDelegated)
	}
	if p.ContractVersion != ContractVersion {
		return fmt.Errorf("contract-version is %q, which is unknown; this engine reads %s and no other: state the contract version as %s", p.ContractVersion, ContractVersion, ContractVersion)
	}
	return nil
}

const MigrationFileNamePattern = `^([0-9]+)_.+\.(up|down)\.[A-Za-z0-9]+$`

type Plan struct {
	ContractVersion string      `json:"contract-version"`
	Database        string      `json:"database"`
	Extensions      []Extension `json:"extensions"`
	Lineages        []Lineage   `json:"lineages"`
	Access          Access      `json:"access"`
	Digest          string      `json:"digest"`
}

type Extension struct {
	Name     string `json:"name"`
	Required bool   `json:"required"`
}

type Lineage struct {
	Label  string `json:"label"`
	Ledger string `json:"ledger"`
	Stage  string `json:"stage"`
	Digest string `json:"digest"`
	Files  []File `json:"files"`
}

type File struct {
	Name   string `json:"name"`
	Digest string `json:"digest"`
}

type Access struct {
	ReaderGrants   string   `json:"reader-grants"`
	ReadOnlyRole   string   `json:"read-only-role"`
	ReadWriteRole  string   `json:"read-write-role"`
	Schemas        []string `json:"schemas"`
	ReadWriteRoles []string `json:"read-write-roles"`
	ReadOnlyRoles  []string `json:"read-only-roles,omitempty"`
}

// ContentDigest is the plan's deterministic identity. The reader grants are
// part of it, so two plans that differ only in mode never share a digest.
func (p Plan) ContentDigest() string {
	h := sha256.New()
	write := func(values ...string) {
		for _, v := range values {
			h.Write([]byte(v))
			h.Write([]byte{0})
		}
	}
	write(p.ContractVersion, p.Database)
	for _, e := range p.Extensions {
		write(e.Name, fmt.Sprint(e.Required))
	}
	write(p.Access.ReadOnlyRole, p.Access.ReadWriteRole)
	write(p.Access.Schemas...)
	write(p.Access.ReadWriteRoles...)
	write("reader-grants", p.Access.ReaderGrants)
	if p.DelegatesReaders() {
		write("read-only-roles", fmt.Sprint(len(p.Access.ReadOnlyRoles)))
		write(p.Access.ReadOnlyRoles...)
	}
	for _, l := range p.Lineages {
		write(l.Label, l.Ledger, l.Stage, l.Digest)
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

func (l Lineage) ContentDigest() string {
	h := sha256.New()
	h.Write([]byte(l.Label + "\x00" + l.Ledger + "\x00"))
	for _, f := range l.Files {
		h.Write([]byte(f.Name + "\x00" + f.Digest + "\x00"))
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}
