// Package schemaplan defines the content-addressed artifact shared by the
// service builder and explicit database bootstrap runners. It contains no secrets.
package schemaplan

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

const ContractVersion = "codefly.dev/postgres-schema-plan/v1"
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
	ReadOnlyRole   string   `json:"read-only-role"`
	ReadWriteRole  string   `json:"read-write-role"`
	Schemas        []string `json:"schemas"`
	ReadWriteRoles []string `json:"read-write-roles"`
}

// ContentDigest preserves the v1 builder's deterministic identity.
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
