package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/codefly-dev/service-postgres/libs/go/schemaplan"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// schemaPlanContractVersion identifies the bootstrap artifact's plan format. A
// consumer reading bootstrap/plan.json checks it before interpreting the fields.
const schemaPlanContractVersion = schemaplan.ContractVersion

// schemaPlan is the packaged form of the resolved schema prerequisites: what the
// bootstrap image carries, and what it applies. Resolving and validating the
// declarations belongs to resolveSchemaPrerequisites, which the runtime and the
// build share; this adds only what packaging needs — a staged location per
// lineage, the files staged under it, and the content identity the artifact
// publishes — so the image applies the same schema contract the runtime does.
type schemaPlan struct {
	database   string
	lineages   []schemaLineage
	extensions []extensionRequest
	access     schemaAccess
}

// schemaLineage is one resolved migration lineage together with where the build
// stages it and what it stages.
type schemaLineage struct {
	// migrationSource is what the runtime applies: the lineage's root and the
	// ledger it owns.
	migrationSource
	// stage is the lineage's directory under bootstrap/sources in the build
	// context. The ordinal prefix makes it collision-free by construction.
	stage  string
	files  []schemaFile
	digest string
}

// schemaFile is one staged file's identity within a lineage.
type schemaFile struct {
	name   string
	digest string
}

// schemaAccess carries the runtime-role grant inputs. Both the local reconciler
// and the bootstrap image's runtime-access.sql are driven from these values.
type schemaAccess struct {
	readOnlyRole   string
	readWriteRole  string
	schemas        []string
	readWriteRoles []string
}

// buildSchemaPlan packages already-resolved prerequisites for the build. It is
// pure: it reads the migration files' names, never a database.
//
// NoMigration packages no lineage at all, mirroring applySchema: extensions and
// runtime grants still apply, so the image does exactly what the runtime does.
//
// Every resolved source is packaged as it comes. resolveSchemaPrerequisites
// already excludes a lineage with no migration, and skipping one here as well
// would hide a lineage from the image that the runtime still tried to apply —
// the divergence this packaging exists to remove.
func buildSchemaPlan(prerequisites *schemaPrerequisites, settings *Settings) (*schemaPlan, error) {
	access, err := resolveSchemaAccess(settings)
	if err != nil {
		return nil, err
	}
	plan := &schemaPlan{
		database:   settings.DatabaseName,
		extensions: prerequisites.extensions,
		access:     access,
	}
	if settings.NoMigration {
		return plan, nil
	}
	for _, source := range prerequisites.sources {
		files, filesErr := stagedFiles(source.dir)
		if filesErr != nil {
			return nil, fmt.Errorf("cannot inventory migration source %q: %w", source.label(), filesErr)
		}
		plan.lineages = append(plan.lineages, schemaLineage{
			migrationSource: source,
			stage:           fmt.Sprintf("%02d-%s", len(plan.lineages), source.label()),
			files:           files,
		})
	}
	return plan, nil
}

// stagedFiles lists the files of one source directory that the build stages,
// sorted by name. A file is staged when migrationFileName recognizes it — the
// same single definition the runtime's source driver filters on — so an editor
// backup left beside a migration is neither applied locally nor carried into the
// image. Contents are not read here: digests are filled in by attest, so a plan
// can be assembled without reading every migration byte.
//
// A symlink is followed when its target stays inside the source root, so a
// layout that works locally keeps working. One that leaves the root is rejected:
// staging copies bytes, and content pulled from an arbitrary path would enter
// the image with no record of where it came from. Declare such content as its
// own migration source instead.
func stagedFiles(dir string) ([]schemaFile, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	files := make([]schemaFile, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !migrationFileName.MatchString(entry.Name()) {
			continue
		}
		if entry.Type()&os.ModeSymlink != 0 {
			contained, containedErr := symlinkStaysInside(dir, entry.Name())
			if containedErr != nil {
				return nil, containedErr
			}
			if !contained.Mode().IsRegular() {
				continue
			}
		} else if !entry.Type().IsRegular() {
			return nil, fmt.Errorf("entry %q is not a regular file", entry.Name())
		}
		files = append(files, schemaFile{name: entry.Name()})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].name < files[j].name })
	return files, nil
}

// symlinkStaysInside resolves one symlinked entry and reports its target's file
// information, rejecting a target that resolves outside the source root.
func symlinkStaysInside(dir, name string) (os.FileInfo, error) {
	root, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return nil, err
	}
	target, err := filepath.EvalSymlinks(filepath.Join(dir, name))
	if err != nil {
		return nil, fmt.Errorf("migration source entry %q does not resolve: %w", name, err)
	}
	relative, err := filepath.Rel(root, target)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf(
			"migration source entry %q links outside its source root; declare %s as its own migration source instead",
			name, filepath.Dir(target))
	}
	return os.Stat(target)
}

// attest fills in the content identity the build artifact publishes: a digest
// per staged file and per lineage.
func (p *schemaPlan) attest() error {
	for i := range p.lineages {
		for j := range p.lineages[i].files {
			digest, err := fileDigest(filepath.Join(p.lineages[i].dir, p.lineages[i].files[j].name))
			if err != nil {
				return fmt.Errorf("cannot digest migration source %q: %w", p.lineages[i].label(), err)
			}
			p.lineages[i].files[j].digest = digest
		}
		p.lineages[i].digest = lineageDigest(p.lineages[i])
	}
	return nil
}

// fileDigest streams the file through sha256 rather than buffering it whole, so
// digesting a large data migration does not read it into memory.
func fileDigest(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hasher := sha256.New()
	if _, err = io.Copy(hasher, file); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(hasher.Sum(nil)), nil
}

// digest is the plan's content identity: a deterministic function of every
// lineage's ledger, staged location and file contents, the required extensions,
// and the runtime-role grant inputs. Mutating one migration file changes it.
func (p *schemaPlan) digest() string { return p.artifactWithoutDigest().ContentDigest() }

func lineageDigest(l schemaLineage) string {
	artifact := schemaLineageArtifact{Label: l.label(), Ledger: l.trackingTable()}
	for _, f := range l.files {
		artifact.Files = append(artifact.Files, schemaFileArtifact{Name: f.name, Digest: f.digest})
	}
	return artifact.ContentDigest()
}

// stagedChecksums renders the staged content as a sha256sum manifest, relative
// to the staging root. The bootstrap program verifies it before applying
// anything: the image is built from the service directory by a later, separate
// process, so a staged tree that drifted or was only partly written would
// otherwise apply fewer migrations and report success.
func (p *schemaPlan) stagedChecksums() []byte {
	var manifest strings.Builder
	for _, lineage := range p.lineages {
		for _, file := range lineage.files {
			manifest.WriteString(strings.TrimPrefix(file.digest, "sha256:"))
			manifest.WriteString("  sources/")
			manifest.WriteString(lineage.stage)
			manifest.WriteString("/")
			manifest.WriteString(file.name)
			manifest.WriteString("\n")
		}
	}
	return []byte(manifest.String())
}

func resolveSchemaAccess(settings *Settings) (schemaAccess, error) {
	readOnlyRole, readWriteRole := runtimeRoleNames(settings.DatabaseName)
	schemas, err := normalizedRuntimeSchemas(settings.RuntimeSchemas)
	if err != nil {
		return schemaAccess{}, err
	}
	readWriteRoles, err := normalizedRuntimeReadWriteRoles(settings.RuntimeReadWriteRoles, readOnlyRole, readWriteRole)
	if err != nil {
		return schemaAccess{}, err
	}
	return schemaAccess{
		readOnlyRole:   readOnlyRole,
		readWriteRole:  readWriteRole,
		schemas:        schemas,
		readWriteRoles: readWriteRoles,
	}, nil
}

// schemaPlanArtifact is the bootstrap image's evidence of what it will apply.
// It is deliberately machine-independent and secret-free: staged locations and
// content digests rather than filesystem provenance, role names rather than
// credentials. Two machines building one commit must publish identical bytes.
type schemaPlanArtifact = schemaplan.Plan
type schemaExtensionArtifact = schemaplan.Extension
type schemaLineageArtifact = schemaplan.Lineage
type schemaFileArtifact = schemaplan.File
type schemaAccessArtifact = schemaplan.Access

func (p *schemaPlan) artifact() schemaPlanArtifact {
	a := p.artifactWithoutDigest()
	a.Digest = a.ContentDigest()
	return a
}

func (p *schemaPlan) artifactWithoutDigest() schemaPlanArtifact {
	extensions := make([]schemaExtensionArtifact, 0, len(p.extensions))
	for _, extension := range p.extensions {
		extensions = append(extensions, schemaExtensionArtifact{Name: extension.name, Required: extension.required})
	}
	lineages := make([]schemaLineageArtifact, 0, len(p.lineages))
	for _, lineage := range p.lineages {
		files := make([]schemaFileArtifact, 0, len(lineage.files))
		for _, file := range lineage.files {
			files = append(files, schemaFileArtifact{Name: file.name, Digest: file.digest})
		}
		lineages = append(lineages, schemaLineageArtifact{
			Label:  lineage.label(),
			Ledger: lineage.trackingTable(),
			Stage:  lineage.stage,
			Digest: lineage.digest,
			Files:  files,
		})
	}
	return schemaPlanArtifact{
		ContractVersion: schemaPlanContractVersion,
		Database:        p.database,
		Extensions:      extensions,
		Lineages:        lineages,
		Access: schemaAccessArtifact{
			ReadOnlyRole:   p.access.readOnlyRole,
			ReadWriteRole:  p.access.readWriteRole,
			Schemas:        p.access.schemas,
			ReadWriteRoles: p.access.readWriteRoles,
		},
	}
}
