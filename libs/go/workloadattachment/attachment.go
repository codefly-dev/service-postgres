// Package workloadattachment defines the public PostgreSQL workload attachment.
// The platform produces transport fragments; consumers copy them without parsing
// qualification programs. This package never derives identities, grants or proxy args.
package workloadattachment

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"regexp"
	"strings"
)

const Version = "codefly.dev/postgres-workload-attachment/v1"

type Connection struct {
	Kind            string `json:"kind"`
	SocketDirectory string `json:"socket_directory"`
	Port            int    `json:"port"`
}
type Binding struct {
	Primitive  string     `json:"primitive"`
	ID         string     `json:"binding_id"`
	Access     string     `json:"access"`
	Database   string     `json:"database"`
	User       string     `json:"user"`
	Connection Connection `json:"connection"`
}
type Mount struct {
	Name      string `json:"name"`
	MountPath string `json:"mountPath"`
	ReadOnly  *bool  `json:"readOnly,omitempty"`
}
type EmptyDir struct {
	Medium    string `json:"medium"`
	SizeLimit string `json:"sizeLimit"`
}
type Volume struct {
	Name     string   `json:"name"`
	EmptyDir EmptyDir `json:"emptyDir"`
}
type Capabilities struct {
	Drop []string `json:"drop"`
}
type Security struct {
	AllowPrivilegeEscalation *bool        `json:"allowPrivilegeEscalation"`
	ReadOnlyRootFilesystem   bool         `json:"readOnlyRootFilesystem"`
	Capabilities             Capabilities `json:"capabilities"`
}
type Seccomp struct {
	Type string `json:"type"`
}
type PodSecurity struct {
	RunAsNonRoot   bool    `json:"runAsNonRoot"`
	RunAsUser      int     `json:"runAsUser"`
	RunAsGroup     int     `json:"runAsGroup"`
	FSGroup        int     `json:"fsGroup"`
	SeccompProfile Seccomp `json:"seccompProfile"`
}
type ResourceValues struct {
	CPU    string `json:"cpu"`
	Memory string `json:"memory"`
}
type Resources struct {
	Requests ResourceValues `json:"requests"`
	Limits   ResourceValues `json:"limits"`
}
type Sidecar struct {
	Name            string    `json:"name"`
	Image           string    `json:"image"`
	RestartPolicy   string    `json:"restartPolicy"`
	Args            []string  `json:"args"`
	VolumeMounts    []Mount   `json:"volumeMounts"`
	SecurityContext Security  `json:"securityContext"`
	Resources       Resources `json:"resources"`
}
type Attachment struct {
	SchemaVersion      string      `json:"schema_version"`
	Binding            Binding     `json:"binding"`
	Namespace          string      `json:"namespace"`
	ServiceAccount     string      `json:"service_account"`
	PodSecurityContext PodSecurity `json:"pod_security_context"`
	InitContainers     []Sidecar   `json:"init_containers"`
	Volumes            []Volume    `json:"volumes"`
	VolumeMounts       []Mount     `json:"volume_mounts"`
	Digest             string      `json:"digest"`
}

var namePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
var imagePattern = regexp.MustCompile(`^[^\s@]+@sha256:[a-f0-9]{64}$`)

func validPath(value string) bool {
	return path.IsAbs(value) && value != "/" && path.Clean(value) == value && !strings.ContainsAny(value, "\t\r\n ") && !strings.Contains(value, ".s.PGSQL.")
}
func bounded(s string) bool {
	return len(s) > 0 && len(s) <= 1024 && !strings.ContainsAny(s, "\x00\r\n")
}

// Parse rejects unknown fields and extra JSON documents before validating the seal.
func Parse(data []byte) (*Attachment, error) {
	var a Attachment
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&a); err != nil {
		return nil, fmt.Errorf("invalid attachment: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("attachment must contain one JSON document")
	}
	if err := a.Validate(); err != nil {
		return nil, err
	}
	return &a, nil
}

// Seal binds all supplied transport and identity fields. It is an integrity seal,
// not a signature or authorization; deployment policy approves the exact digest.
func (a *Attachment) Seal() error {
	digest, err := a.computedDigest()
	if err != nil {
		return err
	}
	a.Digest = digest
	return nil
}
func (a *Attachment) computedDigest() (string, error) {
	data, err := json.Marshal(a)
	if err != nil {
		return "", err
	}
	var value map[string]any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err = decoder.Decode(&value); err != nil {
		return "", err
	}
	delete(value, "digest")
	var canonical bytes.Buffer
	encoder := json.NewEncoder(&canonical)
	encoder.SetEscapeHTML(false)
	if err = encoder.Encode(value); err != nil {
		return "", err
	}
	sum := sha256.Sum256(bytes.TrimSuffix(canonical.Bytes(), []byte("\n")))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// Validate checks the neutral security envelope and references. Cloud transport
// argument semantics and approved identity matching belong to its platform producer.
func (a *Attachment) Validate() error {
	fail := func() error { return fmt.Errorf("invalid PostgreSQL workload attachment") }
	if a.SchemaVersion != Version || !namePattern.MatchString(a.Namespace) || !namePattern.MatchString(a.ServiceAccount) {
		return fail()
	}
	b := a.Binding
	if b.Primitive != "database" || (b.Access != "reader" && b.Access != "writer" && b.Access != "maintenance") || !bounded(b.ID) || !bounded(b.Database) || !bounded(b.User) || b.Connection.Kind != "local-identity-proxy" || !validPath(b.Connection.SocketDirectory) || b.Connection.Port < 1 || b.Connection.Port > 65535 {
		return fail()
	}
	p := a.PodSecurityContext
	if !p.RunAsNonRoot || p.RunAsUser < 1 || p.RunAsGroup < 1 || p.FSGroup < 1 || p.SeccompProfile.Type != "RuntimeDefault" {
		return fail()
	}
	if len(a.InitContainers) == 0 || len(a.InitContainers) > 16 || len(a.Volumes) == 0 || len(a.Volumes) > 16 || len(a.VolumeMounts) == 0 || len(a.VolumeMounts) > 16 {
		return fail()
	}
	volumes := map[string]bool{}
	for _, v := range a.Volumes {
		if !namePattern.MatchString(v.Name) || volumes[v.Name] || v.EmptyDir.Medium != "Memory" || !bounded(v.EmptyDir.SizeLimit) {
			return fail()
		}
		volumes[v.Name] = true
	}
	checkMounts := func(mounts []Mount, consumer bool) bool {
		seen := map[string]bool{}
		for _, m := range mounts {
			if !volumes[m.Name] || seen[m.Name] || !validPath(m.MountPath) || (consumer && (m.ReadOnly == nil || !*m.ReadOnly)) {
				return false
			}
			seen[m.Name] = true
		}
		return len(mounts) > 0 && len(mounts) <= 16
	}
	if !checkMounts(a.VolumeMounts, true) {
		return fail()
	}
	socketMounted := false
	for _, m := range a.VolumeMounts {
		if strings.HasPrefix(b.Connection.SocketDirectory, m.MountPath+"/") || b.Connection.SocketDirectory == m.MountPath {
			socketMounted = true
		}
	}
	if !socketMounted {
		return fail()
	}
	containers := map[string]bool{}
	for _, c := range a.InitContainers {
		if !namePattern.MatchString(c.Name) || containers[c.Name] || !imagePattern.MatchString(c.Image) || c.RestartPolicy != "Always" || len(c.Args) == 0 || len(c.Args) > 16 || !checkMounts(c.VolumeMounts, false) {
			return fail()
		}
		containers[c.Name] = true
		s := c.SecurityContext
		if s.AllowPrivilegeEscalation == nil || *s.AllowPrivilegeEscalation || !s.ReadOnlyRootFilesystem || len(s.Capabilities.Drop) != 1 || s.Capabilities.Drop[0] != "ALL" {
			return fail()
		}
		for _, argument := range c.Args {
			if !bounded(argument) {
				return fail()
			}
		}
		for _, value := range []string{c.Resources.Requests.CPU, c.Resources.Requests.Memory, c.Resources.Limits.CPU, c.Resources.Limits.Memory} {
			if !bounded(value) {
				return fail()
			}
		}
	}
	digest, err := a.computedDigest()
	if err != nil || digest != a.Digest {
		return fail()
	}
	return nil
}
