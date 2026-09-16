package workloadattachment

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

func fixture(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/example.json")
	if err != nil {
		t.Fatal(err)
	}
	return data
}
func pooledFixture(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/pooled.json")
	if err != nil {
		t.Fatal(err)
	}
	return data
}
func TestPublicFixtureAndCanonicalSeal(t *testing.T) {
	a, err := Parse(fixture(t))
	if err != nil {
		t.Fatal(err)
	}
	original := a.Digest
	if err = a.Seal(); err != nil {
		t.Fatal(err)
	}
	if a.Digest != original {
		t.Fatal("Python/Go canonical digests diverge")
	}
	before, _ := json.Marshal(a)
	if err = a.Validate(); err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(a)
	if !bytes.Equal(before, after) {
		t.Fatal("validation mutated attachment")
	}
}
func TestPooledFixtureAndCanonicalSeal(t *testing.T) {
	a, err := Parse(pooledFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	original := a.Digest
	if err = a.Seal(); err != nil {
		t.Fatal(err)
	}
	if a.Digest != original {
		t.Fatal("Python/Go canonical digests diverge")
	}
}

func TestPooledConnectionFailsClosed(t *testing.T) {
	cases := []func(*Attachment){
		func(a *Attachment) { a.SchemaVersion = Version },
		func(a *Attachment) { a.Binding.Connection.Kind = "local-identity-proxy" },
		func(a *Attachment) { a.Binding.Connection.PoolMode = "session" },
		func(a *Attachment) { a.Binding.Connection.SessionState = "session-persistent" },
		func(a *Attachment) { a.Binding.Connection.ConnectionLimitScope = "server" },
		func(a *Attachment) { a.Binding.Connection.MaxDBConnections = 0 },
		func(a *Attachment) { a.Binding.Connection.MaxDBConnections = 101 },
		func(a *Attachment) {
			a.Binding.Connection.StartupParameters = append(a.Binding.Connection.StartupParameters, "options")
		},
		func(a *Attachment) { a.InitContainers[1].StartupProbe = nil },
		func(a *Attachment) { a.InitContainers[0].StartupProbe = a.InitContainers[1].StartupProbe },
		func(a *Attachment) { a.InitContainers[1].StartupProbe.Exec.Command = nil },
		func(a *Attachment) { a.InitContainers[1].Args[4] += "\runsafe" },
	}
	for i, change := range cases {
		a, err := Parse(pooledFixture(t))
		if err != nil {
			t.Fatal(err)
		}
		change(a)
		_ = a.Seal()
		if a.Validate() == nil {
			t.Fatalf("case%d accepted", i)
		}
	}
}
func TestUnknownFieldsAndExtraDocument(t *testing.T) {
	data := fixture(t)
	for _, bad := range [][]byte{bytes.Replace(data, []byte(`"namespace":`), []byte(`"unexpected":true,"namespace":`), 1), append(data, []byte(`{}`)...), bytes.Replace(data, []byte(`"emptyDir":`), []byte(`"hostPath":{"path":"/"},"emptyDir":`), 1)} {
		if _, err := Parse(bad); err == nil {
			t.Fatal("unsafe or unknown field accepted")
		}
	}
}
func TestChangedBindingWithoutReviewRejected(t *testing.T) {
	a, err := Parse(fixture(t))
	if err != nil {
		t.Fatal(err)
	}
	a.Binding.User = "other"
	if a.Validate() == nil {
		t.Fatal("changed identity passed old seal")
	}
	a, _ = Parse(fixture(t))
	a.Binding.Connection.SocketDirectory = "/elsewhere/socket"
	_ = a.Seal()
	if a.Validate() == nil {
		t.Fatal("socket outside volume passed")
	}
}
func TestSecurityAndReferencesFailClosed(t *testing.T) {
	cases := []func(*Attachment){func(a *Attachment) { a.SchemaVersion = "future" }, func(a *Attachment) { a.InitContainers[0].Image = "proxy:latest" }, func(a *Attachment) { v := true; a.InitContainers[0].SecurityContext.AllowPrivilegeEscalation = &v }, func(a *Attachment) { a.PodSecurityContext.RunAsUser = 0 }, func(a *Attachment) { a.VolumeMounts[0].Name = "missing" }, func(a *Attachment) { a.VolumeMounts[0].ReadOnly = nil }, func(a *Attachment) { a.Volumes = append(a.Volumes, a.Volumes[0]) }, func(a *Attachment) { a.InitContainers = append(a.InitContainers, a.InitContainers[0]) }}
	for i, change := range cases {
		a, _ := Parse(fixture(t))
		change(a)
		_ = a.Seal()
		if a.Validate() == nil {
			t.Fatalf("case%d accepted", i)
		}
	}
}
func TestAnotherTargetIsOnlyData(t *testing.T) {
	a, _ := Parse(fixture(t))
	a.Namespace = "inference-west"
	a.ServiceAccount = "runtime-west"
	a.Binding.ID = "customer-west/inference/writer-v1"
	a.Binding.Database = "inference_west"
	a.Binding.User = "writer-west@example-west.iam"
	a.Binding.Connection.SocketDirectory = "/cloudsql/example-west:us-west1:customer-db"
	a.InitContainers[0].Args[0] = "--impersonate-service-account=writer-west@example-west.iam.gserviceaccount.com"
	a.InitContainers[0].Args[len(a.InitContainers[0].Args)-1] = "example-west:us-west1:customer-db"
	if err := a.Seal(); err != nil {
		t.Fatal(err)
	}
	if err := a.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestMountPathsMustNotOverlap(t *testing.T) {
	for _, consumer := range []bool{true, false} {
		for _, path := range []string{"/cloudsql", "/cloudsql/nested", "/"} {
			a, _ := Parse(fixture(t))
			volume := a.Volumes[0]
			volume.Name = "second-socket"
			a.Volumes = append(a.Volumes, volume)
			mount := a.VolumeMounts[0]
			mount.Name, mount.MountPath = volume.Name, path
			if consumer {
				a.VolumeMounts = append(a.VolumeMounts, mount)
			} else {
				a.InitContainers[0].VolumeMounts = append(a.InitContainers[0].VolumeMounts, mount)
			}
			_ = a.Seal()
			if a.Validate() == nil {
				t.Fatalf("consumer=%t overlapping path %s accepted", consumer, path)
			}
		}
	}
	a, err := Parse(pooledFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	a.InitContainers[1].VolumeMounts[2].MountPath = "/pooler/nested"
	_ = a.Seal()
	if a.Validate() == nil {
		t.Fatal("pooled repeated volume with overlapping paths accepted")
	}
}

func TestKubernetesNamesMustEndInAlphanumeric(t *testing.T) {
	for _, change := range []func(*Attachment){
		func(a *Attachment) { a.Namespace = "invalid-" },
		func(a *Attachment) { a.ServiceAccount = "invalid-" },
		func(a *Attachment) { a.InitContainers[0].Name = "invalid-" },
		func(a *Attachment) {
			a.Volumes[0].Name = "invalid-"
			a.VolumeMounts[0].Name = "invalid-"
			a.InitContainers[0].VolumeMounts[0].Name = "invalid-"
		},
	} {
		a, _ := Parse(fixture(t))
		change(a)
		_ = a.Seal()
		if a.Validate() == nil {
			t.Fatal("invalid Kubernetes name accepted")
		}
	}
}

func TestUTF8SealMatchesPythonAndKeepsLiteralEscapes(t *testing.T) {
	a, _ := Parse(fixture(t))
	a.Binding.ID = "unicode-\u2028-\u2029-literal-\\u2028-\\u2029"
	if err := a.Seal(); err != nil {
		t.Fatal(err)
	}
	// hashlib.sha256(json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()
	if a.Digest != "sha256:8d9c1c8a27bccfce0d09e06a2eceb90078c6ea546aa2886034780022ccd6e190" {
		t.Fatal("UTF-8 canonical digest diverges from Python")
	}
	if err := a.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestSocketAndMountPathsRejectNullAndUnicodeWhitespace(t *testing.T) {
	for _, path := range []string{"/cloudsql/\x00socket", "/cloudsql/\u2028socket"} {
		a, _ := Parse(fixture(t))
		a.Binding.Connection.SocketDirectory = path
		_ = a.Seal()
		if a.Validate() == nil {
			t.Fatal("unsafe socket path accepted")
		}
	}
}

func TestParseRejectsNormalizationBeforeSeal(t *testing.T) {
	data := fixture(t)
	for name, bad := range map[string][]byte{
		"field case":             bytes.Replace(data, []byte(`"namespace":`), []byte(`"Namespace":`), 1),
		"nested field case":      bytes.Replace(data, []byte(`"socket_directory":`), []byte(`"Socket_Directory":`), 1),
		"duplicate identity":     bytes.Replace(data, []byte(`"namespace":`), []byte(`"namespace":"unreviewed","namespace":`), 1),
		"duplicate nested field": bytes.Replace(data, []byte(`"port":`), []byte(`"port":1,"port":`), 1),
		"escaped duplicate key":  bytes.Replace(data, []byte(`"namespace":`), []byte(`"namespac\u0065":"unreviewed","namespace":`), 1),
		"null optional mount":    bytes.Replace(data, []byte(`"mountPath":`), []byte(`"readOnly":null,"mountPath":`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(bad); err == nil {
				t.Fatal("document outside the public contract accepted under the original seal")
			}
		})
	}
}

func TestParseUnicodeIsLossless(t *testing.T) {
	a, _ := Parse(fixture(t))
	a.Binding.ID = "replacement-\ufffd"
	_ = a.Seal()
	data, _ := json.Marshal(a)
	for _, replacement := range [][]byte{[]byte(`\ud800`), []byte(`\udfff`), {0xff}} {
		bad := bytes.Replace(data, []byte("\ufffd"), replacement, 1)
		if _, err := Parse(bad); err == nil {
			t.Fatal("lossy Unicode normalization accepted under replacement-character seal")
		}
	}
	if _, err := Parse(data); err != nil {
		t.Fatal("literal replacement character is valid UTF-8:", err)
	}
	a.Binding.ID = "pair-\U0001f512-literal-\\ud800"
	_ = a.Seal()
	data, _ = json.Marshal(a)
	data = bytes.Replace(data, []byte("\U0001f512"), []byte(`\ud83d\udd12`), 1)
	if _, err := Parse(data); err != nil {
		t.Fatal("valid surrogate pair or literal escape rejected:", err)
	}
}
