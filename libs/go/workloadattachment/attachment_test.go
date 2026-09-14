package workloadattachment

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

func fixture(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile("../../../contracts/workload-attachment/example.json")
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
}
