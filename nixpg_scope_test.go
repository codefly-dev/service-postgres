package main

import "testing"

func TestRunServerKeyIsStablePerRun(t *testing.T) {
	const workspace = "/workspace/robin/playground"
	if runServerKey(workspace, "qa") != runServerKey(workspace, "qa") {
		t.Fatal("one run produced two server keys")
	}
}

// TestRunServerKeySeparatesRuns pins the isolation boundary: a naming scope or
// another workspace is another run, with its own server, data and credentials.
func TestRunServerKeySeparatesRuns(t *testing.T) {
	const workspace = "/workspace/robin/playground"
	keys := map[string]string{
		"unscoped":         runServerKey(workspace, ""),
		"scope a":          runServerKey(workspace, "qualification-a"),
		"scope b":          runServerKey(workspace, "qualification-b"),
		"other workspace":  runServerKey("/workspace/other", "qualification-a"),
		"ambiguous concat": runServerKey(workspace+"\x00naming-scope\x00qualification", "-a"),
	}
	seen := map[string]string{}
	for name, key := range keys {
		hash := serviceHash(key)[:16]
		if other, ok := seen[hash]; ok {
			t.Fatalf("%s and %s share a run server", name, other)
		}
		seen[hash] = name
	}
}
