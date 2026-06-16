package main

import (
	"context"
	"testing"

	"github.com/codefly-dev/core/wool"
)

// capturingProcessor records every Log emitted through Wool so tests can
// assert on the level, message, and fields the pgLogWriter produced.
type capturingProcessor struct {
	logs []*wool.Log
}

func (c *capturingProcessor) Process(l *wool.Log) { c.logs = append(c.logs, l) }

// newCaptureWool returns a Wool wired to a capturing processor at TRACE level
// (so even de-emphasized DEBUG lines are recorded).
func newCaptureWool() (*wool.Wool, *capturingProcessor) {
	cap := &capturingProcessor{}
	w := wool.Get(context.Background()).WithLogger(cap)
	w.WithLoglevel(wool.TRACE)
	return w, cap
}

func fieldValue(l *wool.Log, key string) (any, bool) {
	for _, f := range l.Fields {
		if f.Key == key {
			return f.Value, true
		}
	}
	return nil, false
}

func TestPGLogWriter_ParsesSeverityAndStripsPrefix(t *testing.T) {
	cases := []struct {
		name      string
		line      string
		wantLevel wool.Loglevel
		wantMsg   string
		wantPID   string
	}{
		{
			name:      "startup LOG maps to INFO",
			line:      `2026-06-16 14:56:37.339 UTC [35801] LOG:  database system is ready to accept connections`,
			wantLevel: wool.INFO,
			wantMsg:   "database system is ready to accept connections",
			wantPID:   "35801",
		},
		{
			name:      "WARNING maps to WARN",
			line:      `2026-06-16 14:56:37.339 UTC [35801] WARNING:  here be dragons`,
			wantLevel: wool.WARN,
			wantMsg:   "here be dragons",
			wantPID:   "35801",
		},
		{
			name:      "ERROR maps to ERROR",
			line:      `2026-06-16 14:56:37.339 UTC [35801] ERROR:  relation "missing" does not exist`,
			wantLevel: wool.ERROR,
			wantMsg:   `relation "missing" does not exist`,
			wantPID:   "35801",
		},
		{
			name:      "FATAL maps to FATAL",
			line:      `2026-06-16 14:56:37.339 UTC [35804] FATAL:  the database system is starting up`,
			wantLevel: wool.FATAL,
			wantMsg:   "the database system is starting up",
			wantPID:   "35804",
		},
		{
			name:      "PANIC maps to FATAL",
			line:      `2026-06-16 14:56:37.339 UTC [35804] PANIC:  could not write to file`,
			wantLevel: wool.FATAL,
			wantMsg:   "could not write to file",
			wantPID:   "35804",
		},
		{
			name:      "DEBUG1 maps to DEBUG",
			line:      `2026-06-16 14:56:37.339 UTC [35804] DEBUG1:  forked new backend`,
			wantLevel: wool.DEBUG,
			wantMsg:   "forked new backend",
			wantPID:   "35804",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w, cap := newCaptureWool()
			pw := newPGLogWriter(w)
			if _, err := pw.Write([]byte(tc.line + "\n")); err != nil {
				t.Fatalf("write: %v", err)
			}
			if len(cap.logs) != 1 {
				t.Fatalf("expected 1 log, got %d", len(cap.logs))
			}
			got := cap.logs[0]
			if got.Level != tc.wantLevel {
				t.Errorf("level: got %v want %v", got.Level, tc.wantLevel)
			}
			if got.Message != tc.wantMsg {
				t.Errorf("message: got %q want %q", got.Message, tc.wantMsg)
			}
			pid, ok := fieldValue(got, "pid")
			if !ok || pid != tc.wantPID {
				t.Errorf("pid field: got %v (present=%v) want %q", pid, ok, tc.wantPID)
			}
		})
	}
}

func TestPGLogWriter_CheckpointDeEmphasized(t *testing.T) {
	w, cap := newCaptureWool()
	pw := newPGLogWriter(w)
	line := `2026-06-16 15:01:37.350 UTC [35802] LOG:  checkpoint complete: wrote 2 buffers (0.0%); 0 WAL file(s) added`
	if _, err := pw.Write([]byte(line + "\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if len(cap.logs) != 1 {
		t.Fatalf("expected 1 log, got %d", len(cap.logs))
	}
	// A LOG line that would normally be INFO is dropped to DEBUG because it is
	// routine checkpoint noise.
	if cap.logs[0].Level != wool.DEBUG {
		t.Errorf("checkpoint level: got %v want DEBUG", cap.logs[0].Level)
	}
}

func TestPGLogWriter_UnparsedLinePassesThrough(t *testing.T) {
	w, cap := newCaptureWool()
	pw := newPGLogWriter(w)
	if _, err := pw.Write([]byte("initializing database system\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if len(cap.logs) != 1 {
		t.Fatalf("expected 1 log, got %d", len(cap.logs))
	}
	got := cap.logs[0]
	if got.Level != wool.INFO {
		t.Errorf("level: got %v want INFO", got.Level)
	}
	if got.Message != "initializing database system" {
		t.Errorf("message: got %q", got.Message)
	}
}

func TestPGLogWriter_BuffersPartialLines(t *testing.T) {
	w, cap := newCaptureWool()
	pw := newPGLogWriter(w)
	// A single log line split across two writes (as Docker's raw stdcopy may
	// deliver it) must surface as exactly one parsed entry.
	if _, err := pw.Write([]byte(`2026-06-16 14:56:37.339 UTC [35801] LOG:  listening`)); err != nil {
		t.Fatalf("write 1: %v", err)
	}
	if len(cap.logs) != 0 {
		t.Fatalf("expected no log before newline, got %d", len(cap.logs))
	}
	if _, err := pw.Write([]byte(" on port 5432\n")); err != nil {
		t.Fatalf("write 2: %v", err)
	}
	if len(cap.logs) != 1 {
		t.Fatalf("expected 1 log, got %d", len(cap.logs))
	}
	if cap.logs[0].Message != "listening on port 5432" {
		t.Errorf("message: got %q", cap.logs[0].Message)
	}
}

func TestPGLogWriter_SkipsBlankLines(t *testing.T) {
	w, cap := newCaptureWool()
	pw := newPGLogWriter(w)
	if _, err := pw.Write([]byte("\n   \n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if len(cap.logs) != 0 {
		t.Errorf("expected blank lines skipped, got %d logs", len(cap.logs))
	}
}
