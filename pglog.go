package main

// pglog.go — structured rendering of the postgres server log stream.
//
// Both runtimes (Docker and nix) point the postgres process's stderr at our
// Wool logger. Raw, every line carries postgres' own timestamp + PID prefix
// ("2026-06-16 14:56:37.312 UTC [35801] LOG:  ...") and lands at a single
// undifferentiated level, so ERROR/FATAL never stand out and routine chatter
// can't be filtered. pgLogWriter sits between postgres and Wool: it splits the
// stream into lines, parses the stock log_line_prefix, drops the redundant
// timestamp (Wool stamps its own), keeps the PID as a compact field, and emits
// each line at the Wool level its postgres severity maps to.

import (
	"bytes"
	"io"
	"regexp"
	"strings"

	"github.com/codefly-dev/core/wool"
)

// pgLogLine matches a line produced by postgres' stock log_line_prefix ("%m
// [%p] "): an ISO timestamp with timezone, the PID in brackets, then
// "SEVERITY:  message". Capture groups: 1=PID, 2=severity, 3=message.
var pgLogLine = regexp.MustCompile(`^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)? \S+ \[(\d+)\] (\w+):\s*(.*)$`)

// pgLogWriter parses the postgres log stream and re-emits each line through
// Wool at a severity-mapped level. It implements io.Writer so it can be handed
// to the runner in place of the raw logger.
type pgLogWriter struct {
	w   *wool.Wool
	buf []byte
}

func newPGLogWriter(w *wool.Wool) *pgLogWriter {
	return &pgLogWriter{w: w}
}

var _ io.Writer = (*pgLogWriter)(nil)

// Write buffers incoming bytes and flushes complete (newline-terminated) lines.
// The runner may deliver postgres output either line-by-line (native) or in raw
// chunks spanning line boundaries (Docker's stdcopy), so a partial trailing line
// is held until its newline arrives.
func (p *pgLogWriter) Write(b []byte) (int, error) {
	p.buf = append(p.buf, b...)
	for {
		i := bytes.IndexByte(p.buf, '\n')
		if i < 0 {
			break
		}
		line := string(bytes.TrimRight(p.buf[:i], "\r"))
		p.buf = p.buf[i+1:]
		p.emit(line)
	}
	return len(b), nil
}

// emit parses one postgres log line and forwards it at the mapped Wool level.
// Lines that don't match the postgres prefix (e.g. initdb progress) pass
// through at INFO so nothing is silently dropped.
func (p *pgLogWriter) emit(line string) {
	if strings.TrimSpace(line) == "" {
		return
	}
	m := pgLogLine.FindStringSubmatch(line)
	if m == nil {
		p.w.Info(line)
		return
	}
	pid, severity, msg := m[1], m[2], m[3]
	level := pgSeverityToLevel(severity)
	// Checkpoint/restartpoint summaries are high-frequency, low-value LOG
	// chatter — drop them below the default INFO threshold so they're filtered
	// unless someone is explicitly looking at debug output.
	if level == wool.INFO && isPGRoutineNoise(msg) {
		level = wool.DEBUG
	}
	p.logAt(level, msg, wool.Field("pid", pid))
}

func (p *pgLogWriter) logAt(level wool.Loglevel, msg string, fields ...*wool.LogField) {
	switch level {
	case wool.FATAL:
		p.w.Fatal(msg, fields...)
	case wool.ERROR:
		p.w.Error(msg, fields...)
	case wool.WARN:
		p.w.Warn(msg, fields...)
	case wool.DEBUG:
		p.w.Debug(msg, fields...)
	default:
		p.w.Info(msg, fields...)
	}
}

// pgSeverityToLevel maps a postgres message severity onto a Wool log level.
// PANIC/FATAL/ERROR/WARNING map to their direct equivalents; LOG/INFO/NOTICE
// are routine operational output and map to INFO; DEBUG1..DEBUG5 map to DEBUG.
// An unrecognized severity defaults to INFO rather than being hidden.
func pgSeverityToLevel(severity string) wool.Loglevel {
	switch severity {
	case "PANIC", "FATAL":
		return wool.FATAL
	case "ERROR":
		return wool.ERROR
	case "WARNING":
		return wool.WARN
	case "LOG", "INFO", "NOTICE":
		return wool.INFO
	}
	if strings.HasPrefix(severity, "DEBUG") {
		return wool.DEBUG
	}
	return wool.INFO
}

// isPGRoutineNoise reports whether a LOG message is high-frequency background
// bookkeeping (checkpoints, restartpoints) worth de-emphasizing.
func isPGRoutineNoise(msg string) bool {
	return strings.HasPrefix(msg, "checkpoint ") || strings.HasPrefix(msg, "restartpoint ")
}
