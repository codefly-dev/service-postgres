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
//
// The parsing rules (prefix regex, severity map, routine-noise demotion) are a
// declarative gortk LogSpec rather than hand-written Go — the same engine other
// service agents can reuse for their own log streams. pgLogWriter keeps only
// the streaming shell (buffer, split) and the level→Wool routing.

import (
	"bytes"
	"io"
	"strings"

	"github.com/codefly-dev/core/wool"
	"github.com/mind-build/gortk"
)

// pgLog parses postgres' stock log_line_prefix ("%m [%p] "): an ISO timestamp
// with timezone, the PID, then "SEVERITY:  message". Named captures pid/level/
// msg become Record fields; postgres severities map to canonical levels;
// checkpoint/restartpoint bookkeeping is demoted to debug so it filters out
// unless someone is explicitly looking at debug output.
var pgLog = mustCompileLog(gortk.LogSpec{
	LineRegex: `^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)? \S+ \[(?P<pid>\d+)\] (?P<level>\w+):\s*(?P<msg>.*)$`,
	LevelMap: map[string]string{
		"PANIC": "fatal", "FATAL": "fatal", "ERROR": "error", "WARNING": "warn",
		"LOG": "info", "INFO": "info", "NOTICE": "info",
		"DEBUG1": "debug", "DEBUG2": "debug", "DEBUG3": "debug", "DEBUG4": "debug", "DEBUG5": "debug",
	},
	DefaultLevel:   "info",
	DemotePatterns: []string{`^checkpoint `, `^restartpoint `},
})

func mustCompileLog(s gortk.LogSpec) *gortk.LogParser {
	p, err := s.Compile()
	if err != nil {
		panic("postgres pglog: " + err.Error())
	}
	return p
}

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

// emit parses one postgres log line via the gortk LogParser and forwards it at
// the mapped Wool level, keeping the PID as a compact field. Lines that don't
// match the postgres prefix (e.g. initdb progress) come back at the default
// level so nothing is silently dropped.
func (p *pgLogWriter) emit(line string) {
	if strings.TrimSpace(line) == "" {
		return
	}
	rec := pgLog.Parse(line)
	msg, _ := rec.Fields["msg"].(string)

	var fields []*wool.LogField
	if pid, ok := rec.Fields["pid"].(string); ok && pid != "" {
		fields = append(fields, wool.Field("pid", pid))
	}
	p.logAt(woolLevel(rec.Level), msg, fields...)
}

// woolLevel maps a gortk canonical level onto a Wool log level.
func woolLevel(level string) wool.Loglevel {
	switch level {
	case "fatal":
		return wool.FATAL
	case "error":
		return wool.ERROR
	case "warn":
		return wool.WARN
	case "debug":
		return wool.DEBUG
	default:
		return wool.INFO
	}
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
