package logging

import (
	"io"
	"log"
)

// Level represents the minimum severity a logger will emit.
type Level int

const (
	// LevelOff disables all log output.
	LevelOff Level = iota
	// LevelError emits only errors.
	LevelError
	// LevelInfo emits informational messages and errors.
	LevelInfo
	// LevelDebug emits debug, info, and error messages.
	LevelDebug
)

// Logger defines the logging contract used by the client helpers.
type Logger interface {
	Debugf(format string, args ...interface{})
	Infof(format string, args ...interface{})
	Errorf(format string, args ...interface{})
}

// Config controls the construction of a logger implementation.
type Config struct {
	Base     *log.Logger
	Level    Level
	LevelSet bool
}

// New constructs a logger from the provided configuration. When cfg.Base is
// nil, a logger backed by io.Discard is created. The log level defaults to
// LevelError unless a valid value is provided. Use LevelOff to silence output.
func New(cfg Config) Logger {
	lvl := LevelError
	if cfg.LevelSet {
		lvl = normalizeLevel(cfg.Level)
	} else if cfg.Level > LevelOff {
		lvl = normalizeLevel(cfg.Level)
	}
	base := cfg.Base
	if base == nil {
		base = log.New(io.Discard, "", 0)
	}
	return &stdLogger{base: base, level: lvl}
}

// NewNop returns a logger that never emits output.
func NewNop() Logger {
	return &stdLogger{base: log.New(io.Discard, "", 0), level: LevelOff}
}

type stdLogger struct {
	base  *log.Logger
	level Level
}

func (l *stdLogger) shouldLog(lvl Level) bool {
	if l == nil || l.base == nil {
		return false
	}
	if l.level == LevelOff {
		return false
	}
	return lvl <= l.level
}

func (l *stdLogger) logf(lvl Level, prefix, format string, args ...interface{}) {
	if !l.shouldLog(lvl) {
		return
	}
	if prefix != "" {
		format = prefix + format
	}
	l.base.Printf(format, args...)
}

func (l *stdLogger) Debugf(format string, args ...interface{}) {
	l.logf(LevelDebug, "[debug] ", format, args...)
}

func (l *stdLogger) Infof(format string, args ...interface{}) {
	l.logf(LevelInfo, "[info] ", format, args...)
}

func (l *stdLogger) Errorf(format string, args ...interface{}) {
	l.logf(LevelError, "[error] ", format, args...)
}

func normalizeLevel(lvl Level) Level {
	switch lvl {
	case LevelOff, LevelError, LevelInfo, LevelDebug:
		return lvl
	default:
		return LevelError
	}
}
