package client

import (
	"log"

	"github.com/AeonDave/go-s5/client/internal/logging"
)

// LogLevel mirrors the logging level used by the client helpers.
type LogLevel = logging.Level

const (
	LogLevelOff   = logging.LevelOff
	LogLevelError = logging.LevelError
	LogLevelInfo  = logging.LevelInfo
	LogLevelDebug = logging.LevelDebug
)

// Logger is the logging interface consumed by helper packages.
type Logger = logging.Logger

// LoggerConfig configures the logger implementation.
type LoggerConfig = logging.Config

// NewLogger builds a helper logger from the provided configuration.
func NewLogger(cfg LoggerConfig) Logger {
	if cfg.LevelSet || cfg.Level != 0 {
		cfg.LevelSet = true
	}
	return logging.New(cfg)
}

// NewSilentLogger returns a logger that never emits output.
func NewSilentLogger() Logger { return logging.NewNop() }

// NewStdLogger is a convenience helper to wrap a standard log.Logger with the
// given minimum level.
func NewStdLogger(l *log.Logger, level LogLevel) Logger {
	return logging.New(logging.Config{Base: l, Level: level, LevelSet: true})
}
