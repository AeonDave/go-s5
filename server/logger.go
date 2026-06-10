package server

import (
	"context"
	"fmt"
	"log"
	"log/slog"
)

// Logger is the minimal logging interface consumed by the server. Wrap a
// standard library *log.Logger with NewLogger or a *slog.Logger with
// NewSlogLogger, or provide your own implementation via WithLogger.
type Logger interface {
	// Infof logs an informational message in fmt.Printf style.
	Infof(format string, args ...any)
	// Errorf logs an error message in fmt.Printf style.
	Errorf(format string, args ...any)
}

// Std adapts a standard library *log.Logger to the Logger interface,
// prefixing messages with their level.
type Std struct {
	*log.Logger
}

// NewLogger wraps a *log.Logger into a server Logger.
func NewLogger(l *log.Logger) *Std {
	return &Std{Logger: l}
}

// Infof implements Logger.
func (sf Std) Infof(format string, args ...any) {
	sf.Printf("[I]: "+format, args...)
}

// Errorf implements Logger.
func (sf Std) Errorf(format string, args ...any) {
	sf.Printf("[E]: "+format, args...)
}

// SlogLogger adapts a structured *slog.Logger to the Logger interface.
// Messages are emitted at Info and Error levels on the wrapped logger.
type SlogLogger struct {
	l *slog.Logger
}

// NewSlogLogger wraps a *slog.Logger into a server Logger. Passing nil uses
// slog.Default().
func NewSlogLogger(l *slog.Logger) *SlogLogger {
	if l == nil {
		l = slog.Default()
	}
	return &SlogLogger{l: l}
}

// Infof implements Logger.
func (sf *SlogLogger) Infof(format string, args ...any) {
	if sf.l.Enabled(context.Background(), slog.LevelInfo) {
		sf.l.Info(fmt.Sprintf(format, args...))
	}
}

// Errorf implements Logger.
func (sf *SlogLogger) Errorf(format string, args ...any) {
	if sf.l.Enabled(context.Background(), slog.LevelError) {
		sf.l.Error(fmt.Sprintf(format, args...))
	}
}
