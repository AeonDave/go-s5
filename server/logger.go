package server

import "log"

type Logger interface {
	Infof(format string, args ...interface{})
	Errorf(format string, args ...interface{})
}

type Std struct {
	*log.Logger
}

func NewLogger(l *log.Logger) *Std {
	return &Std{Logger: l}
}

func (sf Std) Infof(format string, args ...interface{}) {
	sf.Printf("[I]: "+format, args...)
}

func (sf Std) Errorf(format string, args ...interface{}) {
	sf.Printf("[E]: "+format, args...)
}
