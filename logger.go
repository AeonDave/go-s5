package s5

import "log"

type Logger interface {
	Errorf(format string, args ...interface{})
}

type Std struct {
	*log.Logger
}

func NewLogger(l *log.Logger) *Std {
	return &Std{Logger: l}
}

func (sf Std) Errorf(format string, args ...interface{}) {
	sf.Printf("[E]: "+format, args...)
}
