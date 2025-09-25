package auth

type AContext struct {
	Method  uint8
	Payload map[string]string
}
