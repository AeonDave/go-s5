package auth

type AuthContext struct {
	Method  uint8
	Payload map[string]string
}
