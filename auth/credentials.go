package auth

import "crypto/subtle"

// StaticCredentials implements CredentialStore as an in-memory
// username -> password map. Suitable for tests and small fixed deployments;
// production systems should implement CredentialStore against their own
// user store.
type StaticCredentials map[string]string

// Valid reports whether the user/password pair matches the stored entry.
// The password comparison runs in constant time to avoid leaking the match
// length or content through timing. The user address is ignored.
func (s StaticCredentials) Valid(user, password, _ string) bool {
	pass, ok := s[user]
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(password), []byte(pass)) == 1
}
