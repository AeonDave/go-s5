package auth

// StaticCredentials implements CredentialStore as an in-memory
// username -> password map. Suitable for tests and small fixed deployments;
// production systems should implement CredentialStore against their own
// user store.
type StaticCredentials map[string]string

// Valid reports whether the user/password pair matches the stored entry.
// The user address is ignored.
func (s StaticCredentials) Valid(user, password, _ string) bool {
	if pass, ok := s[user]; ok {
		return password == pass
	}
	return false
}
