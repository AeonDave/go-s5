package auth

type StaticCredentials map[string]string

func (s StaticCredentials) Valid(user, password, _ string) bool {
	if pass, ok := s[user]; ok {
		return password == pass
	}
	return false
}
