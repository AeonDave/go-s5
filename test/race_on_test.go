//go:build race

package socks5_test

// raceEnabled reports whether the race detector is active. Under -race,
// sync.Pool intentionally drops a fraction of Put calls, so tests that
// assert strict pool reuse must relax their expectations.
const raceEnabled = true
