//go:build !linux

package secrets

// keychainReachable: Windows Credential Manager and the macOS Keychain need
// no session check; calls still have a time limit.
func keychainReachable() error { return nil }
