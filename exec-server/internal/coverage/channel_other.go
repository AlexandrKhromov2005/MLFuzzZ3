//go:build !linux

package coverage

import "errors"

// memfdCreate is a stub on non-Linux platforms. Coverage
// requires linux memfd semantics; build tags restrict
// production builds, but stub keeps cross-platform
// type-checking green.
func memfdCreate(name string) (int, error) {
	_ = name
	return -1, errors.New(
		"coverage channel requires linux (memfd_create)")
}
