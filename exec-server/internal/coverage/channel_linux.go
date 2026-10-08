//go:build linux

package coverage

import (
	"syscall"
	"unsafe"
)

// sysMemfdCreate is the memfd_create(2) syscall number on
// linux/amd64. Duplicated from
// exec-server/internal/ipc/scmrights_linux_test.go per
// project conventions (no x/sys dep) — production-vs-test
// asymmetry forbids importing the test-only helper.
const sysMemfdCreate = 319

// memfdCreate invokes memfd_create(2) directly. name is
// a cosmetic label visible in /proc/<pid>/fd/<n> readlinks
// (e.g., "/memfd:mlfuzzz3-cov (deleted)"). flags=0 = no
// close-on-exec, no sealing — appropriate for inheriting
// the fd to a child via cmd.ExtraFiles.
func memfdCreate(name string) (int, error) {
	nameBytes, err := syscall.BytePtrFromString(name)
	if err != nil {
		return -1, err
	}
	fd, _, errno := syscall.Syscall(
		sysMemfdCreate,
		uintptr(unsafe.Pointer(nameBytes)),
		0, 0)
	if errno != 0 {
		return -1, errno
	}
	return int(fd), nil
}
