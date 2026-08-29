//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package server

import (
	"path/filepath"
	"syscall"
)

func diskSpace(path string) (total, free uint64) {
	var value syscall.Statfs_t
	if err := syscall.Statfs(filepath.Dir(path), &value); err != nil {
		return 0, 0
	}
	return uint64(value.Blocks) * uint64(value.Bsize), uint64(value.Bavail) * uint64(value.Bsize)
}
