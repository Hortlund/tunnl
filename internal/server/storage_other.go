//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris

package server

func diskSpace(string) (total, free uint64) { return 0, 0 }
