//go:build unix

package coreadapter

import "golang.org/x/sys/unix"

func setIPv6Only(fd uintptr) error {
	return unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, 1)
}
