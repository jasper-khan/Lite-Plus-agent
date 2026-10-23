//go:build windows

package coreadapter

import "golang.org/x/sys/windows"

func setIPv6Only(fd uintptr) error {
	return windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, windows.IPV6_V6ONLY, 1)
}
