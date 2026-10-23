//go:build !unix && !windows

package coreadapter

func setIPv6Only(fd uintptr) error {
	return nil
}
