package coreadapter

import (
	"context"
	"net"
	"syscall"
)

func listenNetwork(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	host = unwrapListenHost(host)
	ip := net.ParseIP(host)
	if ip == nil {
		return "tcp"
	}
	if ip.To4() != nil {
		return "tcp4"
	}
	return "tcp6"
}

func listenFront(addr string) (net.Listener, error) {
	network := listenNetwork(addr)
	if network != "tcp6" {
		return net.Listen(network, addr)
	}
	lc := net.ListenConfig{
		Control: func(network, address string, conn syscall.RawConn) error {
			var sockErr error
			if err := conn.Control(func(fd uintptr) {
				sockErr = setIPv6Only(fd)
			}); err != nil {
				return err
			}
			return sockErr
		},
	}
	return lc.Listen(context.Background(), network, addr)
}
