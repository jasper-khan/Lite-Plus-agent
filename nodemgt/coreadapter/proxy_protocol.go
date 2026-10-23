package coreadapter

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

func publicPresenceIP(raw string) string {
	host := strings.TrimSpace(raw)
	if host == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	ip := net.ParseIP(host)
	if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

func mergePresenceIP(list []PresenceIP, ip PresenceIP) []PresenceIP {
	if ip.IP == "" {
		return list
	}
	for i, prev := range list {
		if prev.IP != ip.IP {
			continue
		}
		if ip.SeenAt.After(prev.SeenAt) {
			list[i] = ip
		}
		return list
	}
	return append(list, ip)
}

func writeProxyProtocolV1(w io.Writer, client, backend net.Conn) error {
	srcIP, srcPort, ok := ipPortFromAddr(client.RemoteAddr())
	if !ok {
		_, err := io.WriteString(w, "PROXY UNKNOWN\r\n")
		return err
	}
	dstIP, dstPort, ok := ipPortFromAddr(backend.LocalAddr())
	if !ok {
		dstIP, dstPort, ok = ipPortFromAddr(backend.RemoteAddr())
	}
	if !ok {
		_, err := io.WriteString(w, "PROXY UNKNOWN\r\n")
		return err
	}
	if src4 := srcIP.To4(); src4 != nil {
		dst4 := dstIP.To4()
		if dst4 == nil {
			_, err := io.WriteString(w, "PROXY UNKNOWN\r\n")
			return err
		}
		_, err := fmt.Fprintf(w, "PROXY TCP4 %s %s %d %d\r\n", src4.String(), dst4.String(), srcPort, dstPort)
		return err
	}
	if dst4 := dstIP.To4(); dst4 != nil {
		dstIP = dst4.To16()
	}
	_, err := fmt.Fprintf(w, "PROXY TCP6 %s %s %d %d\r\n", srcIP.String(), dstIP.String(), srcPort, dstPort)
	return err
}

func ipPortFromAddr(addr net.Addr) (net.IP, int, bool) {
	if addr == nil {
		return nil, 0, false
	}
	host, portStr, err := net.SplitHostPort(addr.String())
	if err != nil {
		return nil, 0, false
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil {
		return nil, 0, false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		return nil, 0, false
	}
	return ip, port, true
}

func presenceIPAt(ip string, unix int64, fallback time.Time) PresenceIP {
	at := fallback
	if unix > 0 {
		at = time.Unix(unix, 0).UTC()
	}
	return PresenceIP{IP: ip, SeenAt: at}
}
