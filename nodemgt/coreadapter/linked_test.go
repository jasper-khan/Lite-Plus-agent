package coreadapter

import (
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"golang.org/x/net/proxy"
)

func TestLinkedCoresReportVersions(t *testing.T) {
	xray := NewXray()
	sb := NewSingBox()
	if !xray.Linked() || !sb.Linked() {
		t.Fatalf("linked xray=%v sing-box=%v", xray.Linked(), sb.Linked())
	}
	if xray.Version() != XrayVersion {
		t.Fatalf("xray version %s want %s", xray.Version(), XrayVersion)
	}
	if sb.Version() != SingBoxVersion {
		t.Fatalf("sing-box version %s want %s", sb.Version(), SingBoxVersion)
	}
}

func TestDualCoreSOCKSPersonalControl(t *testing.T) {
	echo := startEcho(t)
	defer echo.Close()

	xrayPort := freePort(t)
	sbPort := freePort(t)
	xray := NewXray()
	sb := NewSingBox()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer xray.Stop()
	defer sb.Stop()

	users := []UserSpec{
		{ID: "u1", UUID: "alice", Password: "pw1", QuotaBytes: 1 << 20},
		{ID: "u2", UUID: "bob", Password: "pw2", QuotaBytes: 1 << 20},
	}
	if err := xray.ApplyUsers(users); err != nil {
		t.Fatal(err)
	}
	if err := sb.ApplyUsers(users); err != nil {
		t.Fatal(err)
	}
	if err := xray.Start(ctx, []InboundSpec{{
		ID: "xray-socks", Core: "xray", Listen: "127.0.0.1", Port: xrayPort, Protocol: "socks",
	}}); err != nil {
		t.Fatal(err)
	}
	if err := sb.Start(ctx, []InboundSpec{{
		ID: "sb-socks", Core: "sing-box", Listen: "127.0.0.1", Port: sbPort, Protocol: "socks",
	}}); err != nil {
		t.Fatal(err)
	}

	echoAddr := echo.Addr().String()
	payload := []byte("lite-plus-dual-core")
	for _, tc := range []struct{ name, addr, user, pass string }{
		{"xray-alice", fmt.Sprintf("127.0.0.1:%d", xrayPort), "alice", "pw1"},
		{"xray-bob", fmt.Sprintf("127.0.0.1:%d", xrayPort), "bob", "pw2"},
		{"singbox-alice", fmt.Sprintf("127.0.0.1:%d", sbPort), "alice", "pw1"},
		{"singbox-bob", fmt.Sprintf("127.0.0.1:%d", sbPort), "bob", "pw2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			waitProxy(t, tc.addr)
			got := socksEcho(t, tc.addr, tc.user, tc.pass, echoAddr, payload)
			if string(got) != string(payload) {
				t.Fatalf("echo %q", got)
			}
		})
	}

	if _, err := socksTry(fmt.Sprintf("127.0.0.1:%d", xrayPort), "alice", "wrong", echoAddr); err == nil {
		t.Fatal("xray accepted wrong password")
	}
	if _, err := socksTry(fmt.Sprintf("127.0.0.1:%d", sbPort), "alice", "wrong", echoAddr); err == nil {
		t.Fatal("sing-box accepted wrong password")
	}

	if err := xray.CloseUserSessions("u1"); err != nil {
		t.Fatal(err)
	}
	if err := sb.CloseUserSessions("u1"); err != nil {
		t.Fatal(err)
	}
	waitProxy(t, fmt.Sprintf("127.0.0.1:%d", xrayPort))
	waitProxy(t, fmt.Sprintf("127.0.0.1:%d", sbPort))
	if _, err := socksTry(fmt.Sprintf("127.0.0.1:%d", xrayPort), "alice", "pw1", echoAddr); err == nil {
		t.Fatal("xray still allowed disabled user")
	}
	if _, err := socksTry(fmt.Sprintf("127.0.0.1:%d", sbPort), "alice", "pw1", echoAddr); err == nil {
		t.Fatal("sing-box still allowed disabled user")
	}
	if got := socksEcho(t, fmt.Sprintf("127.0.0.1:%d", xrayPort), "bob", "pw2", echoAddr, payload); string(got) != string(payload) {
		t.Fatalf("xray bob after alice disable: %q", got)
	}
	if got := socksEcho(t, fmt.Sprintf("127.0.0.1:%d", sbPort), "bob", "pw2", echoAddr, payload); string(got) != string(payload) {
		t.Fatalf("sing-box bob after alice disable: %q", got)
	}

	time.Sleep(200 * time.Millisecond)
	snaps := xray.TakeSnapshots()
	var total int64
	seen := map[string]bool{}
	for _, s := range snaps {
		total += s.Bytes
		seen[s.UserID] = true
	}
	if total == 0 {
		t.Fatal("xray user traffic counters stayed at 0")
	}
	if seen["alice"] {
		t.Fatalf("usage keyed by socks username: %+v", snaps)
	}
}

func TestDualCoreSOCKSQuotaDeviceAndPeerSession(t *testing.T) {
	requireAltLoopback(t)
	echo := startEcho(t)
	defer echo.Close()
	echoAddr := echo.Addr().String()
	payload := make([]byte, 65536)
	for _, core := range []Core{NewXray(), NewSingBox()} {
		t.Run(core.Name(), func(t *testing.T) {
			defer core.Stop()
			port := freePort(t)
			users := []UserSpec{
				{ID: "u1", UUID: "alice", Password: "pw1", QuotaBytes: 32, RateLimitBps: 1, DeviceLimit: 1},
				{ID: "u2", UUID: "bob", Password: "pw2", QuotaBytes: 1 << 20},
			}
			if err := core.ApplyUsers(users); err != nil {
				t.Fatal(err)
			}
			if err := core.Start(context.Background(), []InboundSpec{{
				ID: "socks", Core: core.Name(), Listen: "127.0.0.1", Port: port, Protocol: "socks",
			}}); err != nil {
				t.Fatal(err)
			}
			addr := fmt.Sprintf("127.0.0.1:%d", port)
			waitProxy(t, addr)
			alice, err := socksTry(addr, "alice", "pw1", echoAddr)
			if err != nil {
				t.Fatal(err)
			}
			defer alice.Close()
			same, err := socksTry(addr, "alice", "pw1", echoAddr)
			if err != nil {
				t.Fatal("same ip extra conn")
			}
			same.Close()
			if _, err := socksTryFrom(addr, "alice", "pw1", echoAddr, "127.0.0.2"); err == nil {
				t.Fatal("second ip allowed")
			}
			bob, err := socksTry(addr, "bob", "pw2", echoAddr)
			if err != nil {
				t.Fatal(err)
			}
			defer bob.Close()
			_ = alice.SetDeadline(time.Now().Add(2 * time.Second))
			_, _ = alice.Write(payload)
			got := make([]byte, len(payload))
			if _, err := io.ReadFull(alice, got); err == nil {
				t.Fatal("quota/rate allowed 64KiB")
			}
			if err := core.CloseUserSessions("u1"); err != nil {
				t.Fatal(err)
			}
			_ = bob.SetDeadline(time.Now().Add(2 * time.Second))
			if _, err := bob.Write([]byte("stay")); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 4)
			if _, err := io.ReadFull(bob, buf); err != nil || string(buf) != "stay" {
				t.Fatalf("healthy session dropped: %v %q", err, buf)
			}
			snaps := core.TakeSnapshots()
			for _, s := range snaps {
				if s.UserID == "alice" {
					t.Fatalf("socks username leaked into snapshots: %+v", snaps)
				}
			}
		})
	}
}

func startEcho(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()
	return ln
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

func waitProxy(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("proxy %s not listening", addr)
}

func socksEcho(t *testing.T, proxyAddr, user, pass, dest string, payload []byte) []byte {
	t.Helper()
	conn, err := socksTry(proxyAddr, user, pass, dest)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	return buf
}

func socksTry(proxyAddr, user, pass, dest string) (net.Conn, error) {
	return socksTryFrom(proxyAddr, user, pass, dest, "")
}

func socksTryFrom(proxyAddr, user, pass, dest, localIP string) (net.Conn, error) {
	var forward proxy.Dialer = proxy.Direct
	if localIP != "" {
		forward = &net.Dialer{Timeout: 2 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(localIP)}}
	}
	d, err := proxy.SOCKS5("tcp", proxyAddr, &proxy.Auth{User: user, Password: pass}, forward)
	if err != nil {
		return nil, err
	}
	return d.Dial("tcp", dest)
}

func TestPlainVLESSQuotaDeviceAndPeerSession(t *testing.T) {
	requireAltLoopback(t)
	echo := startEcho(t)
	defer echo.Close()
	host, portStr, err := net.SplitHostPort(echo.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	var destPort int
	fmt.Sscanf(portStr, "%d", &destPort)
	for _, core := range []Core{NewXray(), NewSingBox()} {
		t.Run(core.Name(), func(t *testing.T) {
			defer core.Stop()
			port := freePort(t)
			users := []UserSpec{
				{ID: "u1", UUID: vlessAlice, Password: "pw", QuotaBytes: 32, DeviceLimit: 1},
				{ID: "u2", UUID: vlessBob, Password: "pw", QuotaBytes: 1 << 20},
			}
			if err := core.ApplyUsers(users); err != nil {
				t.Fatal(err)
			}
			if err := core.Start(context.Background(), []InboundSpec{{
				ID: "vless", Core: core.Name(), Listen: "127.0.0.1", Port: port, Protocol: "vless",
			}}); err != nil {
				t.Fatal(err)
			}
			addr := fmt.Sprintf("127.0.0.1:%d", port)
			waitProxy(t, addr)
			alice, err := vlessOpen(addr, vlessAlice, host, destPort)
			if err != nil {
				t.Fatal(err)
			}
			defer alice.Close()
			same, err := vlessOpen(addr, vlessAlice, host, destPort)
			if err != nil {
				t.Fatal("same ip extra conn")
			}
			same.Close()
			if _, err := vlessOpenFrom(addr, vlessAlice, host, destPort, "127.0.0.2"); err == nil {
				t.Fatal("second vless ip allowed")
			}
			bob, err := vlessOpen(addr, vlessBob, host, destPort)
			if err != nil {
				t.Fatal(err)
			}
			defer bob.Close()
			_ = alice.SetDeadline(time.Now().Add(2 * time.Second))
			if echoConn(alice, make([]byte, 65536)) {
				t.Fatal("vless quota allowed 64KiB")
			}
			if err := core.CloseUserSessions("u1"); err != nil {
				t.Fatal(err)
			}
			if echoConn(bob, []byte("stay")) != true {
				t.Fatal("healthy vless session dropped")
			}
			if echoConn(alice, []byte("dead")) {
				t.Fatal("revoked vless session still alive")
			}
		})
	}
}

func TestSOCKSRateCompletesAndIdleSnapshotEmpty(t *testing.T) {
	echo := startEcho(t)
	defer echo.Close()
	echoAddr := echo.Addr().String()
	for _, core := range []Core{NewXray(), NewSingBox()} {
		t.Run(core.Name(), func(t *testing.T) {
			defer core.Stop()
			port := freePort(t)
			if err := core.ApplyUsers([]UserSpec{{ID: "u1", UUID: "alice", Password: "pw", RateLimitBps: 1024}}); err != nil {
				t.Fatal(err)
			}
			if err := core.Start(context.Background(), []InboundSpec{{
				ID: "socks", Core: core.Name(), Listen: "127.0.0.1", Port: port, Protocol: "socks",
			}}); err != nil {
				t.Fatal(err)
			}
			addr := fmt.Sprintf("127.0.0.1:%d", port)
			waitProxy(t, addr)
			conn, err := socksTry(addr, "alice", "pw", echoAddr)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(6 * time.Second))
			payload := make([]byte, 2048)
			if _, err := conn.Write(payload); err != nil {
				t.Fatal(err)
			}
			if _, err := io.ReadFull(conn, make([]byte, 2048)); err != nil {
				t.Fatalf("rate-limited transfer failed: %v", err)
			}
			time.Sleep(20 * time.Millisecond)
			first := core.TakeSnapshots()
			if totalUser(first, "u1") == 0 {
				t.Fatal("missing first snapshot")
			}
			core.AcknowledgeUsage()
			idle := core.TakeSnapshots()
			if totalUser(idle, "u1") != 0 {
				t.Fatalf("idle snapshot %+v", idle)
			}
		})
	}
}

func vlessOpen(addr, id, destHost string, destPort int) (net.Conn, error) {
	return vlessOpenFrom(addr, id, destHost, destPort, "")
}

func vlessOpenFrom(addr, id, destHost string, destPort int, localIP string) (net.Conn, error) {
	d := &net.Dialer{Timeout: 3 * time.Second}
	if localIP != "" {
		d.LocalAddr = &net.TCPAddr{IP: net.ParseIP(localIP)}
	}
	conn, err := d.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	header, err := encodeVLESSHeader(id, destHost, destPort)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if _, err := conn.Write(append(header, 0x42)); err != nil {
		conn.Close()
		return nil, err
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		conn.Close()
		return nil, err
	}
	if resp[1] > 0 {
		if _, err := io.ReadFull(conn, make([]byte, int(resp[1]))); err != nil {
			conn.Close()
			return nil, err
		}
	}
	if _, err := io.ReadFull(conn, make([]byte, 1)); err != nil {
		conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

func echoConn(c net.Conn, payload []byte) bool {
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write(payload); err != nil {
		return false
	}
	_, err := io.ReadFull(c, make([]byte, len(payload)))
	return err == nil
}

func totalUser(snaps []Snapshot, id string) int64 {
	var n int64
	for _, s := range snaps {
		if s.UserID == id {
			n += s.Bytes
		}
	}
	return n
}

func TestUnchangedStartSkipsCoreRestart(t *testing.T) {
	echo := startEcho(t)
	defer echo.Close()
	for _, tc := range []struct {
		name string
		core Core
	}{
		{"xray", NewXray()},
		{"sing-box", NewSingBox()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			core := tc.core
			defer core.Stop()
			port := freePort(t)
			users := []UserSpec{{ID: "u1", UUID: "alice", Password: "pw"}}
			in := []InboundSpec{{ID: "socks", Core: core.Name(), Listen: "127.0.0.1", Port: port, Protocol: "socks"}}
			if err := core.ApplyUsers(users); err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			if err := core.Start(ctx, in); err != nil {
				t.Fatal(err)
			}
			addr := fmt.Sprintf("127.0.0.1:%d", port)
			waitProxy(t, addr)
			conn := socksDial(t, addr, "alice", "pw", echo.Addr().String())
			defer conn.Close()
			if !echoConn(conn, []byte("before")) {
				t.Fatal("echo before reapply")
			}
			if err := core.ApplyUsers(users); err != nil {
				t.Fatal(err)
			}
			if err := core.Start(ctx, in); err != nil {
				t.Fatal(err)
			}
			if !echoConn(conn, []byte("after")) {
				t.Fatal("unchanged apply restarted live inbound")
			}
		})
	}
}

func TestSOCKSPresenceIncludesClientIP(t *testing.T) {
	echo := startEcho(t)
	defer echo.Close()
	core := NewXray()
	defer core.Stop()
	port := freePort(t)
	users := []UserSpec{{ID: "u1", UUID: "alice", Password: "pw"}}
	if err := core.ApplyUsers(users); err != nil {
		t.Fatal(err)
	}
	if err := core.Start(context.Background(), []InboundSpec{{
		ID: "socks", Core: "xray", Listen: "127.0.0.1", Port: port, Protocol: "socks",
	}}); err != nil {
		t.Fatal(err)
	}
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	waitProxy(t, addr)
	conn := socksDial(t, addr, "alice", "pw", echo.Addr().String())
	defer conn.Close()
	if !echoConn(conn, []byte("ip")) {
		t.Fatal("echo")
	}
	found := false
	for _, row := range core.Presence() {
		if row.UserID != "u1" || !row.Online {
			continue
		}
		for _, ip := range row.IPs {
			if ip.IP == "127.0.0.1" {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("presence %+v", core.Presence())
	}
}

func socksDial(t *testing.T, addr, user, pass, dest string) net.Conn {
	t.Helper()
	dialer, err := proxy.SOCKS5("tcp", addr, &proxy.Auth{User: user, Password: pass}, &net.Dialer{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := dialer.Dial("tcp", dest)
	if err != nil {
		t.Fatal(err)
	}
	return conn
}
