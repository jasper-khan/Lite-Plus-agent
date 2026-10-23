package runtime

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nuomiiiii/lite-agent/nodemgt/coreadapter"
	"golang.org/x/net/proxy"
)

func TestFlushUsageRecoversAfterPendingWriteFailure(t *testing.T) {
	dir := t.TempDir()
	echo := startEcho(t)
	defer echo.Close()
	port := freePort(t)
	rt, err := Start(filepath.Join(dir, "agent.json"), func(string, any) {})
	if err != nil {
		t.Fatal(err)
	}
	rt.HandleControl(map[string]any{
		"operation_id": "start",
		"kind":         "applyConfig",
		"payload": map[string]any{
			"inbounds": []any{map[string]any{"id": "socks", "core": "sing-box", "protocol": "socks", "listen": "127.0.0.1", "port": port, "enabled": true}},
			"users": []any{map[string]any{
				"id": "persist-user", "status": "active", "inbound_ids": []string{"socks"},
				"credentials": []any{map[string]any{"uuid": "alice", "secret": "pw", "enabled": true}},
			}},
		},
	}, "")
	waitPort(t, port)
	d, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", port), &proxy.Auth{User: "alice", Password: "pw"}, &net.Dialer{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	c, err := d.Dial("tcp", echo.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var sent []int64
	rt.SetSender(func(method string, params any) error {
		if method == "nodemgt.usage" {
			sent = append(sent, params.(map[string]any)["bytes"].(int64))
		}
		return nil
	})
	pending := filepath.Join(dir, "nodemgt", "pending-usage.json")
	if err := os.Mkdir(pending, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := echoN(c, 10); err != nil {
		t.Fatal(err)
	}
	rt.FlushUsage()
	if err := os.Remove(pending); err != nil {
		t.Fatal(err)
	}
	rt.FlushUsage()
	if err := echoN(c, 10); err != nil {
		t.Fatal(err)
	}
	rt.FlushUsage()
	var total int64
	for _, n := range sent {
		total += n
	}
	if total != 40 {
		t.Fatalf("sent %+v total %d want 40", sent, total)
	}
}

func TestMergeUsageItemsSumsSameUser(t *testing.T) {
	got := mergeUsageItems([]coreadapter.Snapshot{
		{UserID: "u1", Bytes: 20},
		{UserID: "u2", Bytes: 5},
		{UserID: "u1", Bytes: 40},
	})
	if len(got) != 2 || got[0].UserID != "u1" || got[0].Bytes != 60 || got[1].Bytes != 5 {
		t.Fatalf("%+v", got)
	}
}

func TestFlushUsageMergesDualCoreAndKeepsGap(t *testing.T) {
	dir := t.TempDir()
	echo := startEcho(t)
	defer echo.Close()
	ports := make([]int, 2)
	var inbounds []any
	for i, name := range []string{"xray", "sing-box"} {
		ports[i] = freePort(t)
		inbounds = append(inbounds, map[string]any{
			"id": name, "core": name, "protocol": "socks", "listen": "127.0.0.1", "port": ports[i], "enabled": true,
		})
	}
	rt, err := Start(filepath.Join(dir, "agent.json"), func(string, any) {})
	if err != nil {
		t.Fatal(err)
	}
	rt.HandleControl(map[string]any{
		"operation_id": "dual-start",
		"kind":         "applyConfig",
		"payload": map[string]any{
			"inbounds": inbounds,
			"users": []any{map[string]any{
				"id": "u1", "status": "active", "inbound_ids": []string{"xray", "sing-box"},
				"credentials": []any{map[string]any{"uuid": "alice", "secret": "pw", "enabled": true}},
			}},
		},
	}, "")
	conns := make([]net.Conn, 2)
	for i, port := range ports {
		waitPort(t, port)
		d, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", port), &proxy.Auth{User: "alice", Password: "pw"}, &net.Dialer{Timeout: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		c, err := d.Dial("tcp", echo.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		conns[i] = c
		defer c.Close()
		if err := echoN(c, 10*(i+1)); err != nil {
			t.Fatal(err)
		}
	}
	var batches []int64
	inject := true
	rt.SetSender(func(method string, params any) error {
		if method != "nodemgt.usage" {
			return nil
		}
		v := params.(map[string]any)
		batches = append(batches, v["bytes"].(int64))
		if inject {
			inject = false
			_ = echoN(conns[0], 20)
		}
		return nil
	})
	rt.FlushUsage()
	if len(batches) != 1 || batches[0] != 60 {
		t.Fatalf("merged batch %+v want [60]", batches)
	}
	if err := echoN(conns[0], 30); err != nil {
		t.Fatal(err)
	}
	rt.FlushUsage()
	if len(batches) != 2 || batches[1] != 100 {
		t.Fatalf("gap batch %+v want [60 100]", batches)
	}
	rt.FlushUsage()
	if len(batches) != 2 {
		t.Fatalf("idle extra %+v", batches)
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
			go func(c net.Conn) { defer c.Close(); _, _ = io.Copy(c, c) }(c)
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

func waitPort(t *testing.T, port int) {
	t.Helper()
	addr := fmt.Sprintf("127.0.0.1:%d", port)
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

func echoN(c net.Conn, n int) error {
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write(make([]byte, n)); err != nil {
		return err
	}
	_, err := io.ReadFull(c, make([]byte, n))
	return err
}
