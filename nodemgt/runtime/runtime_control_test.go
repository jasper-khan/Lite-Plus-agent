package runtime

import (
	"fmt"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/net/proxy"
)

func TestHandleControlIgnoresDuplicateAndStaleQuotaAfterRevoke(t *testing.T) {
	dir := t.TempDir()
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { defer c.Close(); _, _ = io.Copy(c, c) }(c)
		}
	}()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	rt, err := Start(filepath.Join(dir, "agent.json"), func(string, any) {})
	if err != nil {
		t.Fatal(err)
	}
	target := echo.Addr().String()
	apply := func(op, kind, user string) {
		rt.HandleControl(map[string]any{
			"operation_id": op,
			"kind":         kind,
			"payload": map[string]any{
				"inbounds": []any{map[string]any{"id": "audit", "core": "xray", "listen": "127.0.0.1", "port": port, "protocol": "socks", "enabled": true}},
				"users": []any{map[string]any{
					"id": "u1", "status": "active", "inbound_ids": []string{"audit"},
					"credentials": []any{map[string]any{"uuid": user, "secret": "pw", "enabled": true}},
				}},
			},
		}, "")
	}
	can := func(user string) bool {
		d, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", port), &proxy.Auth{User: user, Password: "pw"}, &net.Dialer{Timeout: 2 * time.Second})
		if err != nil {
			return false
		}
		c, err := d.Dial("tcp", target)
		if err != nil {
			return false
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := c.Write([]byte("ok")); err != nil {
			return false
		}
		buf := make([]byte, 2)
		_, err = io.ReadFull(c, buf)
		return err == nil
	}
	apply("apply-a", "applyConfig", "alice")
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && !can("alice") {
		time.Sleep(50 * time.Millisecond)
	}
	if !can("alice") {
		t.Fatal("initial apply failed")
	}
	rt.HandleControl(map[string]any{"operation_id": "revoke", "kind": "revokeUser", "payload": map[string]any{"user_ids": []string{"u1"}}}, "")
	if can("alice") {
		t.Fatal("revoke did not take effect")
	}
	apply("apply-a", "applyConfig", "alice")
	if can("alice") {
		t.Fatal("duplicate apply restored revoked user")
	}
	apply("apply-new", "applyConfig", "bob")
	if can("alice") {
		t.Fatal("alice connected after new credential")
	}
	apply("old-quota", "syncQuota", "alice")
	if can("alice") {
		t.Fatal("old syncQuota restored revoked user")
	}
}
