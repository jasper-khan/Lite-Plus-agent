package coreadapter

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"testing"
	"time"
)

func TestSingBoxAnyTLSTLSEcho(t *testing.T) {
	echo := startEcho(t)
	defer echo.Close()
	certPEM, keyPEM := testPEMs(t)
	serverPort := freePort(t)
	socksPort := freePort(t)
	server := NewSingBox()
	client := newSingBoxCore()
	defer server.Stop()
	defer client.Stop()

	if err := server.ApplyUsers([]UserSpec{{ID: "u1", UUID: "alice", Password: "any-secret", QuotaBytes: 1 << 20}}); err != nil {
		t.Fatal(err)
	}
	if err := server.Start(context.Background(), []InboundSpec{{
		ID: "anytls", Core: "sing-box", Listen: "127.0.0.1", Port: serverPort, Protocol: "anytls",
		CertPEM: certPEM, KeyPEM: keyPEM,
		StreamJSON: `{"network":"tcp","security":"tls"}`,
	}}); err != nil {
		t.Fatal(err)
	}
	settings, err := json.Marshal(map[string]any{
		"address": "127.0.0.1", "port": serverPort, "password": "any-secret",
		"security": "tls", "sni": "localhost", "insecure": true, "fingerprint": "chrome",
	})
	if err != nil {
		t.Fatal(err)
	}
	client.SetForwarding(
		[]OutboundSpec{{ID: "exit", Name: "exit", Protocol: "anytls", Enabled: true, SettingsJSON: string(settings)}},
		[]RouteSpec{{ID: "r1", Enabled: true, Priority: 1, RuleJSON: `{"inbound_id":"socks","outbound_id":"exit"}`}},
	)
	if err := client.ApplyUsers([]UserSpec{{ID: "c1", UUID: "cli", Password: "clipw"}}); err != nil {
		t.Fatal(err)
	}
	if err := client.Start(context.Background(), []InboundSpec{{
		ID: "socks", Core: "sing-box", Listen: "127.0.0.1", Port: socksPort, Protocol: "socks",
	}}); err != nil {
		t.Fatal(err)
	}
	serverAddr := fmt.Sprintf("127.0.0.1:%d", serverPort)
	socksAddr := fmt.Sprintf("127.0.0.1:%d", socksPort)
	waitProxy(t, serverAddr)
	waitProxy(t, socksAddr)
	conn, err := socksTry(socksAddr, "cli", "clipw", echo.Addr().String())
	if err != nil {
		t.Fatalf("anytls tls dial: %v", err)
	}
	defer conn.Close()
	payload := []byte("anytls-tls")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("echo %q", got)
	}
}

func TestSingBoxAnyTLSRealityEcho(t *testing.T) {
	echo := startEcho(t)
	defer echo.Close()
	certPEM, keyPEM, _ := auditCerts(t)
	decoy := startTLS13Decoy(t, certPEM, keyPEM)
	defer decoy.Close()
	priv, pub := realityKeys(t)
	stream, err := json.Marshal(map[string]any{
		"network": "tcp", "security": "reality",
		"realitySettings": map[string]any{
			"dest": decoy.Addr().String(), "target": decoy.Addr().String(),
			"serverNames": []string{"audit.test"}, "privateKey": priv, "shortIds": []string{"abcd"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	serverPort := freePort(t)
	socksPort := freePort(t)
	server := NewSingBox()
	client := newSingBoxCore()
	defer server.Stop()
	defer client.Stop()

	if err := server.ApplyUsers([]UserSpec{{ID: "u1", UUID: "alice", Password: "any-secret", QuotaBytes: 1 << 20}}); err != nil {
		t.Fatal(err)
	}
	if err := server.Start(context.Background(), []InboundSpec{{
		ID: "anytls", Core: "sing-box", Listen: "127.0.0.1", Port: serverPort, Protocol: "anytls",
		StreamJSON: string(stream),
	}}); err != nil {
		t.Fatal(err)
	}
	settings, err := json.Marshal(map[string]any{
		"address": "127.0.0.1", "port": serverPort, "password": "any-secret",
		"security": "reality", "sni": "audit.test", "fingerprint": "chrome",
		"reality_public_key": pub, "reality_short_id": "abcd",
	})
	if err != nil {
		t.Fatal(err)
	}
	client.SetForwarding(
		[]OutboundSpec{{ID: "exit", Name: "exit", Protocol: "anytls", Enabled: true, SettingsJSON: string(settings)}},
		[]RouteSpec{{ID: "r1", Enabled: true, Priority: 1, RuleJSON: `{"inbound_id":"socks","outbound_id":"exit"}`}},
	)
	if err := client.ApplyUsers([]UserSpec{{ID: "c1", UUID: "cli", Password: "clipw"}}); err != nil {
		t.Fatal(err)
	}
	if err := client.Start(context.Background(), []InboundSpec{{
		ID: "socks", Core: "sing-box", Listen: "127.0.0.1", Port: socksPort, Protocol: "socks",
	}}); err != nil {
		t.Fatal(err)
	}
	waitProxy(t, fmt.Sprintf("127.0.0.1:%d", serverPort))
	waitProxy(t, fmt.Sprintf("127.0.0.1:%d", socksPort))
	conn, err := socksTry(fmt.Sprintf("127.0.0.1:%d", socksPort), "cli", "clipw", echo.Addr().String())
	if err != nil {
		t.Fatalf("anytls reality dial: %v", err)
	}
	defer conn.Close()
	payload := []byte("anytls-reality")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("echo %q", got)
	}
}
