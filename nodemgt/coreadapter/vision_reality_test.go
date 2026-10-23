package coreadapter

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/net/proxy"

	xraycore "github.com/xtls/xray-core/core"
)

func TestXrayTLSVisionConnectAndPolicy(t *testing.T) {
	certPEM, keyPEM, pin := auditCerts(t)
	tlsEcho := startTLSEcho(t, certPEM, keyPEM)
	defer tlsEcho.Close()
	t.Run("user-flow", func(t *testing.T) {
		core := NewXray()
		defer core.Stop()
		if err := core.ApplyUsers([]UserSpec{{ID: "u1", UUID: vlessAlice, Password: "pw", Flow: "xtls-rprx-vision"}}); err != nil {
			t.Fatal(err)
		}
		port := freePort(t)
		if err := core.Start(context.Background(), []InboundSpec{{
			ID: "tls", Core: "xray", Listen: "127.0.0.1", Port: port, Protocol: "vless",
			CertPEM: certPEM, KeyPEM: keyPEM,
		}}); err != nil {
			t.Fatal(err)
		}
		waitProxy(t, fmt.Sprintf("127.0.0.1:%d", port))
		cli, conn, err := xrayDial(port, vlessAlice, "xtls-rprx-vision", "tls", "", pin, tlsEcho.Addr().String())
		if err != nil {
			t.Fatalf("user-flow vision connect: %v", err)
		}
		defer cli.Close()
		defer conn.Close()
		if !echoConn(conn, make([]byte, 20)) {
			t.Fatal("user-flow vision echo 20")
		}
	})
	t.Run("echo", func(t *testing.T) {
		core := NewXray()
		defer core.Stop()
		if err := core.ApplyUsers([]UserSpec{{ID: "u1", UUID: vlessAlice, Password: "pw"}}); err != nil {
			t.Fatal(err)
		}
		port := freePort(t)
		if err := core.Start(context.Background(), []InboundSpec{{
			ID: "tls", Core: "xray", Listen: "127.0.0.1", Port: port, Protocol: "vless",
			CertPEM: certPEM, KeyPEM: keyPEM, Flow: "xtls-rprx-vision",
		}}); err != nil {
			t.Fatal(err)
		}
		waitProxy(t, fmt.Sprintf("127.0.0.1:%d", port))
		cli, conn, err := xrayDial(port, vlessAlice, "xtls-rprx-vision", "tls", "", pin, tlsEcho.Addr().String())
		if err != nil {
			t.Fatalf("vision connect: %v", err)
		}
		defer cli.Close()
		defer conn.Close()
		if !echoConn(conn, make([]byte, 20)) {
			t.Fatal("vision echo 20")
		}
	})
	t.Run("policy", func(t *testing.T) {
		core := NewXray()
		defer core.Stop()
		if err := core.ApplyUsers([]UserSpec{
			{ID: "u1", UUID: vlessAlice, Password: "pw", DeviceLimit: 1},
			{ID: "u2", UUID: vlessBob, Password: "pw"},
		}); err != nil {
			t.Fatal(err)
		}
		port := freePort(t)
		if err := core.Start(context.Background(), []InboundSpec{{
			ID: "tls", Core: "xray", Listen: "127.0.0.1", Port: port, Protocol: "vless",
			CertPEM: certPEM, KeyPEM: keyPEM, Flow: "xtls-rprx-vision",
		}}); err != nil {
			t.Fatal(err)
		}
		waitProxy(t, fmt.Sprintf("127.0.0.1:%d", port))
		aliceCli, alice, err := xrayDial(port, vlessAlice, "xtls-rprx-vision", "tls", "", pin, tlsEcho.Addr().String())
		if err != nil {
			t.Fatalf("vision connect: %v", err)
		}
		defer aliceCli.Close()
		defer alice.Close()
		if !echoConn(alice, []byte("alice")) {
			t.Fatal("vision echo via freedom")
		}
		bobCli, bob, err := xrayDial(port, vlessBob, "xtls-rprx-vision", "tls", "", pin, tlsEcho.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer bobCli.Close()
		defer bob.Close()
		if err := core.CloseUserSessions("u1"); err != nil {
			t.Fatal(err)
		}
		if !echoConn(bob, []byte("stay")) {
			t.Fatal("healthy vision session dropped")
		}
	})
}

func TestRealityQuotaDeviceAndPeerSession(t *testing.T) {
	requireAltLoopback(t)
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
	for _, maker := range []func() Core{NewXray, NewSingBox} {
		core := maker()
		t.Run(core.Name(), func(t *testing.T) {
			defer core.Stop()
			if err := core.ApplyUsers([]UserSpec{
				{ID: "u1", UUID: vlessAlice, Password: "pw", QuotaBytes: 32, DeviceLimit: 1},
				{ID: "u2", UUID: vlessBob, Password: "pw", QuotaBytes: 1 << 20},
			}); err != nil {
				t.Fatal(err)
			}
			port := freePort(t)
			if err := core.Start(context.Background(), []InboundSpec{{
				ID: "reality", Core: core.Name(), Listen: "127.0.0.1", Port: port, Protocol: "vless",
				StreamJSON: string(stream),
			}}); err != nil {
				t.Fatal(err)
			}
			waitProxy(t, fmt.Sprintf("127.0.0.1:%d", port))
			aliceCli, alice, err := xrayDialRetry(port, vlessAlice, "", "reality", pub, "", echo.Addr().String())
			if err != nil {
				t.Fatalf("reality connect: %v", err)
			}
			defer aliceCli.Close()
			defer alice.Close()
			if core.Name() == "xray" {
				if !echoConn(alice, []byte("alice")) {
					t.Fatal("xray reality echo via freedom")
				}
			}
			sameCli, same, err := xrayDialRetry(port, vlessAlice, "", "reality", pub, "", echo.Addr().String())
			if err != nil {
				t.Fatal("same ip extra conn")
			}
			same.Close()
			sameCli.Close()
			if cli, conn, err := xrayDialAs(t, port, vlessAlice, "", "reality", pub, "", echo.Addr().String(), "127.0.0.2"); err == nil {
				conn.Close()
				cli.Close()
				t.Fatal("second reality ip allowed")
			}
			if core.Name() == "xray" {
				bobCli, bob, err := xrayDialRetry(port, vlessBob, "", "reality", pub, "", echo.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
				defer bobCli.Close()
				defer bob.Close()
				if !echoConn(bob, []byte("bob")) {
					t.Fatal("xray reality peer echo")
				}
				return
			}
			bobCli, bob, err := xrayDialRetry(port, vlessBob, "", "reality", pub, "", echo.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer bobCli.Close()
			defer bob.Close()
			if echoConn(alice, make([]byte, 65536)) {
				t.Fatal("reality quota allowed 64KiB")
			}
			snaps := core.TakeSnapshots()
			if n := totalUser(snaps, "u1"); n != 32 {
				t.Fatalf("reality snapshot %d %+v", n, snaps)
			}
			if err := core.CloseUserSessions("u1"); err != nil {
				t.Fatal(err)
			}
			if !echoConn(bob, []byte("stay")) {
				t.Fatal("healthy reality session dropped")
			}
			if echoConn(alice, []byte("dead")) {
				t.Fatal("revoked reality session still alive")
			}
		})
	}
}

func TestRoutedRealityQuotaDeviceAndPeerSession(t *testing.T) {
	requireAltLoopback(t)
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
	obs := []OutboundSpec{{ID: "audit-direct", Name: "audit-direct", Protocol: "freedom", Enabled: true}}
	routes := []RouteSpec{{ID: "business-route", Enabled: true, Priority: 1, RuleJSON: `{"inbound_id":"reality","outbound_id":"audit-direct"}`}}
	for _, maker := range []func() Core{NewXray, NewSingBox} {
		core := maker()
		t.Run(core.Name(), func(t *testing.T) {
			defer core.Stop()
			setForwarding(t, core, obs, routes)
			if err := core.ApplyUsers([]UserSpec{
				{ID: "u1", UUID: vlessAlice, Password: "pw", QuotaBytes: 32, DeviceLimit: 1},
				{ID: "u2", UUID: vlessBob, Password: "pw", QuotaBytes: 1 << 20},
			}); err != nil {
				t.Fatal(err)
			}
			port := freePort(t)
			if err := core.Start(context.Background(), []InboundSpec{{
				ID: "reality", Core: core.Name(), Listen: "127.0.0.1", Port: port, Protocol: "vless",
				StreamJSON: string(stream),
			}}); err != nil {
				t.Fatal(err)
			}
			waitProxy(t, fmt.Sprintf("127.0.0.1:%d", port))
			aliceCli, alice, err := xrayDialRetry(port, vlessAlice, "", "reality", pub, "", echo.Addr().String())
			if err != nil {
				t.Fatalf("routed reality connect: %v", err)
			}
			defer aliceCli.Close()
			defer alice.Close()
			if core.Name() == "xray" {
				if !echoConn(alice, []byte("alice")) {
					t.Fatal("xray routed reality echo via freedom")
				}
			}
			sameCli, same, err := xrayDialRetry(port, vlessAlice, "", "reality", pub, "", echo.Addr().String())
			if err != nil {
				t.Fatal("same ip extra conn")
			}
			same.Close()
			sameCli.Close()
			if cli, conn, err := xrayDialAs(t, port, vlessAlice, "", "reality", pub, "", echo.Addr().String(), "127.0.0.2"); err == nil {
				conn.Close()
				cli.Close()
				t.Fatal("second routed reality ip allowed")
			}
			if core.Name() == "xray" {
				bobCli, bob, err := xrayDialRetry(port, vlessBob, "", "reality", pub, "", echo.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
				defer bobCli.Close()
				defer bob.Close()
				if !echoConn(bob, []byte("bob")) {
					t.Fatal("xray routed reality peer echo")
				}
				return
			}
			bobCli, bob, err := xrayDialRetry(port, vlessBob, "", "reality", pub, "", echo.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer bobCli.Close()
			defer bob.Close()
			if echoConn(alice, make([]byte, 65536)) {
				t.Fatal("routed reality quota allowed 64KiB")
			}
			snaps := core.TakeSnapshots()
			if n := totalUser(snaps, "u1"); n != 32 {
				t.Fatalf("routed snapshot %d %+v", n, snaps)
			}
			if err := core.CloseUserSessions("u1"); err != nil {
				t.Fatal(err)
			}
			if !echoConn(bob, []byte("stay")) {
				t.Fatal("healthy routed session dropped")
			}
			if echoConn(alice, []byte("dead")) {
				t.Fatal("revoked routed session still alive")
			}
			if cli, conn, err := xrayDial(port, vlessAlice, "", "reality", pub, "", echo.Addr().String()); err == nil {
				conn.Close()
				cli.Close()
				t.Fatal("revoked user reconnect allowed")
			}
		})
	}
}

func TestXrayRoutedRealitySOCKSMixedMeter(t *testing.T) {
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
	core := NewXray()
	defer core.Stop()
	setForwarding(t, core,
		[]OutboundSpec{{ID: "audit-direct", Name: "audit-direct", Protocol: "freedom", Enabled: true}},
		[]RouteSpec{{ID: "business-route", Enabled: true, Priority: 1, RuleJSON: `{"inbound_id":"reality","outbound_id":"audit-direct"}`}},
	)
	if err := core.ApplyUsers([]UserSpec{{ID: "u1", UUID: vlessAlice, Password: "pw"}}); err != nil {
		t.Fatal(err)
	}
	rPort, sPort := freePort(t), freePort(t)
	if err := core.Start(context.Background(), []InboundSpec{
		{ID: "reality", Core: "xray", Listen: "127.0.0.1", Port: rPort, Protocol: "vless", StreamJSON: string(stream)},
		{ID: "socks", Core: "xray", Listen: "127.0.0.1", Port: sPort, Protocol: "socks"},
	}); err != nil {
		t.Fatal(err)
	}
	waitProxy(t, fmt.Sprintf("127.0.0.1:%d", rPort))
	waitProxy(t, fmt.Sprintf("127.0.0.1:%d", sPort))
	cli, a, err := xrayDialRetry(rPort, vlessAlice, "", "reality", pub, "", echo.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	defer a.Close()
	if !echoConn(a, make([]byte, 20)) {
		t.Fatal("reality echo")
	}
	b, err := socksTry(fmt.Sprintf("127.0.0.1:%d", sPort), vlessAlice, "pw", echo.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if !echoConn(b, make([]byte, 10)) {
		t.Fatal("socks echo")
	}
	first := core.TakeSnapshots()
	if total := totalUser(first, "u1"); total != 62 {
		t.Fatalf("routed mixed snapshot %d %+v", total, first)
	}
	core.AcknowledgeUsage()
	if idle := core.TakeSnapshots(); totalUser(idle, "u1") != 0 {
		t.Fatalf("idle %+v", idle)
	}
}

func TestRoutedRealitySocksPayloadMeter(t *testing.T) {
	echo := startEcho(t)
	defer echo.Close()
	relay, hits := startSocksRelay(t)
	defer relay.Close()
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
	obs := []OutboundSpec{socksOutbound("audit-exit", relay.Addr().String(), "")}
	routes := []RouteSpec{{ID: "business", Enabled: true, Priority: 1, RuleJSON: `{"inbound_id":"reality","outbound_id":"audit-exit"}`}}
	for _, maker := range []func() Core{NewXray, NewSingBox} {
		core := maker()
		t.Run(core.Name(), func(t *testing.T) {
			defer core.Stop()
			setForwarding(t, core, obs, routes)
			if err := core.ApplyUsers([]UserSpec{{ID: "u1", UUID: vlessAlice, Password: "pw", QuotaBytes: 32}}); err != nil {
				t.Fatal(err)
			}
			port := freePort(t)
			if err := core.Start(context.Background(), []InboundSpec{{
				ID: "reality", Core: core.Name(), Listen: "127.0.0.1", Port: port, Protocol: "vless",
				StreamJSON: string(stream),
			}}); err != nil {
				t.Fatal(err)
			}
			waitProxy(t, fmt.Sprintf("127.0.0.1:%d", port))
			drainHits(hits)
			cli, conn, err := xrayDialRetry(port, vlessAlice, "", "reality", pub, "", echo.Addr().String())
			if err != nil {
				t.Fatalf("socks path connect: %v", err)
			}
			defer cli.Close()
			defer conn.Close()
			if !echoConn(conn, make([]byte, 10)) {
				t.Fatal("quota 32 should allow echo 10 after initial 1")
			}
			time.Sleep(30 * time.Millisecond)
			if dests := drainHits(hits); !containsHost(dests, echo.Addr().String()) {
				t.Fatalf("relay dests %v want %s", dests, echo.Addr().String())
			}
			snaps := core.TakeSnapshots()
			if n := totalUser(snaps, "u1"); n != 22 {
				t.Fatalf("socks payload snapshot %d %+v", n, snaps)
			}
		})
	}
}

func TestRoutedRealityViaKeepsHop(t *testing.T) {
	echo := startEcho(t)
	defer echo.Close()
	relayA, hitsA := startSocksRelay(t)
	defer relayA.Close()
	relayB, hitsB := startSocksRelay(t)
	defer relayB.Close()
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
	obs := []OutboundSpec{
		socksOutbound("audit-B", relayB.Addr().String(), ""),
		socksOutbound("audit-A", relayA.Addr().String(), "audit-B"),
	}
	routes := []RouteSpec{{ID: "business", Enabled: true, Priority: 1, RuleJSON: `{"inbound_id":"reality","outbound_id":"audit-A"}`}}
	for _, maker := range []func() Core{NewXray, NewSingBox} {
		core := maker()
		t.Run(core.Name(), func(t *testing.T) {
			defer core.Stop()
			setForwarding(t, core, obs, routes)
			if err := core.ApplyUsers([]UserSpec{{ID: "u1", UUID: vlessAlice, Password: "pw"}}); err != nil {
				t.Fatal(err)
			}
			port := freePort(t)
			if err := core.Start(context.Background(), []InboundSpec{{
				ID: "reality", Core: core.Name(), Listen: "127.0.0.1", Port: port, Protocol: "vless",
				StreamJSON: string(stream),
			}}); err != nil {
				t.Fatal(err)
			}
			waitProxy(t, fmt.Sprintf("127.0.0.1:%d", port))
			drainHits(hitsA)
			drainHits(hitsB)
			cli, conn, err := xrayDialRetry(port, vlessAlice, "", "reality", pub, "", echo.Addr().String())
			if err != nil {
				t.Fatalf("via chain connect: %v", err)
			}
			defer cli.Close()
			defer conn.Close()
			if !echoConn(conn, []byte("via-chain")) {
				t.Fatal("via chain echo")
			}
			time.Sleep(30 * time.Millisecond)
			if dests := drainHits(hitsA); !containsHost(dests, echo.Addr().String()) {
				t.Fatalf("relay A dests %v want %s", dests, echo.Addr().String())
			}
			if dests := drainHits(hitsB); !containsHost(dests, relayA.Addr().String()) {
				t.Fatalf("relay B dests %v want %s", dests, relayA.Addr().String())
			}
		})
	}
}

func TestRoutedRealityVLESSPayloadMeter(t *testing.T) {
	echo := startEcho(t)
	defer echo.Close()
	relay, hits := startVLESSRelay(t)
	defer relay.Close()
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
	obs := []OutboundSpec{typedOutbound("audit-exit", "vless", relay.Addr().String(), "")}
	routes := []RouteSpec{{ID: "business", Enabled: true, Priority: 1, RuleJSON: `{"inbound_id":"reality","outbound_id":"audit-exit"}`}}
	for _, maker := range []func() Core{NewXray, NewSingBox} {
		core := maker()
		t.Run(core.Name(), func(t *testing.T) {
			defer core.Stop()
			setForwarding(t, core, obs, routes)
			if err := core.ApplyUsers([]UserSpec{{ID: "u1", UUID: vlessAlice, Password: "pw", QuotaBytes: 32}}); err != nil {
				t.Fatal(err)
			}
			port := freePort(t)
			if err := core.Start(context.Background(), []InboundSpec{{
				ID: "reality", Core: core.Name(), Listen: "127.0.0.1", Port: port, Protocol: "vless",
				StreamJSON: string(stream),
			}}); err != nil {
				t.Fatal(err)
			}
			waitProxy(t, fmt.Sprintf("127.0.0.1:%d", port))
			drainHits(hits)
			cli, conn, err := xrayDialRetry(port, vlessAlice, "", "reality", pub, "", echo.Addr().String())
			if err != nil {
				t.Fatalf("vless path connect: %v", err)
			}
			defer cli.Close()
			defer conn.Close()
			if !echoConn(conn, make([]byte, 10)) {
				t.Fatal("quota 32 should allow echo 10 after initial 1")
			}
			time.Sleep(30 * time.Millisecond)
			if dests := drainHits(hits); !containsHost(dests, echo.Addr().String()) {
				t.Fatalf("vless dests %v want %s", dests, echo.Addr().String())
			}
			snaps := core.TakeSnapshots()
			if n := totalUser(snaps, "u1"); n != 22 {
				t.Fatalf("vless payload snapshot %d %+v", n, snaps)
			}
		})
	}
}

func TestRoutedRealityVLESSViaSOCKS(t *testing.T) {
	echo := startEcho(t)
	defer echo.Close()
	relayA, hitsA := startVLESSRelay(t)
	defer relayA.Close()
	relayB, hitsB := startSocksRelay(t)
	defer relayB.Close()
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
	obs := []OutboundSpec{
		socksOutbound("audit-B", relayB.Addr().String(), ""),
		typedOutbound("audit-A", "vless", relayA.Addr().String(), "audit-B"),
	}
	routes := []RouteSpec{{ID: "business", Enabled: true, Priority: 1, RuleJSON: `{"inbound_id":"reality","outbound_id":"audit-A"}`}}
	for _, maker := range []func() Core{NewXray, NewSingBox} {
		core := maker()
		t.Run(core.Name(), func(t *testing.T) {
			defer core.Stop()
			setForwarding(t, core, obs, routes)
			if err := core.ApplyUsers([]UserSpec{{ID: "u1", UUID: vlessAlice, Password: "pw"}}); err != nil {
				t.Fatal(err)
			}
			port := freePort(t)
			if err := core.Start(context.Background(), []InboundSpec{{
				ID: "reality", Core: core.Name(), Listen: "127.0.0.1", Port: port, Protocol: "vless",
				StreamJSON: string(stream),
			}}); err != nil {
				t.Fatal(err)
			}
			waitProxy(t, fmt.Sprintf("127.0.0.1:%d", port))
			drainHits(hitsA)
			drainHits(hitsB)
			cli, conn, err := xrayDialRetry(port, vlessAlice, "", "reality", pub, "", echo.Addr().String())
			if err != nil {
				t.Fatalf("vless via socks connect: %v", err)
			}
			defer cli.Close()
			defer conn.Close()
			if !echoConn(conn, []byte("via-vless")) {
				t.Fatal("vless via socks echo")
			}
			time.Sleep(30 * time.Millisecond)
			if dests := drainHits(hitsA); !containsHost(dests, echo.Addr().String()) {
				t.Fatalf("vless A dests %v want %s", dests, echo.Addr().String())
			}
			if dests := drainHits(hitsB); !containsHost(dests, relayA.Addr().String()) {
				t.Fatalf("socks B dests %v want %s", dests, relayA.Addr().String())
			}
		})
	}
}

func TestRoutedRealityVLESSDelayedReply(t *testing.T) {
	echo := startEcho(t)
	defer echo.Close()
	relay, hits := startDelayedVLESSRelay(t)
	defer relay.Close()
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
	obs := []OutboundSpec{typedOutbound("audit-exit", "vless", relay.Addr().String(), "")}
	routes := []RouteSpec{{ID: "business", Enabled: true, Priority: 1, RuleJSON: `{"inbound_id":"reality","outbound_id":"audit-exit"}`}}
	for _, maker := range []func() Core{NewXray, NewSingBox} {
		core := maker()
		t.Run(core.Name(), func(t *testing.T) {
			defer core.Stop()
			setForwarding(t, core, obs, routes)
			if err := core.ApplyUsers([]UserSpec{{ID: "u1", UUID: vlessAlice, Password: "pw"}}); err != nil {
				t.Fatal(err)
			}
			port := freePort(t)
			if err := core.Start(context.Background(), []InboundSpec{{
				ID: "reality", Core: core.Name(), Listen: "127.0.0.1", Port: port, Protocol: "vless",
				StreamJSON: string(stream),
			}}); err != nil {
				t.Fatal(err)
			}
			waitProxy(t, fmt.Sprintf("127.0.0.1:%d", port))
			drainHits(hits)
			cli, conn, err := xrayDialRetry(port, vlessAlice, "", "reality", pub, "", echo.Addr().String())
			if err != nil {
				t.Fatalf("delayed vless connect: %v", err)
			}
			defer cli.Close()
			defer conn.Close()
			if !echoConn(conn, make([]byte, 20)) {
				t.Fatal("delayed vless echo")
			}
			time.Sleep(30 * time.Millisecond)
			if dests := drainHits(hits); !containsHost(dests, echo.Addr().String()) {
				t.Fatalf("delayed dests %v want %s", dests, echo.Addr().String())
			}
		})
	}
}

func TestRoutedRealityVLESSTLSRejectsPlain(t *testing.T) {
	echo := startEcho(t)
	defer echo.Close()
	relay, hits := startVLESSRelay(t)
	defer relay.Close()
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
	obs := []OutboundSpec{tlsVLESSOutbound("audit-exit", relay.Addr().String())}
	routes := []RouteSpec{{ID: "business", Enabled: true, Priority: 1, RuleJSON: `{"inbound_id":"reality","outbound_id":"audit-exit"}`}}
	for _, maker := range []func() Core{NewXray, NewSingBox} {
		core := maker()
		t.Run(core.Name(), func(t *testing.T) {
			defer core.Stop()
			setForwarding(t, core, obs, routes)
			if err := core.ApplyUsers([]UserSpec{{ID: "u1", UUID: vlessAlice, Password: "pw"}}); err != nil {
				t.Fatal(err)
			}
			port := freePort(t)
			if err := core.Start(context.Background(), []InboundSpec{{
				ID: "reality", Core: core.Name(), Listen: "127.0.0.1", Port: port, Protocol: "vless",
				StreamJSON: string(stream),
			}}); err != nil {
				t.Fatal(err)
			}
			waitProxy(t, fmt.Sprintf("127.0.0.1:%d", port))
			drainHits(hits)
			cli, conn, err := xrayDial(port, vlessAlice, "", "reality", pub, "", echo.Addr().String())
			if err == nil {
				conn.Close()
				cli.Close()
				t.Fatal("tls vless outbound accepted plaintext peer")
			}
			if dests := drainHits(hits); len(dests) != 0 {
				t.Fatalf("plaintext peer accepted tls client %v", dests)
			}
		})
	}
}

func TestRoutedRealityVLESSTLSConnects(t *testing.T) {
	echo := startEcho(t)
	defer echo.Close()
	certPEM, keyPEM, pin := auditCerts(t)
	withHopTLSRoots(t, certPEM)
	relay, hits := startTLSVLESSRelay(t, certPEM, keyPEM)
	defer relay.Close()
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
	obs := []OutboundSpec{withPinnedCert(tlsVLESSOutbound("audit-exit", relay.Addr().String()), pin)}
	routes := []RouteSpec{{ID: "business", Enabled: true, Priority: 1, RuleJSON: `{"inbound_id":"reality","outbound_id":"audit-exit"}`}}
	for _, maker := range []func() Core{NewXray, NewSingBox} {
		core := maker()
		t.Run(core.Name(), func(t *testing.T) {
			defer core.Stop()
			setForwarding(t, core, obs, routes)
			if err := core.ApplyUsers([]UserSpec{{ID: "u1", UUID: vlessAlice, Password: "pw", QuotaBytes: 32}}); err != nil {
				t.Fatal(err)
			}
			port := freePort(t)
			if err := core.Start(context.Background(), []InboundSpec{{
				ID: "reality", Core: core.Name(), Listen: "127.0.0.1", Port: port, Protocol: "vless",
				StreamJSON: string(stream),
			}}); err != nil {
				t.Fatal(err)
			}
			waitProxy(t, fmt.Sprintf("127.0.0.1:%d", port))
			drainHits(hits)
			cli, conn, err := xrayDialRetry(port, vlessAlice, "", "reality", pub, "", echo.Addr().String())
			if err != nil {
				t.Fatalf("tls vless connect: %v", err)
			}
			defer cli.Close()
			defer conn.Close()
			if !echoConn(conn, make([]byte, 10)) {
				t.Fatal("tls vless echo")
			}
			time.Sleep(30 * time.Millisecond)
			if dests := drainHits(hits); !containsHost(dests, echo.Addr().String()) {
				t.Fatalf("tls dests %v want %s", dests, echo.Addr().String())
			}
			if n := totalUser(core.TakeSnapshots(), "u1"); n != 22 {
				t.Fatalf("tls vless snapshot %d", n)
			}
		})
	}
}

func TestRoutedRealityVLESSTLSRejectsWrongName(t *testing.T) {
	echo := startEcho(t)
	defer echo.Close()
	certPEM, keyPEM := namedTestCerts(t, "wrong.test")
	withHopTLSRoots(t, certPEM)
	relay, hits := startTLSVLESSRelay(t, certPEM, keyPEM)
	defer relay.Close()
	decoyPEM, decoyKey, _ := auditCerts(t)
	decoy := startTLS13Decoy(t, decoyPEM, decoyKey)
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
	obs := []OutboundSpec{tlsVLESSOutbound("audit-exit", relay.Addr().String())}
	routes := []RouteSpec{{ID: "business", Enabled: true, Priority: 1, RuleJSON: `{"inbound_id":"reality","outbound_id":"audit-exit"}`}}
	core := NewXray()
	defer core.Stop()
	setForwarding(t, core, obs, routes)
	if err := core.ApplyUsers([]UserSpec{{ID: "u1", UUID: vlessAlice, Password: "pw"}}); err != nil {
		t.Fatal(err)
	}
	port := freePort(t)
	if err := core.Start(context.Background(), []InboundSpec{{
		ID: "reality", Core: "xray", Listen: "127.0.0.1", Port: port, Protocol: "vless",
		StreamJSON: string(stream),
	}}); err != nil {
		t.Fatal(err)
	}
	waitProxy(t, fmt.Sprintf("127.0.0.1:%d", port))
	drainHits(hits)
	cli, conn, err := xrayDial(port, vlessAlice, "", "reality", pub, "", echo.Addr().String())
	if err == nil {
		conn.Close()
		cli.Close()
		t.Fatal("tls outbound accepted certificate for wrong.test as audit.test")
	}
}

func TestRoutedRealityVLESSTLSRejectsUntrusted(t *testing.T) {
	echo := startEcho(t)
	defer echo.Close()
	certPEM, keyPEM, _ := auditCerts(t)
	relay, hits := startTLSVLESSRelay(t, certPEM, keyPEM)
	defer relay.Close()
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
	obs := []OutboundSpec{tlsVLESSOutbound("audit-exit", relay.Addr().String())}
	routes := []RouteSpec{{ID: "business", Enabled: true, Priority: 1, RuleJSON: `{"inbound_id":"reality","outbound_id":"audit-exit"}`}}
	core := NewXray()
	defer core.Stop()
	setForwarding(t, core, obs, routes)
	if err := core.ApplyUsers([]UserSpec{{ID: "u1", UUID: vlessAlice, Password: "pw"}}); err != nil {
		t.Fatal(err)
	}
	port := freePort(t)
	if err := core.Start(context.Background(), []InboundSpec{{
		ID: "reality", Core: "xray", Listen: "127.0.0.1", Port: port, Protocol: "vless",
		StreamJSON: string(stream),
	}}); err != nil {
		t.Fatal(err)
	}
	waitProxy(t, fmt.Sprintf("127.0.0.1:%d", port))
	drainHits(hits)
	cli, conn, err := xrayDial(port, vlessAlice, "", "reality", pub, "", echo.Addr().String())
	if err == nil {
		conn.Close()
		cli.Close()
		t.Fatal("tls outbound accepted untrusted certificate")
	}
}

func TestRoutedRealitySOCKSViaDelayedVLESS(t *testing.T) {
	echo := startEcho(t)
	defer echo.Close()
	relayA, hitsA := startSocksRelay(t)
	defer relayA.Close()
	relayB, hitsB := startDelayedVLESSRelay(t)
	defer relayB.Close()
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
	obs := []OutboundSpec{
		socksOutbound("audit-A", relayA.Addr().String(), "audit-B"),
		typedOutbound("audit-B", "vless", relayB.Addr().String(), ""),
	}
	routes := []RouteSpec{{ID: "business", Enabled: true, Priority: 1, RuleJSON: `{"inbound_id":"reality","outbound_id":"audit-A"}`}}
	for _, maker := range []func() Core{NewXray, NewSingBox} {
		core := maker()
		t.Run(core.Name(), func(t *testing.T) {
			defer core.Stop()
			setForwarding(t, core, obs, routes)
			if err := core.ApplyUsers([]UserSpec{{ID: "u1", UUID: vlessAlice, Password: "pw"}}); err != nil {
				t.Fatal(err)
			}
			port := freePort(t)
			if err := core.Start(context.Background(), []InboundSpec{{
				ID: "reality", Core: core.Name(), Listen: "127.0.0.1", Port: port, Protocol: "vless",
				StreamJSON: string(stream),
			}}); err != nil {
				t.Fatal(err)
			}
			waitProxy(t, fmt.Sprintf("127.0.0.1:%d", port))
			drainHits(hitsA)
			drainHits(hitsB)
			cli, conn, err := xrayDialRetry(port, vlessAlice, "", "reality", pub, "", echo.Addr().String())
			if err != nil {
				t.Fatalf("socks via vless connect: %v", err)
			}
			defer cli.Close()
			defer conn.Close()
			if !echoConn(conn, make([]byte, 20)) {
				t.Fatal("socks via vless echo")
			}
			time.Sleep(30 * time.Millisecond)
			if dests := drainHits(hitsA); !containsHost(dests, echo.Addr().String()) {
				t.Fatalf("socks A dests %v want %s", dests, echo.Addr().String())
			}
			if dests := drainHits(hitsB); !containsHost(dests, relayA.Addr().String()) {
				t.Fatalf("vless B dests %v want %s", dests, relayA.Addr().String())
			}
		})
	}
}

func TestRoutedRealityVLESSWSPayloadMeter(t *testing.T) {
	echo := startEcho(t)
	defer echo.Close()
	relay, hits := startWSVLESSRelay(t, "/audit")
	defer relay.Close()
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
	obs := []OutboundSpec{wsVLESSOutbound("audit-exit", relay.Addr().String(), "/audit")}
	routes := []RouteSpec{{ID: "business", Enabled: true, Priority: 1, RuleJSON: `{"inbound_id":"reality","outbound_id":"audit-exit"}`}}
	for _, maker := range []func() Core{NewXray, NewSingBox} {
		core := maker()
		t.Run(core.Name(), func(t *testing.T) {
			defer core.Stop()
			setForwarding(t, core, obs, routes)
			if err := core.ApplyUsers([]UserSpec{{ID: "u1", UUID: vlessAlice, Password: "pw", QuotaBytes: 32}}); err != nil {
				t.Fatal(err)
			}
			port := freePort(t)
			if err := core.Start(context.Background(), []InboundSpec{{
				ID: "reality", Core: core.Name(), Listen: "127.0.0.1", Port: port, Protocol: "vless",
				StreamJSON: string(stream),
			}}); err != nil {
				t.Fatal(err)
			}
			waitProxy(t, fmt.Sprintf("127.0.0.1:%d", port))
			drainHits(hits)
			cli, conn, err := xrayDialRetry(port, vlessAlice, "", "reality", pub, "", echo.Addr().String())
			if err != nil {
				t.Fatalf("ws vless connect: %v", err)
			}
			defer cli.Close()
			defer conn.Close()
			if !echoConn(conn, make([]byte, 10)) {
				t.Fatal("quota 32 should allow echo 10 after initial 1")
			}
			time.Sleep(30 * time.Millisecond)
			if dests := drainHits(hits); !containsHost(dests, echo.Addr().String()) {
				t.Fatalf("ws dests %v want %s", dests, echo.Addr().String())
			}
			if n := totalUser(core.TakeSnapshots(), "u1"); n != 22 {
				t.Fatalf("ws vless snapshot %d", n)
			}
		})
	}
}

func TestRoutedRealityVLESSWSQueryPath(t *testing.T) {
	echo := startEcho(t)
	defer echo.Close()
	relay, hits, uris := startWSVLESSRelayLogged(t, "/audit")
	defer relay.Close()
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
	obs := []OutboundSpec{wsVLESSOutbound("audit-exit", relay.Addr().String(), "/audit?token=audit")}
	routes := []RouteSpec{{ID: "business", Enabled: true, Priority: 1, RuleJSON: `{"inbound_id":"reality","outbound_id":"audit-exit"}`}}
	for _, maker := range []func() Core{NewXray, NewSingBox} {
		core := maker()
		t.Run(core.Name(), func(t *testing.T) {
			defer core.Stop()
			setForwarding(t, core, obs, routes)
			if err := core.ApplyUsers([]UserSpec{{ID: "u1", UUID: vlessAlice, Password: "pw", QuotaBytes: 32}}); err != nil {
				t.Fatal(err)
			}
			port := freePort(t)
			if err := core.Start(context.Background(), []InboundSpec{{
				ID: "reality", Core: core.Name(), Listen: "127.0.0.1", Port: port, Protocol: "vless",
				StreamJSON: string(stream),
			}}); err != nil {
				t.Fatal(err)
			}
			waitProxy(t, fmt.Sprintf("127.0.0.1:%d", port))
			drainHits(hits)
			drainHits(uris)
			cli, conn, err := xrayDialRetry(port, vlessAlice, "", "reality", pub, "", echo.Addr().String())
			if err != nil {
				t.Fatalf("ws query connect: %v", err)
			}
			defer cli.Close()
			defer conn.Close()
			if !echoConn(conn, make([]byte, 10)) {
				t.Fatal("ws query echo")
			}
			time.Sleep(30 * time.Millisecond)
			if got := drainHits(uris); !containsHost(got, "/audit?token=audit") {
				t.Fatalf("ws request %v", got)
			}
			if n := totalUser(core.TakeSnapshots(), "u1"); n != 22 {
				t.Fatalf("ws query snapshot %d", n)
			}
		})
	}
}

func TestRoutedRealityVLESSWSEscapedPath(t *testing.T) {
	echo := startEcho(t)
	defer echo.Close()
	relay, hits, uris := startWSVLESSRelayLogged(t, "/audit")
	defer relay.Close()
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
	obs := []OutboundSpec{wsVLESSOutbound("audit-exit", relay.Addr().String(), "/%61udit?token=audit")}
	routes := []RouteSpec{{ID: "business", Enabled: true, Priority: 1, RuleJSON: `{"inbound_id":"reality","outbound_id":"audit-exit"}`}}
	for _, maker := range []func() Core{NewXray, NewSingBox} {
		core := maker()
		t.Run(core.Name(), func(t *testing.T) {
			defer core.Stop()
			setForwarding(t, core, obs, routes)
			if err := core.ApplyUsers([]UserSpec{{ID: "u1", UUID: vlessAlice, Password: "pw", QuotaBytes: 32}}); err != nil {
				t.Fatal(err)
			}
			port := freePort(t)
			if err := core.Start(context.Background(), []InboundSpec{{
				ID: "reality", Core: core.Name(), Listen: "127.0.0.1", Port: port, Protocol: "vless",
				StreamJSON: string(stream),
			}}); err != nil {
				t.Fatal(err)
			}
			waitProxy(t, fmt.Sprintf("127.0.0.1:%d", port))
			drainHits(hits)
			drainHits(uris)
			cli, conn, err := xrayDialRetry(port, vlessAlice, "", "reality", pub, "", echo.Addr().String())
			if err != nil {
				t.Fatalf("ws escaped connect: %v", err)
			}
			defer cli.Close()
			defer conn.Close()
			if !echoConn(conn, make([]byte, 10)) {
				t.Fatal("ws escaped echo")
			}
			time.Sleep(30 * time.Millisecond)
			got := drainHits(uris)
			if containsHost(got, "/%2561udit?token=audit") {
				t.Fatalf("ws path double-encoded %v", got)
			}
			if !containsHost(got, "/%61udit?token=audit") {
				t.Fatalf("ws request %v", got)
			}
			if n := totalUser(core.TakeSnapshots(), "u1"); n != 22 {
				t.Fatalf("ws escaped snapshot %d", n)
			}
		})
	}
}

func TestRoutedRealityVLESSTLSOmitsSNI(t *testing.T) {
	echo := startEcho(t)
	defer echo.Close()
	certPEM, keyPEM, pin := namedTestCertsPinned(t, "localhost")
	withHopTLSRoots(t, certPEM)
	relay, hits, names := startTLSVLESSRelayHello(t, certPEM, keyPEM)
	defer relay.Close()
	decoyPEM, decoyKey, _ := auditCerts(t)
	decoy := startTLS13Decoy(t, decoyPEM, decoyKey)
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
	_, portStr, err := net.SplitHostPort(relay.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	var relayPort int
	fmt.Sscanf(portStr, "%d", &relayPort)
	obs := []OutboundSpec{withPinnedCert(tlsVLESSOutboundAt("audit-exit", "localhost", relayPort), pin)}
	routes := []RouteSpec{{ID: "business", Enabled: true, Priority: 1, RuleJSON: `{"inbound_id":"reality","outbound_id":"audit-exit"}`}}
	for _, maker := range []func() Core{NewXray, NewSingBox} {
		core := maker()
		t.Run(core.Name(), func(t *testing.T) {
			defer core.Stop()
			setForwarding(t, core, obs, routes)
			if err := core.ApplyUsers([]UserSpec{{ID: "u1", UUID: vlessAlice, Password: "pw", QuotaBytes: 32}}); err != nil {
				t.Fatal(err)
			}
			port := freePort(t)
			if err := core.Start(context.Background(), []InboundSpec{{
				ID: "reality", Core: core.Name(), Listen: "127.0.0.1", Port: port, Protocol: "vless",
				StreamJSON: string(stream),
			}}); err != nil {
				t.Fatal(err)
			}
			waitProxy(t, fmt.Sprintf("127.0.0.1:%d", port))
			drainHits(hits)
			drainHits(names)
			cli, conn, err := xrayDialRetry(port, vlessAlice, "", "reality", pub, "", echo.Addr().String())
			if err != nil {
				t.Fatalf("tls default sni connect: %v", err)
			}
			defer cli.Close()
			defer conn.Close()
			if !echoConn(conn, make([]byte, 10)) {
				t.Fatal("tls default sni echo")
			}
			time.Sleep(30 * time.Millisecond)
			if got := drainHits(names); !containsHost(got, "localhost") {
				t.Fatalf("client hello names %v", got)
			}
			if n := totalUser(core.TakeSnapshots(), "u1"); n != 22 {
				t.Fatalf("tls default sni snapshot %d", n)
			}
		})
	}
}

func TestRoutedRealityVLESSGRPCPayloadMeter(t *testing.T) {
	echo := startEcho(t)
	defer echo.Close()
	peer, peerPort := startGRPCVLESSPeer(t)
	defer peer.Stop()
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
	obs := []OutboundSpec{grpcVLESSOutbound("audit-exit", fmt.Sprintf("127.0.0.1:%d", peerPort))}
	routes := []RouteSpec{{ID: "business", Enabled: true, Priority: 1, RuleJSON: `{"inbound_id":"reality","outbound_id":"audit-exit"}`}}
	for _, maker := range []func() Core{NewXray, NewSingBox} {
		core := maker()
		t.Run(core.Name(), func(t *testing.T) {
			defer core.Stop()
			setForwarding(t, core, obs, routes)
			if err := core.ApplyUsers([]UserSpec{{ID: "u1", UUID: vlessAlice, Password: "pw", QuotaBytes: 32}}); err != nil {
				t.Fatal(err)
			}
			port := freePort(t)
			if err := core.Start(context.Background(), []InboundSpec{{
				ID: "reality", Core: core.Name(), Listen: "127.0.0.1", Port: port, Protocol: "vless",
				StreamJSON: string(stream),
			}}); err != nil {
				t.Fatal(err)
			}
			waitProxy(t, fmt.Sprintf("127.0.0.1:%d", port))
			cli, conn, err := xrayDialRetry(port, vlessAlice, "", "reality", pub, "", echo.Addr().String())
			if err != nil {
				t.Fatalf("grpc vless connect: %v", err)
			}
			defer cli.Close()
			defer conn.Close()
			if !echoConn(conn, make([]byte, 10)) {
				t.Fatal("grpc vless echo")
			}
			time.Sleep(30 * time.Millisecond)
			if n := totalUser(core.TakeSnapshots(), "u1"); n != 22 {
				t.Fatalf("grpc vless snapshot %d", n)
			}
		})
	}
}

func TestSingBoxGRPCOutboundSendsTLSClientHello(t *testing.T) {
	echo := startEcho(t)
	defer echo.Close()
	peer, peerPort := startGRPCVLESSPeer(t)
	defer peer.Stop()
	tap, prefixes := startWireTap(t, fmt.Sprintf("127.0.0.1:%d", peerPort))
	defer tap.Close()
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
	obs := []OutboundSpec{grpcTLSVLESSOutbound("audit-exit", tap.Addr().String())}
	routes := []RouteSpec{{ID: "business", Enabled: true, Priority: 1, RuleJSON: `{"inbound_id":"reality","outbound_id":"audit-exit"}`}}
	core := NewSingBox()
	defer core.Stop()
	setForwarding(t, core, obs, routes)
	if err := core.ApplyUsers([]UserSpec{{ID: "u1", UUID: vlessAlice, Password: "pw"}}); err != nil {
		t.Fatal(err)
	}
	port := freePort(t)
	if err := core.Start(context.Background(), []InboundSpec{{
		ID: "reality", Core: core.Name(), Listen: "127.0.0.1", Port: port, Protocol: "vless",
		StreamJSON: string(stream),
	}}); err != nil {
		t.Fatal(err)
	}
	waitProxy(t, fmt.Sprintf("127.0.0.1:%d", port))
	cli, conn, err := xrayDialRetry(port, vlessAlice, "", "reality", pub, "", echo.Addr().String())
	if err == nil {
		_ = echoConn(conn, make([]byte, 10))
		conn.Close()
		cli.Close()
		t.Fatal("tls grpc succeeded against a plaintext peer")
	}
	deadline := time.Now().Add(2 * time.Second)
	var prefix []byte
	for time.Now().Before(deadline) {
		select {
		case prefix = <-prefixes:
		default:
			time.Sleep(20 * time.Millisecond)
			continue
		}
		break
	}
	if len(prefix) < 2 || prefix[0] != 0x16 || prefix[1] != 0x03 {
		t.Fatalf("expected tls client hello, got %x err=%v", prefix, err)
	}
}

func TestSingBoxGRPCViaAuthSOCKSMapsUsername(t *testing.T) {
	echo := startEcho(t)
	defer echo.Close()
	peer, peerPort := startGRPCVLESSPeer(t)
	defer peer.Stop()
	relay, hits, auths := startAuthSocksRelay(t)
	defer relay.Close()
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
	obs := []OutboundSpec{
		withVia(grpcVLESSOutbound("audit-A", fmt.Sprintf("127.0.0.1:%d", peerPort)), "audit-B"),
		socksAuthOutbound("audit-B", relay.Addr().String(), ""),
	}
	routes := []RouteSpec{{ID: "business", Enabled: true, Priority: 1, RuleJSON: `{"inbound_id":"reality","outbound_id":"audit-A"}`}}
	core := NewSingBox()
	defer core.Stop()
	setForwarding(t, core, obs, routes)
	if err := core.ApplyUsers([]UserSpec{{ID: "u1", UUID: vlessAlice, Password: "pw", QuotaBytes: 32}}); err != nil {
		t.Fatal(err)
	}
	port := freePort(t)
	if err := core.Start(context.Background(), []InboundSpec{{
		ID: "reality", Core: core.Name(), Listen: "127.0.0.1", Port: port, Protocol: "vless",
		StreamJSON: string(stream),
	}}); err != nil {
		t.Fatal(err)
	}
	waitProxy(t, fmt.Sprintf("127.0.0.1:%d", port))
	cli, conn, err := xrayDialRetry(port, vlessAlice, "", "reality", pub, "", echo.Addr().String())
	if err != nil {
		t.Fatalf("grpc via auth socks connect: %v auths=%v", err, drainHits(auths))
	}
	defer cli.Close()
	defer conn.Close()
	if !echoConn(conn, make([]byte, 10)) {
		t.Fatal("grpc via auth socks echo")
	}
	time.Sleep(30 * time.Millisecond)
	if got := drainHits(auths); !containsHost(got, "username=audit-user") {
		t.Fatalf("auth attempts %v", got)
	}
	if got := drainHits(hits); !containsHost(got, fmt.Sprintf("127.0.0.1:%d", peerPort)) {
		t.Fatalf("relay targets %v", got)
	}
	if n := totalUser(core.TakeSnapshots(), "u1"); n != 22 {
		t.Fatalf("grpc via auth socks snapshot %d", n)
	}
}

func typedOutbound(id, proto, addr, via string) OutboundSpec {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		panic(err)
	}
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	settings := map[string]any{"address": host, "port": port, "via_outbound": via, "uuid": vlessAlice}
	raw, err := json.Marshal(settings)
	if err != nil {
		panic(err)
	}
	return OutboundSpec{ID: id, Name: id, Protocol: proto, Enabled: true, SettingsJSON: string(raw)}
}

func tlsVLESSOutbound(id, addr string) OutboundSpec {
	o := typedOutbound(id, "vless", addr, "")
	var s map[string]any
	if err := json.Unmarshal([]byte(o.SettingsJSON), &s); err != nil {
		panic(err)
	}
	s["security"] = "tls"
	s["transport"] = "tcp"
	s["sni"] = "audit.test"
	raw, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	o.SettingsJSON = string(raw)
	return o
}

func withPinnedCert(o OutboundSpec, pin string) OutboundSpec {
	var s map[string]any
	if err := json.Unmarshal([]byte(o.SettingsJSON), &s); err != nil {
		panic(err)
	}
	s["pinned_peer_cert_sha256"] = pin
	raw, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	o.SettingsJSON = string(raw)
	return o
}

func tlsVLESSOutboundAt(id, host string, port int) OutboundSpec {
	raw, err := json.Marshal(map[string]any{
		"address": host, "port": port, "uuid": vlessAlice, "security": "tls", "transport": "tcp",
	})
	if err != nil {
		panic(err)
	}
	return OutboundSpec{ID: id, Name: id, Protocol: "vless", Enabled: true, SettingsJSON: string(raw)}
}

func grpcVLESSOutbound(id, addr string) OutboundSpec {
	o := typedOutbound(id, "vless", addr, "")
	var s map[string]any
	if err := json.Unmarshal([]byte(o.SettingsJSON), &s); err != nil {
		panic(err)
	}
	s["transport"] = "grpc"
	s["security"] = "none"
	s["grpc_service"] = "audit"
	raw, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	o.SettingsJSON = string(raw)
	return o
}

func grpcTLSVLESSOutbound(id, addr string) OutboundSpec {
	o := grpcVLESSOutbound(id, addr)
	var s map[string]any
	if err := json.Unmarshal([]byte(o.SettingsJSON), &s); err != nil {
		panic(err)
	}
	s["security"] = "tls"
	s["sni"] = "audit.test"
	raw, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	o.SettingsJSON = string(raw)
	return o
}

func withVia(o OutboundSpec, via string) OutboundSpec {
	var s map[string]any
	if err := json.Unmarshal([]byte(o.SettingsJSON), &s); err != nil {
		panic(err)
	}
	s["via_outbound"] = via
	raw, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	o.SettingsJSON = string(raw)
	return o
}

func wsVLESSOutbound(id, addr, path string) OutboundSpec {
	o := typedOutbound(id, "vless", addr, "")
	var s map[string]any
	if err := json.Unmarshal([]byte(o.SettingsJSON), &s); err != nil {
		panic(err)
	}
	s["transport"] = "ws"
	s["security"] = "none"
	s["ws_path"] = path
	raw, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	o.SettingsJSON = string(raw)
	return o
}

func withHopTLSRoots(t *testing.T, certPEM string) {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(certPEM)) {
		t.Fatal("test tls roots")
	}
	hopTLSMu.Lock()
	prev := hopTLSRootCAs
	hopTLSRootCAs = pool
	hopTLSMu.Unlock()
	t.Cleanup(func() {
		hopTLSMu.Lock()
		hopTLSRootCAs = prev
		hopTLSMu.Unlock()
	})
}

func namedTestCerts(t *testing.T, name string) (string, string) {
	t.Helper()
	certPEM, keyPEM, _ := namedTestCertsPinned(t, name)
	return certPEM, keyPEM
}

func namedTestCertsPinned(t *testing.T, name string) (string, string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(11),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{name},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pin := fmt.Sprintf("%x", sha256.Sum256(der))
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})), pin
}

func startWSVLESSRelay(t *testing.T, path string) (net.Listener, chan string) {
	ln, hits, _ := startWSVLESSRelayLogged(t, path)
	return ln, hits
}

func startWSVLESSRelayLogged(t *testing.T, path string) (net.Listener, chan string, chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hits := make(chan string, 32)
	uris := make(chan string, 8)
	up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		select {
		case uris <- r.RequestURI:
		default:
		}
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		serveVLESSRelay(newWSConn(c), hits, false)
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go srv.Serve(ln)
	t.Cleanup(func() { _ = srv.Close() })
	return ln, hits, uris
}

func startVLESSRelay(t *testing.T) (net.Listener, chan string) {
	return listenVLESSRelay(t, false, nil, "")
}

func startDelayedVLESSRelay(t *testing.T) (net.Listener, chan string) {
	return listenVLESSRelay(t, true, nil, "")
}

func startTLSVLESSRelay(t *testing.T, certPEM, keyPEM string) (net.Listener, chan string) {
	return listenVLESSRelay(t, false, []byte(certPEM), keyPEM)
}

func startTLSVLESSRelayHello(t *testing.T, certPEM, keyPEM string) (net.Listener, chan string, chan string) {
	t.Helper()
	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		t.Fatal(err)
	}
	names := make(chan string, 8)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			select {
			case names <- hello.ServerName:
			default:
			}
			return nil, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	hits := make(chan string, 32)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveVLESSRelay(c, hits, false)
		}
	}()
	return ln, hits, names
}

func startGRPCVLESSPeer(t *testing.T) (Core, int) {
	t.Helper()
	peer := NewXray()
	if err := peer.ApplyUsers([]UserSpec{{ID: "peer", UUID: vlessAlice, Password: "pw"}}); err != nil {
		t.Fatal(err)
	}
	port := freePort(t)
	stream, err := json.Marshal(map[string]any{
		"network": "grpc", "security": "none",
		"grpcSettings": map[string]any{"serviceName": "audit"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := peer.Start(context.Background(), []InboundSpec{{
		ID: "grpc", Core: "xray", Listen: "127.0.0.1", Port: port, Protocol: "vless",
		StreamJSON: string(stream),
	}}); err != nil {
		t.Fatal(err)
	}
	waitProxy(t, fmt.Sprintf("127.0.0.1:%d", port))
	return peer, port
}

func listenVLESSRelay(t *testing.T, delayHeader bool, certPEM []byte, keyPEM string) (net.Listener, chan string) {
	t.Helper()
	var ln net.Listener
	var err error
	if len(certPEM) > 0 {
		cert, cerr := tls.X509KeyPair(certPEM, []byte(keyPEM))
		if cerr != nil {
			t.Fatal(cerr)
		}
		ln, err = tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	} else {
		ln, err = net.Listen("tcp", "127.0.0.1:0")
	}
	if err != nil {
		t.Fatal(err)
	}
	hits := make(chan string, 32)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveVLESSRelay(c, hits, delayHeader)
		}
	}()
	return ln, hits
}

func serveVLESSRelay(c net.Conn, hits chan string, delayHeader bool) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(8 * time.Second))
	h := make([]byte, 18)
	if _, err := io.ReadFull(c, h); err != nil {
		return
	}
	if h[0] != 0 || formatUUID(h[1:17]) != vlessAlice {
		return
	}
	if _, err := io.CopyN(io.Discard, c, int64(h[17])); err != nil {
		return
	}
	r := make([]byte, 4)
	if _, err := io.ReadFull(c, r); err != nil || r[0] != 1 {
		return
	}
	var host string
	switch r[3] {
	case 1:
		b := make([]byte, 4)
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case 2:
		n := make([]byte, 1)
		if _, err := io.ReadFull(c, n); err != nil {
			return
		}
		b := make([]byte, int(n[0]))
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		host = string(b)
	case 3:
		b := make([]byte, 16)
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		host = net.IP(b).String()
	default:
		return
	}
	dest := net.JoinHostPort(host, fmt.Sprint(int(r[1])*256+int(r[2])))
	select {
	case hits <- dest:
	default:
	}
	up, err := net.DialTimeout("tcp", dest, 2*time.Second)
	if err != nil {
		return
	}
	defer up.Close()
	_ = c.SetDeadline(time.Time{})
	if delayHeader {
		go io.Copy(up, c)
		buf := make([]byte, 32*1024)
		n, rerr := up.Read(buf)
		if n > 0 {
			if _, err := c.Write([]byte{0, 0}); err != nil {
				return
			}
			if _, err := c.Write(buf[:n]); err != nil {
				return
			}
		}
		if rerr != nil {
			return
		}
		io.Copy(c, up)
		return
	}
	if _, err := c.Write([]byte{0, 0}); err != nil {
		return
	}
	go io.Copy(up, c)
	io.Copy(c, up)
}

func socksOutbound(id, addr, via string) OutboundSpec {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		panic(err)
	}
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	settings, err := json.Marshal(map[string]any{"address": host, "port": port, "via_outbound": via})
	if err != nil {
		panic(err)
	}
	return OutboundSpec{ID: id, Name: id, Protocol: "socks", Enabled: true, SettingsJSON: string(settings)}
}

func socksAuthOutbound(id, addr, via string) OutboundSpec {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		panic(err)
	}
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	item := map[string]any{"address": host, "port": port, "username": "audit-user", "password": "audit-password"}
	if via != "" {
		item["via_outbound"] = via
	}
	settings, err := json.Marshal(item)
	if err != nil {
		panic(err)
	}
	return OutboundSpec{ID: id, Name: id, Protocol: "socks", Enabled: true, SettingsJSON: string(settings)}
}

func startWireTap(t *testing.T, target string) (net.Listener, chan []byte) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hits := make(chan []byte, 8)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(8 * time.Second))
				up, err := net.DialTimeout("tcp", target, 2*time.Second)
				if err != nil {
					return
				}
				defer up.Close()
				buf := make([]byte, 64)
				n, rerr := c.Read(buf)
				if n > 0 {
					select {
					case hits <- append([]byte(nil), buf[:n]...):
					default:
					}
					_, _ = up.Write(buf[:n])
				}
				if rerr != nil {
					return
				}
				_ = c.SetDeadline(time.Time{})
				go io.Copy(up, c)
				io.Copy(c, up)
			}(c)
		}
	}()
	return ln, hits
}

func startAuthSocksRelay(t *testing.T) (net.Listener, chan string, chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hits := make(chan string, 32)
	auths := make(chan string, 32)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveAuthSocksRelay(c, hits, auths)
		}
	}()
	return ln, hits, auths
}

func serveAuthSocksRelay(c net.Conn, hits, auths chan string) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(8 * time.Second))
	head := make([]byte, 2)
	if _, err := io.ReadFull(c, head); err != nil {
		return
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	offered := false
	for _, m := range methods {
		if m == 2 {
			offered = true
			break
		}
	}
	if !offered {
		select {
		case auths <- "no_password_method":
		default:
		}
		_, _ = c.Write([]byte{5, 255})
		return
	}
	if _, err := c.Write([]byte{5, 2}); err != nil {
		return
	}
	if _, err := io.ReadFull(c, head); err != nil {
		return
	}
	user := make([]byte, int(head[1]))
	if _, err := io.ReadFull(c, user); err != nil {
		return
	}
	plen := make([]byte, 1)
	if _, err := io.ReadFull(c, plen); err != nil {
		return
	}
	pass := make([]byte, int(plen[0]))
	if _, err := io.ReadFull(c, pass); err != nil {
		return
	}
	select {
	case auths <- "username=" + string(user):
	default:
	}
	if string(user) != "audit-user" || string(pass) != "audit-password" {
		_, _ = c.Write([]byte{1, 1})
		return
	}
	if _, err := c.Write([]byte{1, 0}); err != nil {
		return
	}
	serveSocksConnect(c, hits)
}

func serveSocksConnect(c net.Conn, hits chan string) {
	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil {
		return
	}
	var host string
	switch req[3] {
	case 1:
		b := make([]byte, 4)
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case 3:
		n := make([]byte, 1)
		if _, err := io.ReadFull(c, n); err != nil {
			return
		}
		b := make([]byte, int(n[0]))
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		host = string(b)
	case 4:
		b := make([]byte, 16)
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		host = net.IP(b).String()
	default:
		return
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(c, pb); err != nil {
		return
	}
	dest := net.JoinHostPort(host, fmt.Sprint(int(pb[0])*256+int(pb[1])))
	select {
	case hits <- dest:
	default:
	}
	up, err := net.DialTimeout("tcp", dest, 2*time.Second)
	if err != nil {
		return
	}
	defer up.Close()
	if _, err := c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}); err != nil {
		return
	}
	_ = c.SetDeadline(time.Time{})
	go io.Copy(up, c)
	io.Copy(c, up)
}

func startSocksRelay(t *testing.T) (net.Listener, chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hits := make(chan string, 32)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveSocksRelay(c, hits)
		}
	}()
	return ln, hits
}

func serveSocksRelay(c net.Conn, hits chan string) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(8 * time.Second))
	head := make([]byte, 2)
	if _, err := io.ReadFull(c, head); err != nil {
		return
	}
	if _, err := io.ReadFull(c, make([]byte, int(head[1]))); err != nil {
		return
	}
	if _, err := c.Write([]byte{5, 0}); err != nil {
		return
	}
	serveSocksConnect(c, hits)
}

func drainHits(ch chan string) []string {
	var out []string
	for {
		select {
		case s := <-ch:
			out = append(out, s)
		default:
			return out
		}
	}
}

func containsHost(dests []string, want string) bool {
	for _, d := range dests {
		if d == want {
			return true
		}
	}
	return false
}

func setForwarding(t *testing.T, core Core, obs []OutboundSpec, routes []RouteSpec) {
	t.Helper()
	fw, ok := core.(interface {
		SetForwarding([]OutboundSpec, []RouteSpec)
	})
	if !ok {
		t.Fatal("SetForwarding missing")
	}
	fw.SetForwarding(obs, routes)
}

func TestXrayRealitySOCKSMixedMeter(t *testing.T) {
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
	core := NewXray()
	defer core.Stop()
	if err := core.ApplyUsers([]UserSpec{{ID: "u1", UUID: vlessAlice, Password: "pw"}}); err != nil {
		t.Fatal(err)
	}
	rPort, sPort := freePort(t), freePort(t)
	if err := core.Start(context.Background(), []InboundSpec{
		{ID: "reality", Core: "xray", Listen: "127.0.0.1", Port: rPort, Protocol: "vless", StreamJSON: string(stream)},
		{ID: "socks", Core: "xray", Listen: "127.0.0.1", Port: sPort, Protocol: "socks"},
	}); err != nil {
		t.Fatal(err)
	}
	waitProxy(t, fmt.Sprintf("127.0.0.1:%d", rPort))
	waitProxy(t, fmt.Sprintf("127.0.0.1:%d", sPort))
	cli, a, err := xrayDialRetry(rPort, vlessAlice, "", "reality", pub, "", echo.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	defer a.Close()
	if !echoConn(a, make([]byte, 20)) {
		t.Fatal("reality echo")
	}
	b, err := socksTry(fmt.Sprintf("127.0.0.1:%d", sPort), vlessAlice, "pw", echo.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if !echoConn(b, make([]byte, 10)) {
		t.Fatal("socks echo")
	}
	first := core.TakeSnapshots()
	if total := totalUser(first, "u1"); total != 62 {
		t.Fatalf("mixed snapshot %d %+v", total, first)
	}
	core.AcknowledgeUsage()
	if idle := core.TakeSnapshots(); totalUser(idle, "u1") != 0 {
		t.Fatalf("idle %+v", idle)
	}
}

func srcNAT(t *testing.T, dest, srcIP string) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			client, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				d := &net.Dialer{Timeout: 2 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(srcIP)}}
				backend, err := d.Dial("tcp", dest)
				if err != nil {
					return
				}
				defer backend.Close()
				go func() {
					_, _ = io.Copy(backend, c)
					_ = backend.Close()
				}()
				_, _ = io.Copy(c, backend)
			}(client)
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

func xrayDialAs(t *testing.T, port int, id, flow, security, pub, pin, target, srcIP string) (*xraycore.Instance, net.Conn, error) {
	t.Helper()
	relay, stop := srcNAT(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), srcIP)
	host, portStr, err := net.SplitHostPort(relay)
	if err != nil {
		stop()
		return nil, nil, err
	}
	_ = host
	rport, err := strconv.Atoi(portStr)
	if err != nil {
		stop()
		return nil, nil, err
	}
	cli, conn, err := xrayDial(rport, id, flow, security, pub, pin, target)
	if err != nil {
		stop()
		return nil, nil, err
	}
	return cli, &stopConn{Conn: conn, stop: stop}, nil
}

type stopConn struct {
	net.Conn
	stop func()
}

func (c *stopConn) Close() error {
	err := c.Conn.Close()
	if c.stop != nil {
		c.stop()
	}
	return err
}

func xrayDialRetry(port int, id, flow, security, pub, pin, target string) (*xraycore.Instance, net.Conn, error) {
	cli, conn, err := xrayDial(port, id, flow, security, pub, pin, target)
	if err == nil {
		return cli, conn, nil
	}
	return xrayDial(port, id, flow, security, pub, pin, target)
}

func xrayDial(port int, id, flow, security, pub, pin, target string) (*xraycore.Instance, net.Conn, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, nil, err
	}
	socksPort := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	stream := map[string]any{"network": "tcp", "security": security}
	if security == "tls" {
		tlsSettings := map[string]any{"serverName": "audit.test"}
		if pin != "" {
			tlsSettings["pinnedPeerCertSha256"] = pin
		}
		stream["tlsSettings"] = tlsSettings
	} else {
		stream["realitySettings"] = map[string]any{
			"serverName": "audit.test", "fingerprint": "chrome", "publicKey": pub, "shortId": "abcd", "spiderX": "/",
		}
	}
	u := map[string]any{"id": id, "encryption": "none"}
	if flow != "" {
		u["flow"] = flow
	}
	cfg := map[string]any{
		"log": map[string]any{"loglevel": "error"},
		"inbounds": []any{map[string]any{
			"listen": "127.0.0.1", "port": socksPort, "protocol": "socks",
			"settings": map[string]any{"auth": "noauth", "udp": false},
		}},
		"outbounds": []any{map[string]any{
			"protocol": "vless",
			"settings": map[string]any{"vnext": []any{map[string]any{
				"address": "127.0.0.1", "port": port, "users": []any{u},
			}}},
			"streamSettings": stream,
		}},
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		return nil, nil, err
	}
	inst, err := xraycore.StartInstance("json", raw)
	if err != nil {
		return nil, nil, err
	}
	restoreXraySystemDialer()
	d, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort), nil, &net.Dialer{Timeout: 2 * time.Second})
	if err != nil {
		inst.Close()
		return nil, nil, err
	}
	conn, err := d.Dial("tcp", target)
	if err != nil {
		inst.Close()
		return nil, nil, err
	}
	if flow != "" {
		_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
		inner := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
		if err := inner.Handshake(); err != nil {
			conn.Close()
			inst.Close()
			return nil, nil, err
		}
		conn = inner
	}
	if !echoConn(conn, []byte{1}) {
		conn.Close()
		inst.Close()
		return nil, nil, fmt.Errorf("initial echo")
	}
	_ = conn.SetDeadline(time.Time{})
	return inst, conn, nil
}

func auditCerts(t *testing.T) (string, string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(6),
		Subject:      pkix.Name{CommonName: "audit.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"audit.test"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	pin := fmt.Sprintf("%x", sha256.Sum256(der))
	return certPEM, keyPEM, pin
}

func startTLSEcho(t *testing.T, certPEM, keyPEM string) net.Listener {
	t.Helper()
	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { defer c.Close(); io.Copy(c, c) }(c)
		}
	}()
	return ln
}

func startTLS13Decoy(t *testing.T, certPEM, keyPEM string) net.Listener {
	t.Helper()
	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates:     []tls.Certificate{cert},
		NextProtos:       []string{"h2", "http/1.1"},
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519},
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(8 * time.Second))
				if tc, ok := c.(*tls.Conn); ok {
					if tc.Handshake() != nil {
						return
					}
				}
				io.Copy(io.Discard, c)
			}(c)
		}
	}()
	return ln
}

func realityKeys(t *testing.T) (priv, pub string) {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(key.Bytes()), base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
}
