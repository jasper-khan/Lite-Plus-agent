package coreadapter

import (
	"context"
	"encoding/json"
	"net"
	"testing"
)

func TestSingBoxTCPDualWildcardStarts(t *testing.T) {
	for _, tc := range []struct {
		protocol string
		security string
	}{
		{"anytls", "tls"},
		{"anytls", "reality"},
		{"vless", "reality"},
	} {
		t.Run(tc.protocol+"/"+tc.security, func(t *testing.T) {
			testSingBoxDualWildcardStart(t, tc.protocol, tc.security)
		})
	}
}

func testSingBoxDualWildcardStart(t *testing.T, protocol, security string) {
	t.Helper()
	probe, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 listen unavailable: %v", err)
	}
	_ = probe.Close()

	in := InboundSpec{
		ID: "dual", Core: "sing-box", Protocol: protocol,
		Listen: "0.0.0.0,::", Port: freePort(t),
		SettingsJSON: `{"stack":"dual"}`,
	}
	stream := map[string]any{"network": "tcp", "security": security}
	if security == "reality" {
		priv, _ := realityKeys(t)
		stream["realitySettings"] = map[string]any{
			"dest": "127.0.0.1:9", "serverNames": []string{"audit.test"},
			"privateKey": priv, "shortIds": []string{"abcd"},
		}
	} else {
		in.CertPEM, in.KeyPEM = testPEMs(t)
	}
	raw, err := json.Marshal(stream)
	if err != nil {
		t.Fatal(err)
	}
	in.StreamJSON = string(raw)

	core := NewSingBox()
	t.Cleanup(func() { _ = core.Stop() })
	if err := core.ApplyUsers([]UserSpec{{ID: "u1", UUID: vlessAlice, Password: "test-password"}}); err != nil {
		t.Fatal(err)
	}
	if err := core.Start(context.Background(), []InboundSpec{in}); err != nil {
		t.Fatalf("dual-stack %s/%s failed to start: %v", protocol, security, err)
	}
}
