package coreadapter

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestXrayConfigAppliesSniffingStreamAndRoutes(t *testing.T) {
	c := newXrayCore()
	c.users = []UserSpec{{ID: "u1", UUID: vlessAlice, Flow: "xtls-rprx-vision"}}
	c.inbounds = []InboundSpec{{
		ID:           "in1",
		Listen:       "127.0.0.1",
		Port:         443,
		Protocol:     "vless",
		StreamJSON:   `{"network":"ws","security":"none","wsSettings":{"path":"/vless","host":"cdn.example.com"}}`,
		SettingsJSON: `{"sniffing":true,"dest_override":"http,tls","route_only":true}`,
	}}
	c.outbounds = []OutboundSpec{{
		ID: "ob1", Name: "block", Protocol: "blackhole", Enabled: true,
	}}
	c.routes = []RouteSpec{{
		ID: "r1", Name: "ads", Priority: 0, Enabled: true,
		RuleJSON: `{"outbound_id":"ob1","domain":"geosite:category-ads-all","protocol":"http,tls"}`,
	}}
	raw, err := c.configJSON()
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, part := range []string{
		`"destOverride"`,
		`"routeOnly":true`,
		`"xtls-rprx-vision"`,
		`"geosite:category-ads-all"`,
		`"outboundTag":"block"`,
		`"protocol":"blackhole"`,
	} {
		if !strings.Contains(text, part) {
			t.Fatalf("missing %s in %s", part, text)
		}
	}
	if strings.Contains(text, `"path":"/vless"`) {
		t.Fatal("identity front should keep websocket off the core inbound")
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
}

func TestSingBoxRealityUsesStringServerName(t *testing.T) {
	c := newSingBoxCore()
	c.users = []UserSpec{{ID: "u1", UUID: vlessAlice, Password: "audit-pass"}}
	c.inbounds = []InboundSpec{{
		ID:         "schema",
		Listen:     "127.0.0.1",
		Port:       8443,
		Protocol:   "vless",
		StreamJSON: `{"network":"tcp","security":"reality","realitySettings":{"dest":"127.0.0.1:9","serverNames":["audit.test"],"privateKey":"dGVzdA","shortIds":["abcd"]}}`,
	}}
	raw, err := c.configJSON()
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	inbounds, _ := cfg["inbounds"].([]any)
	if len(inbounds) == 0 {
		t.Fatalf("no inbounds: %s", raw)
	}
	in, _ := inbounds[0].(map[string]any)
	tls, _ := in["tls"].(map[string]any)
	name, ok := tls["server_name"].(string)
	if !ok || name != "audit.test" {
		t.Fatalf("server_name=%v %s", tls["server_name"], raw)
	}
	reality, _ := tls["reality"].(map[string]any)
	hs, _ := reality["handshake"].(map[string]any)
	if hs["server"] != "127.0.0.1" {
		t.Fatalf("handshake server=%v", hs["server"])
	}
	port, _ := hs["server_port"].(float64)
	if int(port) != 9 {
		t.Fatalf("handshake port=%v", hs["server_port"])
	}
}

func TestXrayUserFlowVisionKeepsCoreTLS(t *testing.T) {
	c := newXrayCore()
	cert, key := testPEMs(t)
	c.users = []UserSpec{{ID: "u1", UUID: vlessAlice, Password: "pw", Flow: "xtls-rprx-vision"}}
	c.inbounds = []InboundSpec{{
		ID: "tls", Protocol: "vless", Listen: "127.0.0.1", Port: 8443,
		CertPEM: cert, KeyPEM: key,
	}}
	raw, err := c.configJSON()
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, part := range []string{`"security":"tls"`, `"xtls-rprx-vision"`, `"nodemgt-policy-u1"`} {
		if !strings.Contains(text, part) {
			t.Fatalf("missing %s in %s", part, text)
		}
	}
}

func TestXrayBusinessRouteKeepsPolicyDialer(t *testing.T) {
	c := newXrayCore()
	c.users = []UserSpec{{ID: "u1", UUID: vlessAlice, Password: "pw"}}
	c.inbounds = []InboundSpec{{
		ID: "reality", Protocol: "vless", Listen: "127.0.0.1", Port: 443,
		StreamJSON: `{"network":"tcp","security":"reality","realitySettings":{"dest":"127.0.0.1:9","serverNames":["audit.test"],"privateKey":"dGVzdA","shortIds":["abcd"]}}`,
	}}
	c.outbounds = []OutboundSpec{{ID: "audit-direct", Name: "audit-direct", Protocol: "freedom", Enabled: true}}
	c.routes = []RouteSpec{{ID: "business-route", Enabled: true, Priority: 1, RuleJSON: `{"inbound_id":"reality","outbound_id":"audit-direct"}`}}
	raw, err := c.configJSON()
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, part := range []string{`"nodemgt-policy-u1"`, `"outboundTag":"audit-direct"`} {
		if !strings.Contains(text, part) {
			t.Fatalf("missing %s in %s", part, text)
		}
	}
	if !strings.Contains(text, `"user"`) {
		t.Fatal("missing per-user policy route")
	}
}

func TestXraySocksViaKeepsOriginalChain(t *testing.T) {
	c := newXrayCore()
	c.users = []UserSpec{{ID: "u1", UUID: vlessAlice, Password: "pw"}}
	c.inbounds = []InboundSpec{{
		ID: "reality", Protocol: "vless", Listen: "127.0.0.1", Port: 443,
		StreamJSON: `{"network":"tcp","security":"reality","realitySettings":{"dest":"127.0.0.1:9","serverNames":["audit.test"],"privateKey":"dGVzdA","shortIds":["abcd"]}}`,
	}}
	c.outbounds = []OutboundSpec{
		{ID: "audit-B", Name: "audit-B", Protocol: "socks", Enabled: true, SettingsJSON: `{"address":"127.0.0.1","port":1081}`},
		{ID: "audit-A", Name: "audit-A", Protocol: "socks", Enabled: true, SettingsJSON: `{"address":"127.0.0.1","port":1080,"via_outbound":"audit-B"}`},
	}
	c.routes = []RouteSpec{{ID: "business-route", Enabled: true, Priority: 1, RuleJSON: `{"inbound_id":"reality","outbound_id":"audit-A"}`}}
	raw, err := c.configJSON()
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if strings.Contains(text, `"nodemgt-via-`) {
		t.Fatalf("policy cloned socks outbound and overwrote via: %s", text)
	}
	for _, part := range []string{`"nodemgt-policy-u1-audit-A"`, `"dialerProxy":"audit-B"`, `"outboundTag":"audit-A"`} {
		if !strings.Contains(text, part) {
			t.Fatalf("missing %s in %s", part, text)
		}
	}
}

func TestSingBoxSocksViaKeepsPolicyExit(t *testing.T) {
	c := newSingBoxCore()
	c.users = []UserSpec{{ID: "u1", UUID: vlessAlice, Password: "pw"}}
	c.inbounds = []InboundSpec{{
		ID: "reality", Protocol: "vless", Listen: "127.0.0.1", Port: 443,
		StreamJSON: `{"network":"tcp","security":"reality","realitySettings":{"dest":"127.0.0.1:9","serverNames":["audit.test"],"privateKey":"dGVzdA","shortIds":["abcd"]}}`,
	}}
	c.outbounds = []OutboundSpec{
		{ID: "audit-exit", Name: "audit-exit", Protocol: "socks", Enabled: true, SettingsJSON: `{"address":"127.0.0.1","port":1080}`},
	}
	c.routes = []RouteSpec{{ID: "business-route", Enabled: true, Priority: 1, RuleJSON: `{"inbound_id":"reality","outbound_id":"audit-exit"}`}}
	raw, err := c.configJSON()
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if strings.Contains(text, `"detour"`) {
		t.Fatalf("policy set detour on socks outbound: %s", text)
	}
	if !strings.Contains(text, `"nodemgt-policy-u1-audit-exit"`) {
		t.Fatalf("missing policy socks exit in %s", text)
	}
}

func TestXrayVLESSViaKeepsPolicyExit(t *testing.T) {
	c := newXrayCore()
	c.users = []UserSpec{{ID: "u1", UUID: vlessAlice, Password: "pw"}}
	c.inbounds = []InboundSpec{{
		ID: "reality", Protocol: "vless", Listen: "127.0.0.1", Port: 443,
		StreamJSON: `{"network":"tcp","security":"reality","realitySettings":{"dest":"127.0.0.1:9","serverNames":["audit.test"],"privateKey":"dGVzdA","shortIds":["abcd"]}}`,
	}}
	c.outbounds = []OutboundSpec{
		{ID: "audit-B", Name: "audit-B", Protocol: "socks", Enabled: true, SettingsJSON: `{"address":"127.0.0.1","port":1081}`},
		{ID: "audit-A", Name: "audit-A", Protocol: "vless", Enabled: true, SettingsJSON: `{"address":"127.0.0.1","port":1080,"uuid":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","via_outbound":"audit-B"}`},
	}
	c.routes = []RouteSpec{{ID: "business-route", Enabled: true, Priority: 1, RuleJSON: `{"inbound_id":"reality","outbound_id":"audit-A"}`}}
	raw, err := c.configJSON()
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if strings.Contains(text, `"nodemgt-via-`) {
		t.Fatalf("policy cloned vless outbound and skipped hop A: %s", text)
	}
	if !strings.Contains(text, `"nodemgt-policy-u1-audit-A"`) {
		t.Fatalf("missing vless policy exit in %s", text)
	}
}

func TestXrayVLESSTLSKeepsPolicyExit(t *testing.T) {
	c := newXrayCore()
	c.users = []UserSpec{{ID: "u1", UUID: vlessAlice, Password: "pw"}}
	c.inbounds = []InboundSpec{{
		ID: "reality", Protocol: "vless", Listen: "127.0.0.1", Port: 443,
		StreamJSON: `{"network":"tcp","security":"reality","realitySettings":{"dest":"127.0.0.1:9","serverNames":["audit.test"],"privateKey":"dGVzdA","shortIds":["abcd"]}}`,
	}}
	c.outbounds = []OutboundSpec{{
		ID: "audit-exit", Name: "audit-exit", Protocol: "vless", Enabled: true,
		SettingsJSON: `{"address":"127.0.0.1","port":8443,"uuid":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","security":"tls","transport":"tcp","sni":"audit.test"}`,
	}}
	c.routes = []RouteSpec{{ID: "business-route", Enabled: true, Priority: 1, RuleJSON: `{"inbound_id":"reality","outbound_id":"audit-exit"}`}}
	raw, err := c.configJSON()
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if strings.Contains(text, `"nodemgt-via-`) {
		t.Fatalf("tls vless fell back to cloned outbound: %s", text)
	}
	if !strings.Contains(text, `"nodemgt-policy-u1-audit-exit"`) {
		t.Fatalf("missing tls vless policy exit in %s", text)
	}
}

func TestXrayGRPCUsesCoreDetour(t *testing.T) {
	c := newXrayCore()
	c.users = []UserSpec{{ID: "u1", UUID: vlessAlice, Password: "pw"}}
	c.inbounds = []InboundSpec{{
		ID: "reality", Protocol: "vless", Listen: "127.0.0.1", Port: 443,
		StreamJSON: `{"network":"tcp","security":"reality","realitySettings":{"dest":"127.0.0.1:9","serverNames":["audit.test"],"privateKey":"dGVzdA","shortIds":["abcd"]}}`,
	}}
	c.outbounds = []OutboundSpec{{
		ID: "audit-exit", Name: "audit-exit", Protocol: "vless", Enabled: true,
		SettingsJSON: `{"address":"127.0.0.1","port":8443,"uuid":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","transport":"grpc","security":"none","grpc_service":"audit"}`,
	}}
	c.routes = []RouteSpec{{ID: "business-route", Enabled: true, Priority: 1, RuleJSON: `{"inbound_id":"reality","outbound_id":"audit-exit"}`}}
	raw, err := c.configJSON()
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if strings.Contains(text, `"nodemgt-via-`) {
		t.Fatalf("grpc fell back to metered dialerProxy: %s", text)
	}
	for _, part := range []string{`"nodemgt-policy-u1-audit-exit"`, `"nodemgt-core-audit-exit"`, `"network":"grpc"`} {
		if !strings.Contains(text, part) {
			t.Fatalf("missing %s in %s", part, text)
		}
	}
}

func TestSingBoxGRPCMapsOutboundTransport(t *testing.T) {
	c := newSingBoxCore()
	c.users = []UserSpec{{ID: "u1", UUID: vlessAlice, Password: "pw"}}
	c.inbounds = []InboundSpec{{
		ID: "reality", Protocol: "vless", Listen: "127.0.0.1", Port: 443,
		StreamJSON: `{"network":"tcp","security":"reality","realitySettings":{"dest":"127.0.0.1:9","serverNames":["audit.test"],"privateKey":"dGVzdA","shortIds":["abcd"]}}`,
	}}
	c.outbounds = []OutboundSpec{{
		ID: "audit-exit", Name: "audit-exit", Protocol: "vless", Enabled: true,
		SettingsJSON: `{"address":"127.0.0.1","port":8443,"uuid":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","transport":"grpc","security":"none","grpc_service":"audit"}`,
	}}
	c.routes = []RouteSpec{{ID: "business-route", Enabled: true, Priority: 1, RuleJSON: `{"inbound_id":"reality","outbound_id":"audit-exit"}`}}
	raw, err := c.configJSON()
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if strings.Contains(text, `"nodemgt-via-`) {
		t.Fatalf("grpc fell back to cloned outbound: %s", text)
	}
	for _, part := range []string{`"nodemgt-policy-u1-audit-exit"`, `"nodemgt-core-audit-exit"`, `"type":"grpc"`, `"service_name":"audit"`} {
		if !strings.Contains(text, part) {
			t.Fatalf("missing %s in %s", part, text)
		}
	}
	for _, ob := range singBoxTypedOutbounds(t, raw, "vless") {
		if tls, _ := ob["tls"].(map[string]any); tls != nil {
			if enabled, _ := tls["enabled"].(bool); enabled {
				t.Fatalf("security=none still enabled tls on %v", ob["tag"])
			}
		}
	}
}

func TestSingBoxGRPCMapsOutboundTLS(t *testing.T) {
	c := newSingBoxCore()
	c.users = []UserSpec{{ID: "u1", UUID: vlessAlice, Password: "pw"}}
	c.inbounds = []InboundSpec{{
		ID: "reality", Protocol: "vless", Listen: "127.0.0.1", Port: 443,
		StreamJSON: `{"network":"tcp","security":"reality","realitySettings":{"dest":"127.0.0.1:9","serverNames":["audit.test"],"privateKey":"dGVzdA","shortIds":["abcd"]}}`,
	}}
	c.outbounds = []OutboundSpec{{
		ID: "audit-exit", Name: "audit-exit", Protocol: "vless", Enabled: true,
		SettingsJSON: `{"address":"127.0.0.1","port":8443,"uuid":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","transport":"grpc","security":"tls","sni":"audit.test","grpc_service":"audit"}`,
	}}
	c.routes = []RouteSpec{{ID: "business-route", Enabled: true, Priority: 1, RuleJSON: `{"inbound_id":"reality","outbound_id":"audit-exit"}`}}
	raw, err := c.configJSON()
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if strings.Contains(text, `"nodemgt-via-`) {
		t.Fatalf("tls grpc fell back to cloned outbound: %s", text)
	}
	found := 0
	for _, ob := range singBoxTypedOutbounds(t, raw, "vless") {
		tag, _ := ob["tag"].(string)
		if !strings.Contains(tag, "audit-exit") {
			continue
		}
		found++
		tls, _ := ob["tls"].(map[string]any)
		if tls == nil {
			t.Fatalf("missing tls on %s: %v", tag, ob)
		}
		if enabled, _ := tls["enabled"].(bool); !enabled {
			t.Fatalf("tls.enabled=%v on %s", tls["enabled"], tag)
		}
		if tls["server_name"] != "audit.test" {
			t.Fatalf("tls.server_name=%v on %s", tls["server_name"], tag)
		}
		if insecure, ok := tls["insecure"]; ok && insecure == true {
			t.Fatalf("tls verification disabled on %s", tag)
		}
		transport, _ := ob["transport"].(map[string]any)
		if transport["type"] != "grpc" || transport["service_name"] != "audit" {
			t.Fatalf("transport=%v on %s", transport, tag)
		}
	}
	if found == 0 {
		t.Fatalf("missing grpc vless outbound in %s", text)
	}
}

func TestSingBoxSOCKSMapsUsername(t *testing.T) {
	c := newSingBoxCore()
	c.outbounds = []OutboundSpec{
		{
			ID: "audit-socks", Name: "audit-socks", Protocol: "socks", Enabled: true,
			SettingsJSON: `{"address":"127.0.0.1","port":1080,"username":"audit-user","password":"audit-password"}`,
		},
		{
			ID: "audit-open", Name: "audit-open", Protocol: "socks", Enabled: true,
			SettingsJSON: `{"address":"127.0.0.1","port":1081,"password":"ignored-without-user"}`,
		},
	}
	raw, err := c.configJSON()
	if err != nil {
		t.Fatal(err)
	}
	foundAuth, foundOpen := false, false
	for _, ob := range singBoxTypedOutbounds(t, raw, "socks") {
		switch ob["tag"] {
		case "audit-socks":
			foundAuth = true
			if ob["username"] != "audit-user" || ob["password"] != "audit-password" {
				t.Fatalf("auth socks %v", ob)
			}
		case "audit-open":
			foundOpen = true
			if _, ok := ob["username"]; ok {
				t.Fatalf("empty username still mapped on %v", ob)
			}
		}
	}
	if !foundAuth || !foundOpen {
		t.Fatalf("missing socks outbounds in %s", raw)
	}
}

func singBoxTypedOutbounds(t *testing.T, raw []byte, typ string) []map[string]any {
	t.Helper()
	var cfg struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	for _, ob := range cfg.Outbounds {
		if ob["type"] == typ {
			out = append(out, ob)
		}
	}
	return out
}

func TestXrayVisionKeepsCoreTLSAndPolicyExit(t *testing.T) {
	c := newXrayCore()
	cert, key := testPEMs(t)
	c.users = []UserSpec{{ID: "u1", UUID: vlessAlice, Password: "pw"}}
	c.inbounds = []InboundSpec{{
		ID: "tls", Protocol: "vless", Listen: "127.0.0.1", Port: 8443,
		CertPEM: cert, KeyPEM: key, Flow: "xtls-rprx-vision",
	}}
	raw, err := c.configJSON()
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, part := range []string{`"security":"tls"`, `"xtls-rprx-vision"`, `"nodemgt-policy-u1"`} {
		if !strings.Contains(text, part) {
			t.Fatalf("missing %s in %s", part, text)
		}
	}
}

func TestXrayOutboundAppliesRealityPublicKey(t *testing.T) {
	c := newXrayCore()
	c.outbounds = []OutboundSpec{{
		ID: "ob1", Name: "relay", Protocol: "vless", Enabled: true,
		SettingsJSON: `{"address":"example.com","port":443,"uuid":"11111111-1111-1111-1111-111111111111","flow":"xtls-rprx-vision","transport":"tcp","security":"reality","sni":"www.microsoft.com","fingerprint":"chrome","reality_public_key":"pubkey","reality_short_id":"abcd","spider_x":"/"}`,
	}}
	raw, err := c.configJSON()
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, part := range []string{
		`"security":"reality"`,
		`"publicKey":"pubkey"`,
		`"shortId":"abcd"`,
		`"spiderX":"/"`,
		`"serverName":"www.microsoft.com"`,
	} {
		if !strings.Contains(text, part) {
			t.Fatalf("missing %s in %s", part, text)
		}
	}
}
