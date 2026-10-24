package coreadapter

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseGeoMatchSplitsGeoAndPlainTokens(t *testing.T) {
	m := parseGeoMatch(
		[]string{"geosite:cn", "geosite:geolocation-!cn", "example.com"},
		[]string{"geoip:private", "geoip:CN", "10.0.0.0/8"},
	)
	if strings.Join(m.Geosite, ",") != "cn,geolocation-!cn" {
		t.Fatalf("geosite = %#v", m.Geosite)
	}
	if strings.Join(m.Domains, ",") != "example.com" {
		t.Fatalf("domains = %#v", m.Domains)
	}
	if !m.Private {
		t.Fatal("expected geoip:private")
	}
	if strings.Join(m.GeoIP, ",") != "cn" {
		t.Fatalf("geoip = %#v", m.GeoIP)
	}
	if strings.Join(m.CIDRs, ",") != "10.0.0.0/8" {
		t.Fatalf("cidrs = %#v", m.CIDRs)
	}
}

func TestSingBoxGeoRoutesUseRuleSets(t *testing.T) {
	SetGeoAssetDir(t.TempDir())
	t.Cleanup(func() { SetGeoAssetDir("") })
	c := newSingBoxCore()
	c.outbounds = []OutboundSpec{{ID: "ob1", Name: "proxy", Protocol: "vless", Enabled: true}}
	c.routes = []RouteSpec{{
		ID: "r1", Name: "cn", Priority: 0, Enabled: true,
		RuleJSON: `{"outbound_id":"ob1","domain":"geosite:cn, geosite:geolocation-!cn","ip":"geoip:private, geoip:cn"}`,
	}}
	raw, err := c.configJSON()
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, part := range []string{
		`"tag":"geosite-cn"`,
		`"tag":"geosite-geolocation-!cn"`,
		`"tag":"geoip-cn"`,
		`"type":"local"`,
		`"ip_is_private":true`,
		`"mode":"or"`,
		`"mode":"and"`,
	} {
		if !strings.Contains(text, part) {
			t.Fatalf("missing %s in %s", part, text)
		}
	}
	if strings.Contains(text, `"ip_cidr":["geoip:`) {
		t.Fatal("geoip tokens must not stay in ip_cidr")
	}
	if strings.Contains(text, `"domain":["geosite:`) {
		t.Fatal("geosite tokens must not stay in domain")
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
}

func TestSingBoxPlainCIDRUnchanged(t *testing.T) {
	c := newSingBoxCore()
	c.outbounds = []OutboundSpec{{ID: "ob1", Name: "direct", Protocol: "direct", Enabled: true}}
	c.routes = []RouteSpec{{
		ID: "r1", Enabled: true,
		RuleJSON: `{"outbound_id":"ob1","domain":"example.com","ip":"10.0.0.0/8"}`,
	}}
	raw, err := c.configJSON()
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.Contains(text, `"domain":["example.com"]`) {
		t.Fatalf("plain domain missing: %s", text)
	}
	if !strings.Contains(text, `"ip_cidr":["10.0.0.0/8"]`) {
		t.Fatalf("plain cidr missing: %s", text)
	}
	if strings.Contains(text, `"rule_set"`) {
		t.Fatal("plain routes should not add rule_set")
	}
}
