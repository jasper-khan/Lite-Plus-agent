package coreadapter

import "testing"

func TestInboundSpecsEqualIgnoresTLSPointer(t *testing.T) {
	a := []InboundSpec{{ID: "in", Listen: "0.0.0.0", Port: 443, Protocol: "vless", SettingsJSON: `{"stack":"dual"}`}}
	b := []InboundSpec{{ID: "in", Listen: "0.0.0.0", Port: 443, Protocol: "vless", SettingsJSON: `{"stack":"dual"}`}}
	if !inboundSpecsEqual(a, b) {
		t.Fatal("equal specs compared unequal")
	}
	b[0].Port = 8443
	if inboundSpecsEqual(a, b) {
		t.Fatal("port change compared equal")
	}
}

func TestUserAuthEqualIgnoresQuotaAndRate(t *testing.T) {
	a := []UserSpec{{ID: "u1", UUID: "alice", Password: "pw", QuotaBytes: 10, RateLimitBps: 1, DeviceLimit: 2}}
	b := []UserSpec{{ID: "u1", UUID: "alice", Password: "pw", QuotaBytes: 99, RateLimitBps: 8, DeviceLimit: 0}}
	if !userAuthEqual(a, b) {
		t.Fatal("quota/rate/device should not force core restart")
	}
	b[0].UUID = "bob"
	if userAuthEqual(a, b) {
		t.Fatal("uuid change compared equal")
	}
}

func TestCoreShouldRestartSkipsUnchangedRunningCore(t *testing.T) {
	in := []InboundSpec{{ID: "in", Port: 1, Protocol: "socks"}}
	users := []UserSpec{{ID: "u1", UUID: "alice", Password: "pw"}}
	if coreShouldRestart(true, in, in, users, users, nil, nil, nil, nil) {
		t.Fatal("running unchanged core should not restart")
	}
	if !coreShouldRestart(false, in, in, users, users, nil, nil, nil, nil) {
		t.Fatal("unstarted inbound still needs first start")
	}
	next := []InboundSpec{{ID: "in", Port: 2, Protocol: "socks"}}
	if !coreShouldRestart(true, next, in, users, users, nil, nil, nil, nil) {
		t.Fatal("changed inbound should restart")
	}
}
