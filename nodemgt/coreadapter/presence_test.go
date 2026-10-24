package coreadapter

import (
	"testing"
	"time"

	"github.com/nuomiiiii/lite-agent/nodemgt/sessions"
)

func TestPolicyPresenceReportsOnlyLiveIPs(t *testing.T) {
	p := &policyEngine{
		sess: sessions.New(),
		seen: map[string]map[string]time.Time{},
	}
	p.noteIP("u1", "203.0.113.10")
	rows := p.presence()
	if len(rows) != 1 || rows[0].UserID != "u1" {
		t.Fatalf("historical user %+v", rows)
	}
	if rows[0].Online || len(rows[0].IPs) != 0 {
		t.Fatalf("history must not stay online %+v", rows[0])
	}
	p.trackSession(&sessions.Session{ID: "s1", UserID: "u1", IP: "203.0.113.10"})
	rows = p.presence()
	if len(rows) != 1 || !rows[0].Online || len(rows[0].IPs) != 1 || rows[0].IPs[0].IP != "203.0.113.10" {
		t.Fatalf("live ip %+v", rows)
	}
	p.sess.Remove("s1")
	rows = p.presence()
	if len(rows) != 1 || rows[0].Online || len(rows[0].IPs) != 0 {
		t.Fatalf("disconnect must drop ip %+v", rows)
	}
	if len(p.presence()) != 0 {
		t.Fatalf("offline user should leave presence after prune %+v", p.presence())
	}
}
