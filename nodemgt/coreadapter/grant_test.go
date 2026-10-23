package coreadapter

import (
	"testing"
	"time"
)

func TestUsersForInboundHonorsGrants(t *testing.T) {
	users := []UserSpec{
		{ID: "a", UUID: vlessAlice, InboundIDs: []string{"in-a"}},
		{ID: "b", UUID: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", InboundIDs: []string{"in-b"}},
		{ID: "c", UUID: "cccccccc-cccc-cccc-cccc-cccccccccccc"},
	}
	got := usersForInbound(users, "in-a")
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2 (granted + unspecified)", len(got))
	}
	if got[0].ID != "a" || got[1].ID != "c" {
		t.Fatalf("got %#v", got)
	}
	none := usersForInbound([]UserSpec{{ID: "d", UUID: vlessAlice, InboundIDs: []string{}}}, "in-a")
	if len(none) != 0 {
		t.Fatal("empty inbound_ids must not grant access")
	}
}

func TestVlessUUIDDoesNotFallBackToUserID(t *testing.T) {
	if got := vlessUUID(UserSpec{ID: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"}); got != "" {
		t.Fatalf("fallback uuid = %q", got)
	}
}

func TestUserLiveHonorsCredentialExpiry(t *testing.T) {
	past := time.Now().UTC().Add(-time.Second)
	if userLive(UserSpec{ID: "u", UUID: "alice", Password: "x", CredExpiresAt: &past}) {
		t.Fatal("expired credential still live")
	}
}
