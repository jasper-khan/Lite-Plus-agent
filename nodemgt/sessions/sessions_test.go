package sessions

import (
	"net"
	"testing"
)

func TestAddHidesPolicyExitLoopback(t *testing.T) {
	set := New()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	set.Add(&Session{ID: "s1", UserID: "u1", Conn: client, HideIP: true})
	if ips := set.LiveIPs()["u1"]; len(ips) != 0 {
		t.Fatalf("hidden session leaked IPs %v", ips)
	}
	set.Add(&Session{ID: "s2", UserID: "u1", Conn: client})
	found := false
	for _, ip := range set.LiveIPs()["u1"] {
		if ip == "127.0.0.1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("identity session should keep loopback when that is the peer: %v", set.LiveIPs())
	}
}
