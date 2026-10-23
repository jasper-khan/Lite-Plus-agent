package quota

import "testing"

func TestAddStopsAtLimit(t *testing.T) {
	l := New()
	l.Configure("u", 10, 0)
	if _, _, ok := l.Add("u", 4); !ok {
		t.Fatal("4")
	}
	if _, _, ok := l.Add("u", 7); ok {
		t.Fatal("should reject")
	}
	if l.Used("u") != 4 {
		t.Fatalf("used %d", l.Used("u"))
	}
	if l.Room("u") != 6 {
		t.Fatalf("room %d", l.Room("u"))
	}
}
