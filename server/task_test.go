package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

var testTargets = []struct {
	target string
}{
	{"v6-sh-cm.oojj.de"},
	{"2409:8c1e:8f80:2:6a::"},
	{"[2409:8c1e:8f80:2:6a::]"},
	{"[2409:8c1e:8f80:2:6a::]:80"},
	{"v4-sh-cm.oojj.de"},
	{"117.185.125.154"},
	{"117.185.125.154:80"},
}

func requireNetworkIntegration(t *testing.T) {
	t.Helper()
	if os.Getenv("LITE_AGENT_INTEGRATION") != "1" {
		t.Skip("set LITE_AGENT_INTEGRATION=1 to run public network tests")
	}
}

func TestLatencyMillisecondsKeepsFraction(t *testing.T) {
	if got := latencyMilliseconds(1500 * time.Microsecond); got != 1.5 {
		t.Fatalf("latency = %v, want 1.5", got)
	}
	if got := latencyMilliseconds(17 * time.Millisecond); got != 17 {
		t.Fatalf("latency = %v, want 17", got)
	}
}

func TestICMPPing(t *testing.T) {
	requireNetworkIntegration(t)
	timeout := 3 * time.Second
	for _, tt := range testTargets {
		t.Run(tt.target, func(t *testing.T) {
			latency, err := icmpPing(tt.target, timeout)
			if latency < -1 {
				t.Errorf("ICMP ping %s: invalid latency %v", tt.target, latency)
			}
			if err != nil {
				t.Errorf("ICMP ping %s error: %v", tt.target, err)
			}
		})
	}
}

func TestTCPPing(t *testing.T) {
	requireNetworkIntegration(t)
	timeout := 3 * time.Second
	for _, tt := range testTargets {
		t.Run(tt.target, func(t *testing.T) {
			latency, err := tcpPing(tt.target, timeout)
			if latency < -1 {
				t.Errorf("TCP ping %s: invalid latency %v", tt.target, latency)
			}
			if err != nil {
				t.Errorf("TCP ping %s error: %v", tt.target, err)
			}
		})
	}
}

func TestHTTPPing(t *testing.T) {
	requireNetworkIntegration(t)
	timeout := 3 * time.Second
	for _, tt := range testTargets {
		t.Run(tt.target, func(t *testing.T) {
			latency, err := httpPing(tt.target, timeout)
			if latency < -1 {
				t.Errorf("HTTP ping %s: invalid latency %v", tt.target, latency)
			}
			if err != nil {
				t.Errorf("HTTP ping %s error: %v", tt.target, err)
			}
		})
	}
}

func TestHTTPPingSendsBrowserHeaders(t *testing.T) {
	var gotUA, gotAccept string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		gotAccept = r.Header.Get("Accept")
		if gotUA == "" || strings.HasPrefix(gotUA, "Go-http-client/") {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	latency, err := httpPing(server.URL+"/favicon.ico", time.Second)
	if err != nil {
		t.Fatalf("httpPing() error = %v", err)
	}
	if latency < 0 {
		t.Fatalf("httpPing() latency = %v", latency)
	}
	if gotUA != httpPingUserAgent {
		t.Fatalf("User-Agent = %q, want %q", gotUA, httpPingUserAgent)
	}
	if gotAccept != "*/*" {
		t.Fatalf("Accept = %q, want */*", gotAccept)
	}
}

func TestHTTPPingKeepsNonOKStatusAsFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer server.Close()

	_, err := httpPing(server.URL, time.Second)
	if err == nil {
		t.Fatal("httpPing() succeeded on 403, want failure")
	}
}
