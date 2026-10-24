package geostore

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnsureDownloadsDatAndRuleSets(t *testing.T) {
	var hits []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits = append(hits, r.URL.Path)
		w.Write([]byte(strings.Repeat("G", 200)))
	}))
	defer srv.Close()

	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	store.Client = srv.Client()
	store.MinDat = 8
	store.MinSRS = 8
	store.DatURLs = map[string][]string{
		"geoip.dat":   {srv.URL + "/geoip.dat"},
		"geosite.dat": {srv.URL + "/geosite.dat"},
	}
	store.SRSURLs = func(kind, code string) []string {
		return []string{srv.URL + "/" + RuleSetFile(kind, code)}
	}

	if err := store.Ensure(context.Background(), []string{"cn", "geolocation-!cn"}, []string{"private", "cn"}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"geoip.dat", "geosite.dat", "geosite-cn.srs", "geosite-geolocation-!cn.srs", "geoip-cn.srs"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("missing %s: %v", name, err)
		}
	}
	for _, path := range hits {
		if strings.Contains(path, "geoip-private") {
			t.Fatalf("private should not download a rule-set: %v", hits)
		}
	}
	hits = nil
	if err := store.Ensure(context.Background(), []string{"cn"}, []string{"cn"}); err != nil {
		t.Fatal(err)
	}
	if len(hits) != 0 {
		t.Fatalf("second ensure should reuse files, hits=%v", hits)
	}
	if os.Getenv("XRAY_LOCATION_ASSET") != dir {
		t.Fatalf("XRAY_LOCATION_ASSET = %q, want %q", os.Getenv("XRAY_LOCATION_ASSET"), dir)
	}
}

func TestEnsureFallsBackToSecondURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "bad") {
			http.Error(w, "nope", http.StatusNotFound)
			return
		}
		w.Write([]byte(strings.Repeat("G", 200)))
	}))
	defer srv.Close()

	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	store.Client = srv.Client()
	store.MinDat = 8
	store.DatURLs = map[string][]string{
		"geosite.dat": {srv.URL + "/bad/geosite.dat", srv.URL + "/geosite.dat"},
	}

	if err := store.Ensure(context.Background(), []string{"cn"}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "geosite.dat")); err != nil {
		t.Fatal(err)
	}
}
