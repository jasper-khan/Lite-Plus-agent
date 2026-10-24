package geostore

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	defaultMaxAge  = 7 * 24 * time.Hour
	defaultTimeout = 60 * time.Second
	minDatBytes    = 100 * 1024
	minSRSBytes    = 64
)

// Store keeps Xray geoip.dat/geosite.dat and sing-box rule-set files beside the agent config.
type Store struct {
	Dir     string
	Client  *http.Client
	DatURLs map[string][]string
	SRSURLs func(kind, code string) []string
	MinDat  int64
	MinSRS  int64
	MaxAge  time.Duration

	mu sync.Mutex
}

func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Store{
		Dir:     dir,
		Client:  &http.Client{Timeout: defaultTimeout},
		DatURLs: defaultDatURLs(),
		SRSURLs: defaultSRSURLs,
		MinDat:  minDatBytes,
		MinSRS:  minSRSBytes,
		MaxAge:  defaultMaxAge,
	}, nil
}

func defaultDatURLs() map[string][]string {
	return map[string][]string{
		"geoip.dat": {
			"https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat",
			"https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geoip.dat",
		},
		"geosite.dat": {
			"https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat",
			"https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat",
		},
	}
}

func defaultSRSURLs(kind, code string) []string {
	name := kind + "-" + code + ".srs"
	repo := "sing-geosite"
	if kind == "geoip" {
		repo = "sing-geoip"
	}
	escaped := url.PathEscape(name)
	return []string{
		"https://raw.githubusercontent.com/SagerNet/" + repo + "/rule-set/" + escaped,
		"https://cdn.jsdelivr.net/gh/SagerNet/" + repo + "@rule-set/" + escaped,
	}
}

func BindXray(dir string) {
	_ = os.Setenv("XRAY_LOCATION_ASSET", dir)
}

func (s *Store) Path(name string) string {
	return filepath.Join(s.Dir, name)
}

func RuleSetFile(kind, code string) string {
	return kind + "-" + code + ".srs"
}

func (s *Store) Ensure(ctx context.Context, geosite, geoip []string) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	BindXray(s.Dir)
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	needDat := map[string]bool{}
	if len(geosite) > 0 {
		needDat["geosite.dat"] = true
	}
	if len(geoip) > 0 {
		needDat["geoip.dat"] = true
	}
	for name := range needDat {
		if err := s.ensureFile(ctx, name, s.DatURLs[name], s.minSize(name), false); err != nil {
			return err
		}
	}
	for _, code := range geosite {
		name := RuleSetFile("geosite", code)
		if err := s.ensureFile(ctx, name, s.srsURLs("geosite", code), s.MinSRS, false); err != nil {
			return err
		}
	}
	for _, code := range geoip {
		if strings.EqualFold(code, "private") {
			continue
		}
		name := RuleSetFile("geoip", code)
		if err := s.ensureFile(ctx, name, s.srsURLs("geoip", code), s.MinSRS, false); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) RefreshStale(ctx context.Context) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		return
	}
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		name := ent.Name()
		info, err := ent.Info()
		if err != nil || time.Since(info.ModTime()) < s.maxAge() {
			continue
		}
		urls, min := s.urlsFor(name)
		if len(urls) == 0 {
			continue
		}
		_ = s.ensureFile(ctx, name, urls, min, true)
	}
}

func (s *Store) srsURLs(kind, code string) []string {
	if s.SRSURLs == nil {
		return defaultSRSURLs(kind, code)
	}
	return s.SRSURLs(kind, code)
}

func (s *Store) urlsFor(name string) ([]string, int64) {
	if urls := s.DatURLs[name]; len(urls) > 0 {
		return urls, s.minSize(name)
	}
	base := strings.TrimSuffix(name, ".srs")
	kind, code, ok := strings.Cut(base, "-")
	if !ok || (kind != "geosite" && kind != "geoip") {
		return nil, 0
	}
	return s.srsURLs(kind, code), s.MinSRS
}

func (s *Store) minSize(name string) int64 {
	if strings.HasSuffix(name, ".dat") {
		if s.MinDat > 0 {
			return s.MinDat
		}
		return minDatBytes
	}
	if s.MinSRS > 0 {
		return s.MinSRS
	}
	return minSRSBytes
}

func (s *Store) maxAge() time.Duration {
	if s.MaxAge > 0 {
		return s.MaxAge
	}
	return defaultMaxAge
}

func (s *Store) ensureFile(ctx context.Context, name string, urls []string, min int64, refresh bool) error {
	path := s.Path(name)
	if !refresh {
		if info, err := os.Stat(path); err == nil && info.Size() >= min {
			return nil
		}
	}
	var last error
	for _, raw := range urls {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := s.download(ctx, raw, path, min); err != nil {
			last = err
			continue
		}
		return nil
	}
	if !refresh {
		if info, err := os.Stat(path); err == nil && info.Size() >= min {
			return nil
		}
	}
	if last == nil {
		last = fmt.Errorf("no download URL for %s", name)
	}
	return fmt.Errorf("download %s: %w", name, last)
}

func (s *Store) download(ctx context.Context, rawURL, dest string, min int64) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "Lite-Plus-agent")
	client := s.Client
	if client == nil {
		client = http.DefaultClient
	}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: HTTP %d", rawURL, res.StatusCode)
	}
	tmp, err := os.CreateTemp(s.Dir, ".geo-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	n, err := io.Copy(tmp, res.Body)
	if err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if n < min {
		_ = os.Remove(tmpName)
		return fmt.Errorf("%s: got %d bytes, want at least %d", rawURL, n, min)
	}
	if err := os.Rename(tmpName, dest); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}
