package certstore

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Store struct {
	dir   string
	mu    sync.Mutex
	files map[string]binding
}

type binding struct {
	ID       string
	Domain   string
	CertPath string
	KeyPath  string
	LastFP   string
}

type FileInfo struct {
	ID          string
	Domain      string
	Fingerprint string
	Issuer      string
	NotAfter    time.Time
	Err         error
	Changed     bool
}

func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Store{dir: dir, files: map[string]binding{}}, nil
}

func (s *Store) GenerateCSR(domain string) (keyPEM, csrPEM string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}
	keyPEMBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	tpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: domain}, DNSNames: []string{domain}}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tpl, key)
	if err != nil {
		return "", "", err
	}
	csrPEMBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	if err := os.WriteFile(filepath.Join(s.dir, domain+".key.next"), keyPEMBytes, 0o600); err != nil {
		return "", "", err
	}
	return string(keyPEMBytes), string(csrPEMBytes), nil
}

func (s *Store) SaveChain(domain, chainPEM string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	crtNext := filepath.Join(s.dir, domain+".crt.next")
	keyNext := filepath.Join(s.dir, domain+".key.next")
	crtLive := filepath.Join(s.dir, domain+".crt")
	keyLive := filepath.Join(s.dir, domain+".key")
	if err := os.WriteFile(crtNext, []byte(chainPEM), 0o600); err != nil {
		return err
	}
	keyPath := keyLive
	if _, err := os.Stat(keyNext); err == nil {
		keyPath = keyNext
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		_ = os.Remove(crtNext)
		return err
	}
	if _, err := tls.X509KeyPair([]byte(chainPEM), keyPEM); err != nil {
		_ = os.Remove(crtNext)
		return err
	}
	if err := os.Rename(crtNext, crtLive); err != nil {
		return err
	}
	if keyPath == keyNext {
		if err := os.Rename(keyNext, keyLive); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) BindFile(id, domain, certPath, keyPath string) {
	domain = strings.TrimSpace(domain)
	certPath = strings.TrimSpace(certPath)
	keyPath = strings.TrimSpace(keyPath)
	if domain == "" || certPath == "" || keyPath == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.files == nil {
		s.files = map[string]binding{}
	}
	prev := s.files[domain]
	s.files[domain] = binding{
		ID:       strings.TrimSpace(id),
		Domain:   domain,
		CertPath: certPath,
		KeyPath:  keyPath,
		LastFP:   prev.LastFP,
	}
}

func (s *Store) UnbindMissing(keep map[string]struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for domain := range s.files {
		if _, ok := keep[domain]; !ok {
			delete(s.files, domain)
		}
	}
}

func (s *Store) RememberFingerprint(domain, fp string) {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.files[domain]
	if !ok {
		return
	}
	b.LastFP = fp
	s.files[domain] = b
}

func (s *Store) InspectFiles() []FileInfo {
	s.mu.Lock()
	list := make([]binding, 0, len(s.files))
	for _, b := range s.files {
		list = append(list, b)
	}
	s.mu.Unlock()
	out := make([]FileInfo, 0, len(list))
	for _, b := range list {
		info := FileInfo{ID: b.ID, Domain: b.Domain}
		certPEM, err := os.ReadFile(b.CertPath)
		if err != nil {
			info.Err = err
			info.Changed = true
			out = append(out, info)
			continue
		}
		keyPEM, err := os.ReadFile(b.KeyPath)
		if err != nil {
			info.Err = err
			info.Changed = true
			out = append(out, info)
			continue
		}
		fp, issuer, notAfter, err := parseLeaf(certPEM, keyPEM)
		if err != nil {
			info.Err = err
			info.Changed = true
			out = append(out, info)
			continue
		}
		info.Fingerprint = fp
		info.Issuer = issuer
		info.NotAfter = notAfter
		info.Changed = b.LastFP != fp
		out = append(out, info)
	}
	return out
}

func (s *Store) PEM(domain string) (certPEM, keyPEM []byte, err error) {
	s.mu.Lock()
	b, ok := s.files[domain]
	s.mu.Unlock()
	if ok {
		certPEM, err = os.ReadFile(b.CertPath)
		if err != nil {
			return nil, nil, err
		}
		keyPEM, err = os.ReadFile(b.KeyPath)
		return certPEM, keyPEM, err
	}
	certPEM, err = os.ReadFile(filepath.Join(s.dir, domain+".crt"))
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err = os.ReadFile(filepath.Join(s.dir, domain+".key"))
	return certPEM, keyPEM, err
}

func (s *Store) TLSConfig(domain string) (*tls.Config, string, error) {
	certPEM, keyPEM, err := s.PEM(domain)
	if err != nil {
		return nil, "", err
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, "", err
	}
	if len(pair.Certificate) == 0 {
		return nil, "", fmt.Errorf("empty certificate")
	}
	fp := sha256.Sum256(pair.Certificate[0])
	return &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}, hex.EncodeToString(fp[:]), nil
}

func parseLeaf(certPEM, keyPEM []byte) (fp, issuer string, notAfter time.Time, err error) {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return "", "", time.Time{}, err
	}
	if len(pair.Certificate) == 0 {
		return "", "", time.Time{}, fmt.Errorf("empty certificate")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return "", "", time.Time{}, err
	}
	sum := sha256.Sum256(pair.Certificate[0])
	issuer = strings.TrimSpace(leaf.Issuer.CommonName)
	if len(leaf.Issuer.Organization) > 0 {
		if org := strings.TrimSpace(leaf.Issuer.Organization[0]); org != "" {
			issuer = org
		}
	}
	return hex.EncodeToString(sum[:]), issuer, leaf.NotAfter, nil
}
