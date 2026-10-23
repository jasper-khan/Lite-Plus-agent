package coreadapter

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

func TestPersonalControlRealTLS(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	core := newNative("xray", XrayVersion, false)
	cert := testCert(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := core.Start(ctx, []InboundSpec{{
		Core: "xray", Listen: "127.0.0.1", Port: port, TLS: &tls.Config{Certificates: []tls.Certificate{cert}},
	}}); err != nil {
		t.Fatal(err)
	}
	defer core.Stop()
	if err := core.ApplyUsers([]UserSpec{{
		ID: "u1", UUID: "user-uuid", Password: "pw", QuotaBytes: 64, DeviceLimit: 1,
	}}); err != nil {
		t.Fatal(err)
	}

	conn := dial(t, port)
	fmt.Fprintf(conn, "AUTH user-uuid pw\n")
	ok, _ := bufio.NewReader(conn).ReadString('\n')
	if ok != "OK\n" {
		t.Fatalf("auth: %q", ok)
	}
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()

	denied := dial(t, port)
	fmt.Fprintf(denied, "AUTH user-uuid wrong\n")
	msg, _ := bufio.NewReader(denied).ReadString('\n')
	if msg == "OK\n" {
		t.Fatal("expected forbidden")
	}
	_ = denied.Close()

	if err := core.ApplyUsers([]UserSpec{{
		ID: "u1", UUID: "user-uuid", Password: "pw", QuotaBytes: 64, Disabled: true, DeviceLimit: 1,
	}}); err != nil {
		t.Fatal(err)
	}
	off := dial(t, port)
	fmt.Fprintf(off, "AUTH user-uuid pw\n")
	msg, _ = bufio.NewReader(off).ReadString('\n')
	if msg == "OK\n" {
		t.Fatal("disabled user still connected")
	}
}

func dial(t *testing.T, port int) *tls.Conn {
	t.Helper()
	d := &tls.Dialer{Config: &tls.Config{InsecureSkipVerify: true}}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, err := d.DialContext(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	return c.(*tls.Conn)
}

func testCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "nodemgt-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return pair
}
