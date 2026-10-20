package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeTestCert(t *testing.T, notAfter time.Time) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "t"},
		NotBefore: notAfter.Add(-6 * 24 * time.Hour), NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "cert.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCertExpiryProblemsOnlyFireWhenRenewalHasStalled(t *testing.T) {
	now := time.Now()
	if got := certExpiryProblems(writeTestCert(t, now.Add(5*24*time.Hour)), now); len(got) != 0 {
		t.Fatalf("还有 5 天不该告警: %v", got)
	}
	got := certExpiryProblems(writeTestCert(t, now.Add(30*time.Hour)), now)
	if len(got) != 1 || !strings.Contains(got[0], "36 小时") {
		t.Fatalf("30 小时后到期应告警且按 12 小时取整: %v", got)
	}
	again := certExpiryProblems(writeTestCert(t, now.Add(29*time.Hour)), now)
	if len(again) != 1 || again[0] != got[0] {
		t.Fatalf("同一个 12 小时档内文案要稳定，否则每分钟都推一条: %v vs %v", again, got)
	}
	if got := certExpiryProblems(writeTestCert(t, now.Add(-time.Hour)), now); len(got) != 1 || !strings.Contains(got[0], "已于") {
		t.Fatalf("过期要告警: %v", got)
	}
	if got := certExpiryProblems(filepath.Join(t.TempDir(), "none.pem"), now); len(got) != 0 {
		t.Fatalf("还没签发过证书不算异常: %v", got)
	}
}
