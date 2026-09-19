package pipeline

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/exec"
	"time"

	"github.com/dns-stack/dns-stack/internal/backup"
)

const (
	CertPath      = "/etc/dns-stack/secrets/doh-dot.pem"
	KeyPath       = "/etc/dns-stack/secrets/doh-dot.key"
	PanelCertDir  = "/etc/dns-stack/secrets/panel"
	PanelCertPath = PanelCertDir + "/cert.pem"
	PanelKeyPath  = PanelCertDir + "/key.pem"
	AcmeHome      = "/root/.acme.sh"
	renewWhenDays = 3
)

type CertStatus struct {
	NotAfter time.Time
	DaysLeft int
	SANHasIP bool
	KeyMatch bool
	PublicIP string
}

func parsePEMCert(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		return x509.ParseCertificate(block.Bytes)
	}
	return nil, fmt.Errorf("%s 里没有 CERTIFICATE 块", path)
}

func parsePEMKey(path string) (any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
			return key, nil
		}
		if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
			return key, nil
		}
		if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
			return key, nil
		}
	}
	return nil, fmt.Errorf("%s 里没有可解析的私钥", path)
}

func publicKeysMatch(cert *x509.Certificate, key any) bool {
	switch pub := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		private, ok := key.(*ecdsa.PrivateKey)
		return ok && pub.Equal(&private.PublicKey)
	case *rsa.PublicKey:
		private, ok := key.(*rsa.PrivateKey)
		return ok && pub.Equal(&private.PublicKey)
	case ed25519.PublicKey:
		private, ok := key.(ed25519.PrivateKey)
		return ok && pub.Equal(private.Public())
	}
	return false
}

func InspectCert(certPath, keyPath, publicIP string, now time.Time) (CertStatus, error) {
	cert, err := parsePEMCert(certPath)
	if err != nil {
		return CertStatus{}, err
	}
	status := CertStatus{
		NotAfter: cert.NotAfter,
		DaysLeft: int(cert.NotAfter.Sub(now).Hours() / 24),
		PublicIP: publicIP,
	}
	if publicIP != "" {
		want := net.ParseIP(publicIP)
		for _, addr := range cert.IPAddresses {
			if addr.Equal(want) {
				status.SANHasIP = true
				break
			}
		}
	}
	key, err := parsePEMKey(keyPath)
	if err != nil {
		return status, fmt.Errorf("读不到私钥: %w", err)
	}
	status.KeyMatch = publicKeysMatch(cert, key)
	if !status.KeyMatch {
		return status, fmt.Errorf("证书与私钥不匹配")
	}
	return status, nil
}

func stepRenewCert(ctx context.Context, rt *Runtime) error {
	publicIP := rt.Config.Value("PUBLIC_IPV4")
	status, err := InspectCert(CertPath, KeyPath, publicIP, time.Now())
	if err != nil {
		return err
	}
	rt.Infof("证书剩余有效期 %d 天（到期 %s）",
		status.DaysLeft, status.NotAfter.Format("2006-01-02 15:04"))
	if status.SANHasIP {
		rt.Infof("SAN 包含当前公网 IP(%s)，证书与私钥匹配", publicIP)
	} else {
		rt.Warnf("SAN 不包含当前公网 IP(%s)，可能是 IP 已变更", publicIP)
	}
	if status.DaysLeft > renewWhenDays && status.SANHasIP {
		rt.Infof("证书仍然有效(> %d 天)且 SAN 正确，无需续签", renewWhenDays)
		return syncPanelCertIfStale(ctx, rt)
	}
	if publicIP == "" {
		return fmt.Errorf("需要续签但 config.env 没有 PUBLIC_IPV4，无法确定证书主体")
	}
	rt.Infof("开始续签（Let's Encrypt IP 证书约 6 天有效期）")
	return runAcme(ctx, rt, publicIP)
}

func runAcme(ctx context.Context, rt *Runtime, publicIP string) error {
	acme := AcmeHome + "/acme.sh"
	if _, err := os.Stat(acme); err != nil {
		return fmt.Errorf("找不到 acme.sh: %s", acme)
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	renew := exec.CommandContext(ctx, acme, "--home", AcmeHome, "--renew", "-d", publicIP, "--ecc", "--force")
	renew.Stdout, renew.Stderr = rt.Out, rt.Out
	if err := renew.Run(); err != nil {
		return fmt.Errorf("续签失败，继续使用旧证书: %w", err)
	}
	self, err := os.Executable()
	if err != nil {
		self = "/opt/dns-stack/bin/dns-stack-go"
	}
	install := exec.CommandContext(ctx, acme, "--home", AcmeHome, "--install-cert", "-d", publicIP,
		"--key-file", KeyPath, "--fullchain-file", CertPath,
		"--reloadcmd", self+" maintenance --reload-mosproxy", "--ecc")
	install.Stdout, install.Stderr = rt.Out, rt.Out
	if err := install.Run(); err != nil {
		return fmt.Errorf("安装新证书失败: %w", err)
	}
	rt.Infof("续签成功")
	return SyncPanelCert(ctx, rt)
}

func syncPanelCertIfStale(ctx context.Context, rt *Runtime) error {
	source, err := os.ReadFile(CertPath)
	if err != nil {
		return nil
	}
	if copied, err := os.ReadFile(PanelCertPath); err == nil && bytes.Equal(source, copied) {
		return nil
	}
	rt.Warnf("面板证书副本与入口证书不一致——acme.sh 自己的 cron 续签后只重载 mosproxy，不会同步副本")
	return SyncPanelCert(ctx, rt)
}

func SyncPanelCert(ctx context.Context, rt *Runtime) error {
	const dir = PanelCertDir
	if _, err := exec.LookPath("install"); err != nil {
		return nil
	}
	if err := exec.CommandContext(ctx, "id", "-u", "dns-stack-panel").Run(); err != nil {
		return nil
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	for _, pair := range [][2]string{{CertPath, PanelCertPath}, {KeyPath, PanelKeyPath}} {
		cmd := exec.CommandContext(ctx, "install",
			"-o", "dns-stack-panel", "-g", "dns-stack-panel", "-m", "0400", pair[0], pair[1])
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("同步面板证书副本失败: %w", err)
		}
	}
	exec.CommandContext(ctx, "chgrp", "dns-stack-panel", dir).Run()
	exec.CommandContext(ctx, "systemctl", "restart", "dns-stack-panel").Run()
	rt.Infof("面板证书副本已同步")
	return nil
}

func ReloadMosproxyCert(ctx context.Context, rt *Runtime) error {
	const hotReloadSincePatch = 14
	data, err := os.ReadFile("/opt/dns-stack/bin/mosproxy.build-id")
	if err == nil && buildPatchLevel(string(data)) >= hotReloadSincePatch {
		rt.Infof("mosproxy 支持证书热重载，无需重启(新证书将在 10 秒内生效)")
		return nil
	}
	rt.Infof("mosproxy 二进制未含热重载补丁(p%d+)，回退为重启", hotReloadSincePatch)
	return exec.CommandContext(ctx, "systemctl", "restart", "mosproxy.service").Run()
}

func buildPatchLevel(text string) int {
	level := -1
	for i := 0; i+1 < len(text); i++ {
		if text[i] != '-' || text[i+1] != 'p' {
			continue
		}
		value, digits := 0, 0
		for j := i + 2; j < len(text) && text[j] >= '0' && text[j] <= '9'; j++ {
			value = value*10 + int(text[j]-'0')
			digits++
		}
		if digits > 0 && value > level {
			level = value
		}
	}
	return level
}

func stepBackup(ctx context.Context, rt *Runtime) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	cfg := backup.DefaultConfig()
	cfg.StateDir = rt.Config.StateDir
	cfg.ConfigFile = rt.Config.ConfigFile
	cfg.Out = rt.Out
	_, err := cfg.Backup(ctx, false, true)
	return err
}

func MaintenanceSteps() []Step {
	return []Step{
		{Name: "renew-cert", Label: "TLS 证书检查与续签", Every: 6 * time.Hour, Run: stepRenewCert},
		{Name: "backup", Label: "数据库/配置/规则备份", Every: 24 * time.Hour, Run: stepBackup},
	}
}
