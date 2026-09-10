package helper

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/scrypt"
)

const (
	scryptN      = 1 << 15
	scryptR      = 8
	scryptP      = 1
	scryptKeyLen = 32
)

var (
	panelWritableKeys = map[string]bool{"oauth": true, "password_disabled": true, "totp": true}
	oauthWritableKeys = map[string]bool{"client_id": true, "client_secret": true, "allowed_users": true, "verified_once": true}
	totpWritableKeys  = map[string]bool{"secret": true, "enabled": true}
)

func HashPassword(password string) (map[string]any, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	sessionKey := make([]byte, 32)
	if _, err := rand.Read(sessionKey); err != nil {
		return nil, err
	}
	derived, err := scrypt.Key([]byte(password), salt, scryptN, scryptR, scryptP, scryptKeyLen)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"algo":        "scrypt",
		"n":           scryptN,
		"r":           scryptR,
		"p":           scryptP,
		"salt":        base64.StdEncoding.EncodeToString(salt),
		"hash":        base64.StdEncoding.EncodeToString(derived),
		"session_key": base64.StdEncoding.EncodeToString(sessionKey),
		"created_at":  time.Now().Unix(),
	}, nil
}

const (
	MinPanelPasswordLen = 12
	MaxPanelPasswordLen = 256
)

func SetPanelPassword(authPath, password string) error {
	switch length := len([]rune(password)); {
	case length < MinPanelPasswordLen:
		return errors.New("面板密码至少 12 位：它能重启服务、导出含密钥的备份")
	case length > MaxPanelPasswordLen:
		return errors.New("面板密码过长（上限 256 字符）")
	}
	record, err := HashPassword(password)
	if err != nil {
		return err
	}
	return writeAuthRecord(authPath, record, false, 0o640)
}

func DisableTOTP(authPath string) (bool, error) {
	record := loadAuthRecord(authPath)
	if len(record) == 0 {
		return false, errors.New("面板尚未设置密码，无二次认证可重置")
	}
	if _, ok := record["totp"]; !ok {
		return false, nil
	}
	delete(record, "totp")
	return true, writeAuthRecord(authPath, record, false, 0o640)
}

func loadAuthRecord(path string) map[string]any {
	data, err := os.ReadFile(path)
	if err != nil {
		return map[string]any{}
	}
	var record map[string]any
	if json.Unmarshal(data, &record) != nil || record == nil {
		return map[string]any{}
	}
	return record
}

func objectValue(raw any) map[string]any {
	if value, ok := raw.(map[string]any); ok && value != nil {
		return value
	}
	return map[string]any{}
}

func truthy(raw any) bool {
	switch value := raw.(type) {
	case bool:
		return value
	case string:
		return value != ""
	case float64:
		return value != 0
	case nil:
		return false
	default:
		return true
	}
}

func MergeAuthUpdate(authPath string, update map[string]any) map[string]any {
	record := loadAuthRecord(authPath)
	for key, value := range update {
		if !panelWritableKeys[key] {
			continue
		}
		switch key {
		case "oauth":
			old := objectValue(record["oauth"])
			merged := map[string]any{}
			for k, v := range old {
				merged[k] = v
			}
			incoming := objectValue(value)
			for k, v := range incoming {
				if oauthWritableKeys[k] {
					merged[k] = v
				}
			}
			if secret, _ := incoming["client_secret"].(string); strings.TrimSpace(secret) == "" {
				merged["client_secret"] = old["client_secret"]
			}
			merged["verified_once"] = truthy(old["verified_once"]) || truthy(incoming["verified_once"])
			record["oauth"] = merged
		case "totp":
			incoming := objectValue(value)
			if len(incoming) == 0 {
				delete(record, "totp")
				continue
			}
			merged := map[string]any{}
			for k, v := range objectValue(record["totp"]) {
				merged[k] = v
			}
			for k, v := range incoming {
				if totpWritableKeys[k] {
					merged[k] = v
				}
			}
			merged["enabled"] = truthy(merged["enabled"])
			record["totp"] = merged
		default:
			record[key] = truthy(value)
		}
	}
	return record
}

func writeAuthRecord(path string, record map[string]any, indent bool, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	var data []byte
	var err error
	if indent {
		data, err = json.MarshalIndent(record, "", "  ")
	} else {
		data, err = json.Marshal(record)
	}
	if err != nil {
		return err
	}
	temp := strings.TrimSuffix(path, filepath.Ext(path)) + ".tmp"
	if err := os.WriteFile(temp, data, mode); err != nil {
		return err
	}
	if err := os.Chmod(temp, mode); err != nil {
		os.Remove(temp)
		return err
	}
	if err := os.Rename(temp, path); err != nil {
		os.Remove(temp)
		return err
	}
	return nil
}

var errUpdateTooLarge = errors.New("update 载荷过大")
