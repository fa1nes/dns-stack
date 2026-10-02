package helper

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
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
	oauthWritableKeys = map[string]bool{"client_id": true, "client_secret": true, "allowed_users": true, "verified_once": true, "bound_ids": true}
	totpWritableKeys  = map[string]bool{"secret": true, "enabled": true}
	usernamePattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,31}$`)
)

func NormalizeUsername(raw string) (string, error) {
	name := strings.ToLower(strings.TrimSpace(raw))
	if !usernamePattern.MatchString(name) {
		return "", errors.New("用户名要 2–32 位，只能用字母、数字和 . _ -，并以字母或数字开头")
	}
	return name, nil
}

func newSessionKey() (string, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

func HashPassword(password string) (map[string]any, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	sessionKey, err := newSessionKey()
	if err != nil {
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
		"session_key": sessionKey,
		"created_at":  time.Now().Unix(),
	}, nil
}

const (
	MinPanelPasswordLen = 12
	MaxPanelPasswordLen = 256
)

func SetPanelPassword(authPath, username, password string) error {
	switch length := len([]rune(password)); {
	case length < MinPanelPasswordLen:
		return errors.New("面板密码至少 12 位：它能重启服务、导出含密钥的备份")
	case length > MaxPanelPasswordLen:
		return errors.New("面板密码过长（上限 256 字符）")
	}
	record, err := passwordRecord(authPath, password, true)
	if err != nil {
		return err
	}
	if username != "" {
		name, err := NormalizeUsername(username)
		if err != nil {
			return err
		}
		record["username"] = name
	}
	return writeAuthRecord(authPath, record, false, 0o640)
}

func SetPanelUsername(authPath, username string) error {
	name, err := NormalizeUsername(username)
	if err != nil {
		return err
	}
	record := loadAuthRecord(authPath)
	if len(record) == 0 {
		return errors.New("面板尚未设置密码")
	}
	record["username"] = name
	return writeAuthRecord(authPath, record, true, 0o600)
}

func passwordRecord(authPath, password string, reenablePasswordLogin bool) (map[string]any, error) {
	record, err := HashPassword(password)
	if err != nil {
		return nil, err
	}
	previous := loadAuthRecord(authPath)
	for _, key := range []string{"username", "totp", "oauth"} {
		if value, ok := previous[key]; ok {
			record[key] = value
		}
	}
	if !reenablePasswordLogin && truthy(previous["password_disabled"]) {
		record["password_disabled"] = true
	}
	return record, nil
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

func oauthCredentialReplaced(old, incoming map[string]any) bool {
	changed := func(key string, blankKeeps bool) bool {
		raw, present := incoming[key]
		if !present {
			return false
		}
		next, _ := raw.(string)
		next = strings.TrimSpace(next)
		if next == "" && blankKeeps {
			return false
		}
		previous, _ := old[key].(string)
		return next != strings.TrimSpace(previous)
	}
	return changed("client_id", false) || changed("client_secret", true)
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
			if users, listed := incoming["allowed_users"].([]any); listed {
				merged["bound_ids"] = boundIDsFor(users, objectValue(old["bound_ids"]))
			}
			if oauthCredentialReplaced(old, incoming) {
				merged["verified_once"] = false
			} else {
				merged["verified_once"] = truthy(old["verified_once"]) || truthy(incoming["verified_once"])
			}
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

func boundIDsFor(users []any, bound map[string]any) map[string]any {
	kept := map[string]any{}
	for _, raw := range users {
		user, _ := raw.(string)
		user = strings.ToLower(strings.TrimSpace(user))
		if id, ok := bound[user]; ok && user != "" {
			kept[user] = id
		}
	}
	return kept
}

func RotateSessionKey(authPath string) error {
	record := loadAuthRecord(authPath)
	if len(record) == 0 {
		return errors.New("面板尚未设置密码，没有会话可以作废")
	}
	key, err := newSessionKey()
	if err != nil {
		return err
	}
	record["session_key"] = key
	return writeAuthRecord(authPath, record, true, 0o600)
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
	file, err := os.CreateTemp(filepath.Dir(path), ".auth-*")
	if err != nil {
		return err
	}
	temp := file.Name()
	_, writeErr := file.Write(data)
	closeErr := file.Close()
	if err := errors.Join(writeErr, closeErr, os.Chmod(temp, mode)); err != nil {
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
