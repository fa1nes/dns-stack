package panel

import (
	"testing"
)

func recordWithAllowedUsers(users any, verified bool) authRecord {
	return authRecord{OAuth: map[string]any{
		"client_id": "cid", "client_secret": "sec",
		"allowed_users": users, "verified_once": verified,
	}}
}

func TestClosingPasswordLoginUsesTheSameReadinessTestAsLoggingIn(t *testing.T) {
	for _, tc := range []struct {
		name  string
		users any
	}{
		{"只剩一个空串", []any{""}},
		{"只剩空白", []any{"   "}},
		{"空白与非字符串混在一起", []any{"  ", 42, nil}},
	} {
		rec := recordWithAllowedUsers(tc.users, true)
		if oauthReady(rec) {
			t.Errorf("%s: oauthReady 认为配置完整，但 oauthStart 会因为没有可用账号而拒绝授权", tc.name)
		}
		if len(oauthUsers(rec)) != 0 {
			t.Errorf("%s: oauthUsers = %q，空白账号名不该被当成可登录的账号",
				tc.name, oauthUsers(rec))
		}
	}
}

func TestAllowedUsersAreComparedAfterNormalisation(t *testing.T) {
	rec := recordWithAllowedUsers([]any{"  Fa1neS  ", "OTHER"}, true)
	users := oauthUsers(rec)
	if len(users) != 2 || users[0] != "fa1nes" || users[1] != "other" {
		t.Fatalf("oauthUsers = %q，期望全部去空白并转小写——"+
			"oauthCallback 拿 strings.ToLower(login) 去比这份列表，"+
			"列表这边不归一化就会把合法账号判成不在白名单，只有写入路径恰好归一化过才碰巧能登进去", users)
	}
}
