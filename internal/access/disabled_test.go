package access

import "testing"

func TestADisabledACLIsNotEnforcedButKeepsItsList(t *testing.T) {
	s := newStore(t)
	if _, err := s.SetACL([]string{"203.0.113.0/24"}); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.EnforcedACL(); len(got) != 1 {
		t.Fatalf("没关闭时应当按清单执行，得到 %v", got)
	}
	if err := s.SetACLDisabled(true); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.EnforcedACL(); len(got) != 0 {
		t.Fatalf("acl disable 是被锁在门外时的逃生口：看门狗和重启按 EnforcedACL 恢复访问控制，"+
			"关闭后还返回 %v 就会在一分钟内把人重新锁在外面", got)
	}
	if kept, _ := s.ACL(); len(kept) != 1 {
		t.Fatalf("关闭不该清掉清单（apply 要能原样重新启用），剩 %v", kept)
	}
	for i := 0; i < 2; i++ {
		if err := s.SetACLDisabled(false); err != nil {
			t.Fatalf("重新启用应当幂等，第 %d 次报错: %v", i+1, err)
		}
	}
	if got, _ := s.EnforcedACL(); len(got) != 1 {
		t.Fatalf("重新启用后应当恢复执行，得到 %v", got)
	}
}
