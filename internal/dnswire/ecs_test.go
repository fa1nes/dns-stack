package dnswire

import (
	"net/netip"
	"testing"
)

func TestClientSubnetRoundTrip(t *testing.T) {
	cases := []struct {
		subnet    string
		wantBytes int
	}{
		{"1.2.3.0/24", 3},
		{"1.2.3.4/32", 4},
		{"10.0.0.0/8", 1},
		{"0.0.0.0/0", 0},
		{"2001:db8::/32", 4},
		{"2001:db8::1/128", 16},
	}
	for _, tc := range cases {
		prefix := netip.MustParsePrefix(tc.subnet)
		packet, err := BuildQueryWithSubnet(0x1234, "example.com", TypeA, prefix)
		if err != nil {
			t.Fatalf("%s: 构造失败: %v", tc.subnet, err)
		}
		msg, err := Unpack(packet)
		if err != nil {
			t.Fatalf("%s: 解析失败: %v", tc.subnet, err)
		}
		got, ok := msg.ClientSubnet()
		if !ok {
			t.Fatalf("%s: 应答里读不出 ECS 选项", tc.subnet)
		}
		if got.Prefix.Masked() != prefix.Masked() {
			t.Errorf("%s: 往返后变成 %s", tc.subnet, got.Prefix)
		}
		if got.Scope != 0 {
			t.Errorf("%s: 查询侧 scope 必须是 0，得到 %d", tc.subnet, got.Scope)
		}
	}
}

func TestClientSubnetOnlySendsSignificantBytes(t *testing.T) {
	withECS, err := BuildQueryWithSubnet(1, "example.com", TypeA, netip.MustParsePrefix("1.2.3.0/24"))
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	plain, err := BuildQuery(1, "example.com", TypeA)
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	if grew := len(withECS) - len(plain); grew != 11 {
		t.Errorf("/24 只该多带 3 个地址字节（选项头 4 + 族/位数 4 + 3），共 11 字节，实际多了 %d", grew)
	}
}

func TestQueryWithoutSubnetHasNoECSOption(t *testing.T) {
	packet, err := BuildQuery(1, "example.com", TypeA)
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	msg, err := Unpack(packet)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if _, ok := msg.ClientSubnet(); ok {
		t.Error("普通查询不该带 ECS 选项——那会把客户端子网泄露给每一台权威")
	}
}

func TestInvalidSubnetIsRejected(t *testing.T) {
	if _, err := BuildQueryWithSubnet(1, "example.com", TypeA, netip.Prefix{}); err == nil {
		t.Error("无效前缀必须被拒绝，而不是静默发出一个畸形选项")
	}
}
