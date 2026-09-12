#!/usr/bin/env bash
set -uo pipefail
export LC_ALL=C

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WATCHDOG="$ROOT/scripts/routing-watchdog.sh"

PASS=0; FAIL=0
ok()  { printf '  ✓ %s\n' "$1"; PASS=$((PASS+1)); }
bad() { printf '  ✗ %s\n' "$1"; FAIL=$((FAIL+1)); }
chk() { if "$2"; then ok "$1"; else bad "$1"; fi; }
chk_not() { if "$2"; then bad "$1"; else ok "$1"; fi; }

REAL_OUTPUT_CHAIN='table inet dns_route {
	chain output {
		type route hook output priority mangle; policy accept;
		meta skuid 102 ip daddr != @direct4 ip daddr != @cn_authority ip daddr != @tunnel_endpoints counter packets 0 bytes 0 meta mark set 0x000001d5
	}
}'

REAL_POSTROUTING='table inet dns_route {
	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		oifname "wg0" meta mark 0x000001d5 counter packets 0 bytes 0 masquerade
	}
}'

REAL_IP_RULE='0:	from all lookup local
100:	from 10.100.0.2 lookup 100
101:	from all fwmark 0x1d5 lookup 100
102:	from all fwmark 0x1d5 prohibit
32766:	from all lookup main
32767:	from all lookup default'

EMPTY_CHAIN='table inet dns_route {
	chain output {
		type route hook output priority mangle; policy accept;
	}
}'

eval "$(sed -n '/^FWMARK=/p;/^NFT_TABLE=/p' "$WATCHDOG")"
eval "$(sed -n '/^_MARK_RE=/,/^}/p' "$WATCHDOG" | sed -n '1p')"
eval "$(sed -n '/^chain_healthy() {/,/^}/p;/^nat_healthy() {/,/^}/p;/^rule_healthy() {/,/^}/p;/^cn_authority_healthy() {/,/^}/p' "$WATCHDOG")"
eval "$(sed -n '/^CN_AUTH_SET=/p;/^CN_AUTH_MIN_RATIO=/p' "$WATCHDOG")"

REAL_CN_AUTH_SET='table inet dns_route {
	set cn_authority {
		type ipv4_addr
		flags interval
		auto-merge
		elements = { 1.12.0.0/24, 1.12.96.0/24,
			     1.13.76.0/24, 1.14.119.0/24,
			     1.95.235.0/24, 1.193.216.0/24,
			     1.194.194.0/24, 2.16.40.0/24,
			     2.17.46.0/24, 2.22.230.0/24,
			     8.129.10.0/24, 8.129.32.0/24 }
	}
}'
EMPTY_CN_AUTH_SET='table inet dns_route {
	set cn_authority {
		type ipv4_addr
		flags interval
		auto-merge
	}
}'

echo "routing-watchdog 体检函数 · 用生产机真实输出验证"
echo "  FWMARK=$FWMARK  匹配式=$_MARK_RE"
echo

echo "── 健康状态(生产机真实输出) ──"
nft() { echo "$REAL_OUTPUT_CHAIN"; }
chk "chain_healthy 认得 nft 的零填充格式 0x000001d5" chain_healthy
nft() { echo "$REAL_POSTROUTING"; }
chk "nat_healthy 认得零填充格式且校验了 mark" nat_healthy
ip() { echo "$REAL_IP_RULE"; }
chk "rule_healthy 认得 ip rule 的紧凑格式 0x1d5" rule_healthy

echo
echo "── 故障状态 ──"
nft() { echo "$EMPTY_CHAIN"; }
chk_not "chain_healthy 检出被 flush 的空链(表在、规则没了)" chain_healthy
nft() { return 1; }
chk_not "chain_healthy 检出整张表被删" chain_healthy
chk_not "nat_healthy 检出整张表被删" nat_healthy
ip() { echo "0:	from all lookup local
32766:	from all lookup main"; }
chk_not "rule_healthy 检出 ip rule 被清空" rule_healthy

echo
echo "── 匹配边界 ──"
nft() { echo "		meta skuid 102 counter meta mark set 0x000001d50"; }
chk_not "chain_healthy 不把 0x1d50 误认成 0x1d5" chain_healthy
ip() { echo "101:	from all fwmark 0x1d50 lookup 100"; }
chk_not "rule_healthy 不把 0x1d50 误认成 0x1d5" rule_healthy
nft() { echo "		counter meta mark set 0x1d5"; }
chk "chain_healthy 同样接受紧凑格式(不假设填充宽度)" chain_healthy
nft() { echo "		counter meta mark set 0x00000000000001d5"; }
chk "chain_healthy 接受任意宽度的零填充" chain_healthy

echo
echo "── 墙内权威集合 ──"
_TD="$(mktemp -d)"; trap 'rm -rf "$_TD"' EXIT
CN_AUTH_FILE="$_TD/cn-authority.txt"

seq 1 20 | sed 's|^|10.0.|; s|$|.0/24|' > "$CN_AUTH_FILE"
nft() { echo "$REAL_CN_AUTH_SET"; }
chk "集合健康时判为健康(容忍 auto-merge 造成的条数缩水)" cn_authority_healthy

nft() { echo "$EMPTY_CN_AUTH_SET"; }
chk_not "检出集合被清空(1.12 节 ② 实测踩过的形态)" cn_authority_healthy
nft() { return 1; }
chk_not "检出整张表被删" cn_authority_healthy

seq 1 5 | sed 's|^|10.0.|; s|$|.0/24|' > "$CN_AUTH_FILE"
nft() { echo "$EMPTY_CN_AUTH_SET"; }
chk "基线不足 20 条时不判故障(装机首日，尚未积累)" cn_authority_healthy

rm -f "$CN_AUTH_FILE"
chk "基线文件不存在时不判故障" cn_authority_healthy

printf '# 本轮判定结果为空\n\n' > "$CN_AUTH_FILE"
chk "基线零匹配时不崩溃且判为健康(grep -c 退出码陷阱)" cn_authority_healthy

echo
printf '结果: %d 通过  %d 失败\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]] || exit 1
echo "体检函数在真实输出上工作正常。"
