package stack

import "time"

type Kind string

const (
	KindDaemon Kind = "daemon"
	KindJob    Kind = "job"
)

type Impl string

const (
	ImplGo       Impl = "go"
	ImplExternal Impl = "external"
)

const (
	GroupResolve = "解析链路"
	GroupRouting = "分流数据"
	GroupOps     = "面板与运维"
)

const (
	RoleCNResolver = "cn-resolver"
	RoleOffshore   = "offshore"
)

const (
	DefaultNFTTable = "dns_route"
	ACLChain        = "dns_acl"
)

var GroupOrder = []string{GroupResolve, GroupRouting, GroupOps}

type Module struct {
	Unit     string
	OpenRC   string
	Cron     string
	LogFile  string
	Name     string
	Group    string
	Purpose  string
	Kind     Kind
	Impl     Impl
	Roles    []string
	Artifact string
	Every    time.Duration
	Critical bool
}

func (m Module) Overdue() time.Duration {
	if m.Kind != KindJob || m.Every <= 0 {
		return 0
	}
	if budget := m.Every * 3; budget > time.Hour {
		return budget
	}
	return time.Hour
}

func (m Module) CronDriven() bool { return m.Cron != "" }

func (m Module) HasRole(role string) bool {
	for _, item := range m.Roles {
		if item == role {
			return true
		}
	}
	return false
}

var both = []string{RoleCNResolver, RoleOffshore}

var modules = []Module{
	{
		Unit: "mosproxy", Name: "DNS 入口", Group: GroupResolve,
		Purpose: "接收你设备发来的 DoH/DoT 查询，按规则决定走本机递归还是香港递归",
		Kind:    KindDaemon, Impl: ImplExternal, Roles: []string{RoleCNResolver}, Critical: true,
	},
	{
		Unit: "unbound", Name: "递归解析器", Group: GroupResolve,
		OpenRC: "unbound", LogFile: "unbound.log",
		Purpose: "自己从根服务器一级级问下来，不依赖任何公共 DNS",
		Kind:    KindDaemon, Impl: ImplExternal, Roles: both, Critical: true,
	},
	{
		Unit: "dns-stack-recursive-routing", Name: "出口分流", Group: GroupResolve,
		Purpose: "按目标权威服务器的 IP 归属，决定这一跳走大陆直连还是香港隧道",
		Kind:    KindDaemon, Impl: ImplGo, Roles: []string{RoleCNResolver}, Critical: true,
	},
	{
		Unit: "wg-quick@wg0", Name: "香港隧道", Group: GroupResolve,
		OpenRC:  "wg-quick.wg0",
		Purpose: "通往香港节点的 WireGuard 隧道，境外权威的查询从这里出去",
		Kind:    KindDaemon, Impl: ImplExternal, Roles: both, Critical: true,
	},
	{
		Unit: "dns-stack-routing-watchdog", Name: "分流看门狗", Group: GroupResolve,
		Purpose: "定期确认分流规则还在内核里，被其他程序刷掉时自动补回",
		Kind:    KindJob, Impl: ImplGo, Roles: []string{RoleCNResolver}, Every: time.Minute,
	},

	{
		Unit: "dns-stack-routing-data", Name: "分流数据流水线", Group: GroupRouting,
		Purpose: "按依赖顺序重建归属库、大陆网段、交叉校验、共享 anycast、国内权威与 ECS 分片",
		Kind:    KindJob, Impl: ImplGo, Roles: []string{RoleCNResolver},
		Artifact: "chnroute/direct4.txt", Every: 15 * time.Minute, Critical: true,
	},
	{
		Unit: "dns-stack-collect-polluted", Name: "污染 IP 采集", Group: GroupRouting,
		Purpose: "采集 GFW 投毒返回的假地址，作为判定域名被污染的证据",
		Kind:    KindJob, Impl: ImplGo, Roles: []string{RoleCNResolver},
		Artifact: "polluted-ip.txt", Every: 6 * time.Hour,
	},

	{
		Unit: "dns-stack-panel", Name: "管理面板", Group: GroupOps,
		Purpose: "就是你现在看的这个界面",
		Kind:    KindDaemon, Impl: ImplGo, Roles: []string{RoleCNResolver},
	},
	{
		Unit: "dns-stack-helper", Name: "特权助手", Group: GroupOps,
		LogFile: "helper.log",
		Purpose: "面板要动系统时经它代办，只放行白名单内的操作",
		Kind:    KindDaemon, Impl: ImplGo, Roles: []string{RoleCNResolver}, Critical: true,
	},
	{
		Unit: "dns-stack-trim-logs", Name: "日志瘦身", Group: GroupOps,
		Cron: "trim-logs", LogFile: "trim-logs.log",
		Purpose: "每天截断各份日志的尾部、清掉已删模块留下的僵尸日志——境外节点只有 989MB 磁盘",
		Kind:    KindJob, Impl: ImplGo, Roles: []string{RoleOffshore}, Every: 24 * time.Hour,
	},
	{
		Unit: "dns-stack-maintenance", Name: "例行维护", Group: GroupOps,
		Purpose: "检查并续签 TLS 证书，每天备份数据库、配置与规则",
		Kind:    KindJob, Impl: ImplGo, Roles: []string{RoleCNResolver}, Every: 6 * time.Hour,
	},
}

func All() []Module { return modules }

func ForRole(role string) []Module {
	if role != RoleCNResolver && role != RoleOffshore {
		role = RoleCNResolver
	}
	out := make([]Module, 0, len(modules))
	for _, m := range modules {
		if m.HasRole(role) {
			out = append(out, m)
		}
	}
	return out
}

func UnitsForRole(role string) []string {
	list := ForRole(role)
	out := make([]string, 0, len(list))
	for _, m := range list {
		out = append(out, m.Unit)
	}
	return out
}

func Lookup(unit string) (Module, bool) {
	for _, m := range modules {
		if m.Unit == unit {
			return m, true
		}
	}
	return Module{}, false
}
