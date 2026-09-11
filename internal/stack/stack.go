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
	ImplShell    Impl = "shell"
	ImplExternal Impl = "external"
)

const (
	GroupResolve = "解析链路"
	GroupRouting = "分流数据"
	GroupRules   = "规则构建"
	GroupOps     = "面板与运维"
)

const (
	RoleCNResolver    = "cn-resolver"
	RoleGlobalBuilder = "global-builder"
)

var GroupOrder = []string{GroupResolve, GroupRouting, GroupRules, GroupOps}

type Module struct {
	Unit     string
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

func (m Module) HasRole(role string) bool {
	for _, item := range m.Roles {
		if item == role {
			return true
		}
	}
	return false
}

var both = []string{RoleCNResolver, RoleGlobalBuilder}

var modules = []Module{
	{
		Unit: "mosproxy", Name: "DNS 入口", Group: GroupResolve,
		Purpose: "接收你设备发来的 DoH/DoT 查询，按规则决定走本机递归还是香港递归",
		Kind:    KindDaemon, Impl: ImplExternal, Roles: []string{RoleCNResolver}, Critical: true,
	},
	{
		Unit: "unbound", Name: "递归解析器", Group: GroupResolve,
		Purpose: "自己从根服务器一级级问下来，不依赖任何公共 DNS",
		Kind:    KindDaemon, Impl: ImplExternal, Roles: both, Critical: true,
	},
	{
		Unit: "dns-stack-recursive-routing", Name: "出口分流", Group: GroupResolve,
		Purpose: "按目标权威服务器的 IP 归属，决定这一跳走大陆直连还是香港隧道",
		Kind:    KindDaemon, Impl: ImplShell, Roles: []string{RoleCNResolver}, Critical: true,
	},
	{
		Unit: "wg-quick@wg0", Name: "香港隧道", Group: GroupResolve,
		Purpose: "通往香港节点的 WireGuard 隧道，境外权威的查询从这里出去",
		Kind:    KindDaemon, Impl: ImplExternal, Roles: both, Critical: true,
	},
	{
		Unit: "dns-stack-routing-watchdog", Name: "分流看门狗", Group: GroupResolve,
		Purpose: "定期确认分流规则还在内核里，被其他程序刷掉时自动补回",
		Kind:    KindJob, Impl: ImplShell, Roles: []string{RoleCNResolver}, Every: time.Minute,
	},

	{
		Unit: "dns-stack-chnroute", Name: "大陆网段", Group: GroupRouting,
		Purpose: "从 APNIC 官方委派记录重建大陆 IPv4 网段表，是所有归属判定的底座",
		Kind:    KindJob, Impl: ImplShell, Roles: []string{RoleCNResolver},
		Artifact: "chnroute/direct4.txt", Every: 24 * time.Hour,
	},
	{
		Unit: "dns-stack-cn-authority", Name: "国内权威地址", Group: GroupRouting,
		Purpose: "记录国内域名的权威服务器地址，让它们的查询走直连而不是绕香港",
		Kind:    KindJob, Impl: ImplShell, Roles: []string{RoleCNResolver},
		Artifact: "chnroute/cn-authority.txt", Every: 15 * time.Minute,
	},
	{
		Unit: "dns-stack-shared-anycast", Name: "共享 anycast 识别", Group: GroupRouting,
		Purpose: "识别多租户 DNS 服务商的共享节点，避免把它们误当成国内权威",
		Kind:    KindJob, Impl: ImplGo, Roles: []string{RoleCNResolver},
		Artifact: "chnroute/shared-anycast.txt", Every: time.Hour,
	},
	{
		Unit: "dns-stack-geoip", Name: "归属库更新", Group: GroupRouting,
		Purpose: "更新纯真/MaxMind/DB-IP 归属库，IP 查省市运营商靠它",
		Kind:    KindJob, Impl: ImplShell, Roles: []string{RoleCNResolver},
		Artifact: "geoip/qqwry.ipdb", Every: 24 * time.Hour,
	},
	{
		Unit: "dns-stack-geo-cross", Name: "归属交叉校验", Group: GroupRouting,
		Purpose: "拿多个归属库互相对照，挑出「纯真说是大陆、别家说不是」的争议网段",
		Kind:    KindJob, Impl: ImplGo, Roles: []string{RoleCNResolver},
		Artifact: "chnroute/geo-disputed.txt", Every: 24 * time.Hour,
	},
	{
		Unit: "dns-stack-ecs-zone", Name: "ECS 缓存分片", Group: GroupRouting,
		Purpose: "按省份+运营商切分缓存，让 CDN 给你的是本地节点而不是外省节点",
		Kind:    KindJob, Impl: ImplGo, Roles: []string{RoleCNResolver},
		Artifact: "ecs-ip-zone.txt", Every: 24 * time.Hour,
	},
	{
		Unit: "dns-stack-collect-polluted", Name: "污染 IP 采集", Group: GroupRouting,
		Purpose: "采集 GFW 投毒返回的假地址，作为判定域名被污染的证据",
		Kind:    KindJob, Impl: ImplShell, Roles: []string{RoleCNResolver},
		Artifact: "polluted-ip.txt", Every: 6 * time.Hour,
	},
	{
		Unit: "dns-stack-sync-rules", Name: "规则同步", Group: GroupRouting,
		Purpose: "从 GitHub 拉取最新的四文件规则包并热加载进 mosproxy",
		Kind:    KindJob, Impl: ImplShell, Roles: []string{RoleCNResolver},
		Artifact: "cn.txt", Every: 5 * time.Minute,
	},

	{
		Unit: "dns-stack-reference-data", Name: "参考数据", Group: GroupRules,
		Purpose: "更新公共后缀列表与中国 IP 参考表，域名切分靠它",
		Kind:    KindJob, Impl: ImplGo, Roles: []string{RoleGlobalBuilder},
		Artifact: "reference/public_suffix_list.dat", Every: 24 * time.Hour,
	},
	{
		Unit: "dns-stack-classify", Name: "域名分类", Group: GroupRules,
		Purpose: "同一域名在国内和香港各解析一次，比对两份答案判定国内/被墙",
		Kind:    KindJob, Impl: ImplGo, Roles: []string{RoleGlobalBuilder},
		Artifact: "publish/cn.txt", Every: 5 * time.Minute,
	},
	{
		Unit: "dns-stack-verify", Name: "规则复检", Group: GroupRules,
		Purpose: "对已生效的规则持续重判，域名换了服务商就及时纠正",
		Kind:    KindJob, Impl: ImplGo, Roles: []string{RoleGlobalBuilder}, Every: 30 * time.Minute,
	},
	{
		Unit: "dns-stack-publish", Name: "规则发布", Group: GroupRules,
		Purpose: "把复检通过的规则包推到 GitHub，供各台递归节点拉取",
		Kind:    KindJob, Impl: ImplGo, Roles: []string{RoleGlobalBuilder}, Every: 6 * time.Hour,
	},

	{
		Unit: "dns-stack-panel", Name: "管理面板", Group: GroupOps,
		Purpose: "就是你现在看的这个界面",
		Kind:    KindDaemon, Impl: ImplGo, Roles: both,
	},
	{
		Unit: "dns-stack-helper", Name: "特权助手", Group: GroupOps,
		Purpose: "面板要动系统时经它代办，只放行白名单内的操作",
		Kind:    KindDaemon, Impl: ImplGo, Roles: both, Critical: true,
	},
	{
		Unit: "dns-stack-renew-cert", Name: "证书续签", Group: GroupOps,
		Purpose: "检查 TLS 证书剩余天数，到期前自动续签",
		Kind:    KindJob, Impl: ImplShell, Roles: []string{RoleCNResolver}, Every: 6 * time.Hour,
	},
	{
		Unit: "dns-stack-backup", Name: "自动备份", Group: GroupOps,
		Purpose: "每天备份数据库、配置与规则",
		Kind:    KindJob, Impl: ImplShell, Roles: both, Every: 24 * time.Hour,
	},
}

func All() []Module { return modules }

func ForRole(role string) []Module {
	if role != RoleCNResolver && role != RoleGlobalBuilder {
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
