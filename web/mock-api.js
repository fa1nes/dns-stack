
'use strict';

(function () {
  const now = () => Math.floor(Date.now() / 1000);

  const geo = (label, region, carrier, country) => ({
    available: true, label, region, city: region, carrier,
    country: country || 'CN', owner: '示例机构', asn: 64500,
    as_org: 'Example Network', source: 'mock',
  });
  const geoDown = { available: false, label: null, error: '归属库未安装(示例)' };

  const CN_NODE = geo('甲省 A 网', '甲省', 'A 网');
  const NEAR_NODE = geo('乙省 A 网', '乙省', 'A 网');
  const XNET_NODE = geo('甲省 B 网', '甲省', 'B 网');
  const OVERSEAS = geo('境外机房', null, null, 'SG');

  const UPSTREAMS = [
    { tag: 'local-unbound', online: true, query_total: 128340, err_total: 12,
      success_ratio: 99.99, stale_failures: false, avg_latency_ms: 18.4,
      p95_latency_ms: 96, direction: '本机递归' },
    { tag: 'foreign-hk', online: true, query_total: 0, err_total: 0,
      success_ratio: null, stale_failures: false, avg_latency_ms: null,
      p95_latency_ms: null, direction: '香港递归' },
  ];

  const OVERVIEW = {
    role: 'cn-resolver', ts: now(),
    mosproxy: {
      available: true, avg_latency_ms: 21.3, latency_samples: 40218,
      query_total: 512883, query_total_synthetic: true,
      cache_hit_total: 394117, cache_hit_ratio: 76.84, qps: 3.7,
      prefetch_total: 8241, cache_entries: 12043,
      rejected_cc: 0, rejected_qps: 0,
      upstream_query_total: 118766, upstream_err_total: 143, error_ratio: 0.12,
    },
    unbound: {
      available: true, queries: 118766, cache_hits: 91204, cache_miss: 27562,
      cache_hit_ratio: 76.8, prefetch: 6132,
      recursion_time_avg_ms: 214.7, recursion_time_median_ms: 88.2,
      requestlist_current: 3,
    },
    system: {
      disk: { total: 42949672960, used: 12884901888, free: 30064771072, percent: 30.0 },
      memory: { total: 1971322880, available: 1073741824, used: 897581056, percent: 45.5 },
      load: { '1m': 0.34, '5m': 0.41, '15m': 0.38 }, cpu_count: 4,
      uptime_seconds: 1904400,
    },
    events: { last_5m: 214, last_1h: 4389, domains: 853,
              latency: { samples: 4102, avg: 12.4, p50: 1.2, p95: 486, sampled: false, slow_1s: 7 } },
    routing: { direct4_count: 5813, cn_zones_count: 270, cn_authority_count: 387,
               chain_active: true, tunnel_active: true },
    upstreams: UPSTREAMS,
  };

  const QTYPES = ['A', 'AAAA', 'HTTPS', 'CNAME', 'TXT'];
  const RCODES = [[0, 'NOERROR'], [0, 'NOERROR'], [0, 'NOERROR'], [3, 'NXDOMAIN'], [2, 'SERVFAIL']];
  const HOSTS = ['www.example.com', 'cdn.example.net', 'api.example.org',
                 'img.example.com', 'static.example.net', 'a.example.org'];

  function mkEvent(i) {
    const [rcode, rcode_name] = RCODES[i % RCODES.length];
    const cached = i % 3 === 0;
    const foreign = i % 7 === 0;
    return {
      id: 100000 - i, ts: now() - i * 7,
      domain: HOSTS[i % HOSTS.length], qtype: 1, qtype_name: QTYPES[i % QTYPES.length],
      rcode, rcode_name,
      resp_by: cached ? 'cache' : (foreign ? 'foreign-hk' : 'local-unbound'),
      route: cached ? 'cache' : (foreign ? 'foreign' : 'cn'),
      route_name: cached ? '缓存命中' : (foreign ? '香港递归' : '本机递归'),
      cache_hit: cached,
      elapsed_ms: i % 11 === 0 ? null : (cached ? 0.42 : 186.3),
      exit_path: cached ? 'cache' : (foreign ? 'hongkong' : (i % 2 ? 'direct' : 'tunnel')),
    };
  }

  const ROUTING_DETAIL = {
    manual_rule: null, direction: 'adaptive', zone: null,
    reason: '各级权威尚未观测到大陆 IP，按每跳权威的 IP 归属分流',
    zone_queried: 'example.com',
    authorities: [
      { ns: 'ns1.example.com', ip: '203.0.113.10', in_cn: true, geo: CN_NODE, exit: 'direct' },
      { ns: 'ns2.example.net', ip: '198.51.100.20', in_cn: false, geo: OVERSEAS, exit: 'tunnel' },
    ],
    exits: { available: true, direct: '203.0.113.1', tunnel: '198.51.100.1', tunnel_note: null },
    geoip_status: { available: true, degraded: false },
    result_ip: '203.0.113.30', result_in_cn: true, result_geo: CN_NODE,
    result_ips_geo: [
      { ip: '203.0.113.30', in_cn: true, geo: CN_NODE },
      { ip: '203.0.113.31', in_cn: true, geo: NEAR_NODE },
    ],
  };

  const RECORDS = (type) => ({
    status: 'NOERROR', query_time_ms: 24,
    records: [
      { name: 'www.example.com.', ttl: 300, class: 'IN', type: 'CNAME', value: 'cdn.example.net.' },
      { name: 'cdn.example.net.', ttl: 60, class: 'IN', type: type, value: '203.0.113.30' },
    ],
  });

  const OPS = [
    ['sync_rules', '同步四文件规则', false], ['rollback_rules', '回滚上一版规则', true],
    ['collect_polluted_ip', '采集污染 IP', false], ['rotate_doh_path', '轮换 DoH 私密路径', true],
    ['set_cache_ttl', '调整乐观缓存时长', false], ['reload_mosproxy', '重载 mosproxy 域名表', false],
    ['restart_mosproxy', '重启 mosproxy', true], ['restart_unbound', '重启 Unbound', true],
    ['healthcheck', '执行健康检查', false], ['cert_check', '检查证书', false],
    ['cert_renew', '续签证书', true], ['backup', '立即备份', false],
    ['purge_legacy', '清理旧架构数据', true], ['clear_audit', '清空审计记录', true],
    ['vacuum_logs', '清理系统日志(保留7天)', true], ['clear_domains', '清理陈旧域名(7天未出现)', true],
    ['clear_domains_all', '清空全部域名统计', true], ['set_arch_epoch', '重设统计起点', true],
    ['export', '导出迁移包', false],
  ];

  const MODULES = [
    ['解析链路', 'mosproxy', 'DNS 入口', '接收你设备发来的 DoH/DoT 查询，按规则决定走本机递归还是香港递归', 'daemon', 'external', 1],
    ['解析链路', 'unbound', '递归解析器', '自己从根服务器一级级问下来，不依赖任何公共 DNS', 'daemon', 'external', 1],
    ['解析链路', 'dns-stack-recursive-routing', '出口分流', '按目标权威服务器的 IP 归属，决定这一跳走大陆直连还是香港隧道', 'daemon', 'shell', 1],
    ['解析链路', 'wg-quick@wg0', '香港隧道', '通往香港节点的 WireGuard 隧道，境外权威的查询从这里出去', 'daemon', 'external', 1],
    ['解析链路', 'dns-stack-routing-watchdog', '分流看门狗', '定期确认分流规则还在内核里，被其他程序刷掉时自动补回', 'job', 'shell', 0],
    ['分流数据', 'dns-stack-chnroute', '大陆网段', '从 APNIC 官方委派记录重建大陆 IPv4 网段表，是所有归属判定的底座', 'job', 'shell', 0],
    ['分流数据', 'dns-stack-cn-authority', '国内权威地址', '记录国内域名的权威服务器地址，让它们的查询走直连而不是绕香港', 'job', 'shell', 0],
    ['分流数据', 'dns-stack-shared-anycast', '共享 anycast 识别', '识别多租户 DNS 服务商的共享节点，避免把它们误当成国内权威', 'job', 'go', 0],
    ['分流数据', 'dns-stack-geoip', '归属库更新', '更新纯真/MaxMind/DB-IP 归属库，IP 查省市运营商靠它', 'job', 'shell', 0],
    ['分流数据', 'dns-stack-geo-cross', '归属交叉校验', '拿多个归属库互相对照，挑出「纯真说是大陆、别家说不是」的争议网段', 'job', 'go', 0],
    ['分流数据', 'dns-stack-ecs-zone', 'ECS 缓存分片', '按省份+运营商切分缓存，让 CDN 给你的是本地节点而不是外省节点', 'job', 'go', 0],
    ['分流数据', 'dns-stack-collect-polluted', '污染 IP 采集', '采集 GFW 投毒返回的假地址，作为判定域名被污染的证据', 'job', 'shell', 0],
    ['分流数据', 'dns-stack-sync-rules', '规则同步', '从 GitHub 拉取最新的四文件规则包并热加载进 mosproxy', 'job', 'shell', 0],
    ['面板与运维', 'dns-stack-panel', '管理面板', '就是你现在看的这个界面', 'daemon', 'go', 0],
    ['面板与运维', 'dns-stack-helper', '特权助手', '面板要动系统时经它代办，只放行白名单内的操作', 'daemon', 'go', 1],
    ['面板与运维', 'dns-stack-renew-cert', '证书续签', '检查 TLS 证书剩余天数，到期前自动续签', 'job', 'shell', 0],
    ['面板与运维', 'dns-stack-backup', '自动备份', '每天备份数据库、配置与规则', 'job', 'shell', 0],
  ];
  const UNITS = MODULES.map((m) => m[1]);

  const ROUTES = {

    '/api/bootstrap': () => ({
      auth_enabled: true,
      totp_enabled: false,
      role: 'cn-resolver',
      role_name: '国内 DNS 服务器（示例）',
      log_units: ['mosproxy', 'unbound', 'dns-stack-collector', 'dns-stack-panel'],
    }),

    '/api/overview': () => OVERVIEW,

    '/api/timeseries': (q) => {
      const span = Number(q.get('span') || 3600), buckets = Number(q.get('buckets') || 72);
      const step = Math.max(Math.floor(span / buckets), 1), start = now() - span;
      const series = [];
      for (let b = 0; b <= buckets; b++) {
        const w = Math.sin(b / 6) * 0.5 + 0.5;
        series.push({ t: start + b * step, cn: Math.round(18 + w * 26),
                      foreign: b % 9 === 0 ? 1 : 0, cache: Math.round(52 + w * 60),
                      reject: 0, unknown: 0 });
      }
      return { series, step, start, end: now() };
    },

    '/api/queries': (q) => {
      const page = Number(q.get('page') || 1), size = Number(q.get('size') || 50);
      const items = [];
      for (let i = 0; i < size; i++) items.push(mkEvent((page - 1) * size + i));
      return { items, total: 3184, page, size, pages: Math.ceil(3184 / size), total_capped: false };
    },

    '/api/domains': (q) => {
      const metric = q.get('metric') || 'new';
      const size = Number(q.get('size') || 50), page = Number(q.get('page') || 1);
      const items = [];
      for (let i = 0; i < Math.min(size, 24); i++) {
        const base = { domain: HOSTS[i % HOSTS.length].replace('www.', 'h' + i + '.') };
        if (metric === 'slow') {
          items.push(Object.assign(base, { samples: 12 - (i % 9), avg_ms: 1840 - i * 63,
                                           max_ms: 3120 - i * 51, last_seen_at: now() - i * 300 }));
        } else {
          const [rcode, rcode_name] = RCODES[i % RCODES.length];
          items.push(Object.assign(base, {
            first_seen_at: now() - 86400 * (i + 1), last_seen_at: now() - i * 180,
            occurrence_count: 940 - i * 31, fail_count: i % 5 === 0 ? i : 0,
            last_rcode: rcode, last_rcode_name: rcode_name,
            last_route: i % 7 === 0 ? 'foreign' : 'cn',
            last_route_name: i % 7 === 0 ? '香港递归' : '本机递归',
            node: i === 3 ? undefined
              : { ip: '203.0.113.' + (20 + i), geo: i % 4 === 0 ? geoDown : CN_NODE },
          }));
        }
      }
      return { items, metric, total: 853, page, size, pages: Math.ceil(853 / size) };
    },

    '/api/domains/summary': () => ({
      by_route: [{ route: 'cn', route_name: '本机递归', count: 731 },
                 { route: 'cache', route_name: '缓存命中', count: 96 },
                 { route: 'foreign', route_name: '香港递归', count: 26 }],
      by_exit: [{ path: 'direct', name: '直连出网', count: 2841 },
                { path: 'tunnel', name: '经隧道', count: 1163 },
                { path: 'cache', name: '缓存命中', count: 5210 },
                { path: 'hongkong', name: '香港递归器', count: 12 }],
      new_24h: 37, active_1h: 118, failing: 6,
      by_qtype: [{ qtype: 1, name: 'A', count: 5210 }, { qtype: 28, name: 'AAAA', count: 3106 },
                 { qtype: 65, name: 'HTTPS', count: 902 }],
      by_rcode: [{ rcode: 0, name: 'NOERROR', count: 8841 },
                 { rcode: 3, name: 'NXDOMAIN', count: 341 },
                 { rcode: 2, name: 'SERVFAIL', count: 36 }],
    }),

    '/api/domain/': (q, path) => {
      const name = decodeURIComponent(path.split('/api/domain/')[1] || 'www.example.com');
      return {
        domain: name,
        aggregate: { occurrence_count: 612, fail_count: 3, last_rcode_name: 'NOERROR',
                     last_route_name: '本机递归', first_seen_at: now() - 604800,
                     last_seen_at: now() - 42 },
        by_upstream: [{ resp_by: 'local-unbound', count: 431 }, { resp_by: 'cache', count: 181 }],
        recent: [0, 1, 2, 3, 4].map(mkEvent),
        routing: ROUTING_DETAIL,
        live: { 'local-unbound': { A: RECORDS('A'), AAAA: { status: 'NOERROR', records: [] },
                                   CNAME: { status: 'NOERROR', records: [] } },
                'foreign-hk': { A: { error: '上游不可用(示例)' }, AAAA: { status: 'NOERROR', records: [] },
                                CNAME: { status: 'NOERROR', records: [] } } },
      };
    },

    '/api/my-location': () => ({
      client_ip: '203.0.113.77', geo: CN_NODE, ecs: '203.0.113.0/24',
      nodes: [
        { name: '站点一', domain: 'a.example.com', ip: '203.0.113.30', geo: CN_NODE },
        { name: '站点二', domain: 'b.example.com', ip: '203.0.113.41', geo: NEAR_NODE },
        { name: '站点三', domain: 'c.example.com', ip: '203.0.113.52', geo: XNET_NODE },
        { name: '站点四', domain: 'd.example.com', ip: '198.51.100.60', geo: OVERSEAS },
        { name: '站点五', domain: 'e.example.com', ip: null, error: '解析超时(示例)', geo: null },
      ],
    }),

    '/api/rules': () => ({
      cn_count: 270, gfw_count: 325, manual_cn_count: 4, manual_gfw_count: 2,
      cn_cidr_count: 5813, polluted_cidr_count: 40, polluted_ip_count: 40,
      direct4_count: 5813, cn_authority_count: 387, cn_zones_matched_count: 270,
      manual_cn_zones_count: 6,
      updated_at: now() - 7200,
      last_sync_at: now() - 180,
      polluted_ip_updated_at: now() - 21600,
      sources: {
        github_raw_base: 'https://raw.githubusercontent.com/example/dns-rules',
        github_mirror_1: 'https://mirror1.example.com/example/dns-rules',
        github_mirror_2: '',
        github_repository: 'example/dns-rules',
        github_branch: 'main',
      },
      history: ['2026-01-01T00:00:00Z applied gen=1767225600',
                '2026-01-01T00:05:00Z unchanged gen=1767225600'],
      rollback_versions: [{ name: 'bundle-20260101-000000', count: 6448, mtime: now() - 3600 }],
    }),

    '/api/collected': () => {
      const cidrs = [], zones = [], auth = [];
      for (let i = 0; i < 240; i++) cidrs.push('203.0.113.' + (i % 256) + '/24');
      for (let i = 0; i < 60; i++) zones.push('z' + i + '.example.com');
      for (let i = 0; i < 90; i++) auth.push('198.51.100.' + i + '/24');
      return {
        domains_total: 853, domains_active_24h: 411, queries_24h: 9218,
        data: { cn_zones: zones, direct4: cidrs, cn_authority: auth, polluted: ['192.0.2.7'] },
        data_meta: {
          cn_zones: { returned: zones.length, total: 270, truncated: true },
          direct4: { returned: cidrs.length, total: 5813, truncated: true },
          cn_authority: { returned: auth.length, total: 387, truncated: true },
          polluted: { returned: 1, total: 1, truncated: false },
        },
        ip: { direct4: 5813, cn_authority: 387, cn_zones: 270, polluted: 1, polluted_cidr: 40 },
        failing_domains: [{ domain: 'example.org', subdomains: 12, count: 85 },
                          { domain: 'example.net', subdomains: 3, count: 11 }],
      };
    },

    '/api/cert': () => ({ exists: true, not_before: 'Jan  1 00:00:00 2026 GMT',
                          not_after: 'Jan  7 00:00:00 2026 GMT', issuer: 'CN=Example CA',
                          san: 'IP Address:203.0.113.1', days_left: 5 }),

    '/api/cache': () => ({ mosproxy: { optimistic_ttl: 86400, maximum_ttl: 3600 },
                           unbound: { 'serve-expired-ttl': 604800,
                                      'serve-expired-client-timeout': 400,
                                      'cache-max-ttl': 86400 } }),

    '/api/doh': () => ({ doh_url: 'https://203.0.113.1/dns-query', is_default: true }),

    '/api/modules': () => {
      const notes = { 'dns-stack-geo-cross': ['warn', '从未运行过'],
                      'dns-stack-renew-cert': ['warn', '已经 4 天没有运行'] };
      const counts = { ok: 0, warn: 0, down: 0, unknown: 0 };
      const attention = [];
      const byGroup = {};
      const impl = {};
      MODULES.forEach((m, i) => {
        const [group, unit, name, purpose, kind, kindImpl, critical] = m;
        const hit = notes[unit];
        const state = hit ? hit[0] : 'ok';
        counts[state]++;
        impl[kindImpl] = (impl[kindImpl] || 0) + 1;
        if (hit) attention.push(name + '：' + hit[1]);
        const note = hit ? hit[1] : (kind === 'daemon' ? '运行中' : (i % 3 + 1) + ' 小时前运行过');
        (byGroup[group] = byGroup[group] || []).push({
          unit, name, group, purpose, kind, impl: kindImpl, critical: !!critical,
          state, note, active: kind === 'daemon' ? 'active' : 'waiting',
          last_run: hit && hit[1] === '从未运行过' ? null : now() - (i + 1) * 3600,
          next_run: kind === 'job' ? now() + (i + 1) * 1800 : null,
          memory: kind === 'daemon' ? 20971520 + i * 1048576 : null,
          restarts: 0,
          artifact: kind === 'job' ? { path: unit + '.txt', exists: !hit, lines: hit ? null : 1200 + i * 37 } : undefined,
        });
      });
      const verdict = counts.down ? 'down' : (counts.warn ? 'warn' : 'ok');
      return {
        role: 'cn-resolver', verdict, total: MODULES.length, counts, impl, attention,
        headline: verdict === 'ok' ? '全部正常' : attention.length + ' 个模块需要关注',
        groups: ['解析链路', '分流数据', '规则构建', '面板与运维']
          .filter((g) => byGroup[g])
          .map((g) => ({ name: g, modules: byGroup[g],
                         state: byGroup[g].some((x) => x.state !== 'ok') ? 'warn' : 'ok' })),
      };
    },

    '/api/backups': () => ({
      backups: [{ name: 'backup-20260101.tar.zst', size: 4194304, mtime: now() - 3600 }],
      exports: [{ name: 'export-state-20260101.tar.zst', size: 8388608, mtime: now() - 7200 }],
    }),

    '/api/audit': () => ({
      items: [0, 1, 2, 3].map((i) => ({
        id: 40 - i, ts: now() - i * 900, actor: 'panel',
        operation: OPS[i % OPS.length][0], args: '', ok: i !== 2,
        message: i === 2 ? '执行失败(示例)' : '执行成功',
      })),
    }),

    '/api/ops': () => ({ role: 'cn-resolver',
      ops: OPS.map(([op, label, dangerous]) => ({ op, label, dangerous, timeout: 60 })) }),

    '/api/auth/config': () => ({
      password_disabled: false, totp_enabled: false,
      oauth: { client_id: '', allowed_users: [], ready: false,
               secret_set: false, verified_once: false },
    }),

    '/api/logs': (q) => {
      const unit = q.get('unit') || 'mosproxy';
      const lines = [];
      for (let i = 0; i < Number(q.get('lines') || 200) / 4; i++) {
        lines.push(`Jan 01 00:0${i % 10}:00 host ${unit}[1234]: 示例信息日志 #${i}`);
        lines.push(`Jan 01 00:0${i % 10}:01 host ${unit}[1234]: warning: 示例警告 #${i}`);
        lines.push(`Jan 01 00:0${i % 10}:02 host ${unit}[1234]: error: 示例错误 #${i}`);
        lines.push(`Jan 01 00:0${i % 10}:03 host ${unit}[1234]: query 203.0.113.x -> example.com`);
      }
      return { unit, lines, count: lines.length };
    },

    '/api/health': () => ({ ok: true, role: 'cn-resolver', ts: now() }),
  };

  function postResult(path, body) {
    if (path === '/api/dns-test') {
      return { domain: (body && body.domain) || 'www.example.com',
               qtype: (body && body.qtype) || 'A',
               results: { 'local-unbound': Object.assign({ panel_elapsed_ms: 31 }, RECORDS('A')),
                          'foreign-hk': { error: '上游不可用(示例)', panel_elapsed_ms: 12 } },
               routing: ROUTING_DETAIL };
    }
    if (path.startsWith('/api/action/')) {
      const op = path.slice('/api/action/'.length);
      if (op === 'set_rule_sources') {
        return { ok: true, operation: op,
                 stdout: '规则源已更新，下次 sync-rules 运行时生效(预览模式)' };
      }
      return { ok: true, operation: op, label: op, message: '（预览模式）未真正执行：' + op,
               stdout: '', stderr: '' };
    }
    if (path === '/api/auth/totp/setup') {
      return { secret: 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP',
               uri: 'otpauth://totp/Example:admin?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=Example' };
    }
    return { ok: true, message: '（预览模式）操作已模拟完成' };
  }

  function exportResponse(q) {
    const ds = q.get('dataset') || '', fmt = q.get('format') || 'json';
    const bad = (msg) => new Response(JSON.stringify({ error: msg }),
      { status: 400, headers: { 'Content-Type': 'application/json' } });
    if (['queries', 'domains', 'rules'].indexOf(ds) < 0) return bad('不支持的 dataset 参数');
    if ((fmt !== 'json' && fmt !== 'csv') || (ds === 'rules' && fmt === 'csv')) {
      return bad('不支持的 format 参数');
    }
    let data;
    if (ds === 'rules') {
      data = ROUTES['/api/rules']();
    } else if (ds === 'domains') {
      data = [0, 1, 2].map((i) => ({
        domain: HOSTS[i], first_seen_at: now() - 86400 * (i + 1), last_seen_at: now() - i * 180,
        occurrence_count: 940 - i * 31, fail_count: 0, last_rcode: 0, last_route: 'cn',
        last_rcode_name: 'NOERROR', last_route_name: '本机递归',
      }));
    } else {
      data = [0, 1, 2].map((i) => Object.assign(mkEvent(i), { prefetch: false }));
    }
    const headers = { 'Content-Disposition': 'attachment; filename="dns-stack-' + ds + '.' + fmt + '"' };
    if (fmt === 'csv') {
      const cols = Object.keys(data[0]);
      const esc = (v) => {
        const s = v === null || v === undefined ? '' : String(v);
        return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
      };
      const text = [cols.join(',')].concat(data.map((r) => cols.map((c) => esc(r[c])).join(','))).join('\n') + '\n';
      headers['Content-Type'] = 'text/csv; charset=utf-8';
      return new Response(text, { status: 200, headers });
    }
    headers['Content-Type'] = 'application/json; charset=utf-8';
    return new Response(JSON.stringify(data), { status: 200, headers });
  }

  const realFetch = window.fetch.bind(window);
  window.fetch = function (input, init) {
    const url = typeof input === 'string' ? input : (input && input.url) || '';
    if (url.indexOf('/api/') < 0) return realFetch(input, init);

    const u = new URL(url, 'http://preview.local');
    const method = ((init && init.method) || 'GET').toUpperCase();
    let body = null;
    try { body = init && init.body ? JSON.parse(init.body) : null; } catch (e) {  }

    let data;
    if (method !== 'GET') {
      data = postResult(u.pathname, body);
    } else {
      if (u.pathname === '/api/export') {
        return new Promise((resolve) => setTimeout(() => resolve(exportResponse(u.searchParams)), 120));
      }
      const key = u.pathname.startsWith('/api/domain/') ? '/api/domain/' : u.pathname;
      const gen = ROUTES[key];
      data = gen ? gen(u.searchParams, u.pathname) : { error: '预览模式未提供该接口: ' + u.pathname };
    }
    return new Promise((resolve) => setTimeout(() => resolve(new Response(
      JSON.stringify(data), { status: 200, headers: { 'Content-Type': 'application/json' } })), 120));
  };

  window.EventSource = function (url) {
    const self = this;
    self.url = url; self.readyState = 1;
    self.onmessage = null; self.onerror = null; self.onopen = null;
    let seq = 0;
    setTimeout(() => { if (self.onopen) self.onopen({}); }, 60);
    const isLog = url.indexOf('/logs/') >= 0;
    const timer = setInterval(() => {
      if (!self.onmessage) return;
      seq += 1;
      const payload = isLog
        ? { lines: [`Jan 01 00:00:${String(seq % 60).padStart(2, '0')} host mosproxy[1234]: 示例实时日志 #${seq}`] }
        : { events: [mkEvent(seq)] };
      self.onmessage({ data: JSON.stringify(payload) });
    }, 1500);
    self.close = function () { clearInterval(timer); self.readyState = 2; };
  };

  console.info('[预览模式] 假后端已挂载：所有数据为虚构样例，写操作不会真正执行。');
})();
