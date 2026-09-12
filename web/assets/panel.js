
'use strict';

const esc = (s) => String(s === null || s === undefined ? '' : s).replace(
  /[&<>"'`=\/]/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;',
    "'": '&#39;', '`': '&#96;', '=': '&#61;', '/': '&#47;',
  }[c]));

const raw = (s) => ({ __html: String(s) });
const isRaw = (v) => v && typeof v === 'object' && typeof v.__html === 'string';

function html(strings, ...values) {
  let out = strings[0];
  for (let i = 0; i < values.length; i++) {
    const v = values[i];
    if (Array.isArray(v)) out += v.map((x) => (isRaw(x) ? x.__html : esc(x))).join('');
    else if (isRaw(v)) out += v.__html;
    else out += esc(v);
    out += strings[i + 1];
  }
  return raw(out);
}

const _parseTpl = document.createElement('template');
const TEMPLATE_HTML_SINK = 'innerHTML';

function parseFragment(content) {
  _parseTpl[TEMPLATE_HTML_SINK] = isRaw(content) ? content.__html : esc(content);
  return _parseTpl.content;
}

function setHtml(el, content) {
  if (el) el.replaceChildren(parseFragment(content));
}

function appendHtml(el, content) {
  if (el) el.appendChild(parseFragment(content));
}

function prependHtml(el, content) {
  if (el) el.insertBefore(parseFragment(content), el.firstChild);
}

function trimChildren(el, keep) {
  if (!el) return;
  while (el.children.length > keep) el.lastElementChild.remove();
}

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
const pad2 = (n) => String(n).padStart(2, '0');

function fmtTime(ts) {
  if (!ts) return '—';
  const d = new Date(ts * 1000);
  return pad2(d.getMonth() + 1) + '-' + pad2(d.getDate()) + ' ' +
    pad2(d.getHours()) + ':' + pad2(d.getMinutes()) + ':' + pad2(d.getSeconds());
}
function fmtClock(ts) {
  const d = new Date(ts * 1000);
  return pad2(d.getHours()) + ':' + pad2(d.getMinutes()) + ':' + pad2(d.getSeconds());
}
function fmtBytes(n) {
  if (n === null || n === undefined) return '—';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0, v = Number(n);
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return v.toFixed(v >= 100 || i === 0 ? 0 : 1) + ' ' + u[i];
}
const fmtNum = (n) => {
  if (n === null || n === undefined) return '—';
  n = Number(n);
  if (n >= 1e8) return (n / 1e8).toFixed(n >= 1e9 ? 0 : 1).replace(/\.0$/, '') + ' 亿';
  if (n >= 1e5) return (n / 1e4).toFixed(n >= 1e6 ? 0 : 1).replace(/\.0$/, '') + ' 万';
  return n.toLocaleString('zh-CN');
};

const fmtNumFull = (n) => (n === null || n === undefined ? '—' : Number(n).toLocaleString('zh-CN'));

const dash = (v, unit) => (v === null || v === undefined ? '—' : String(v) + (unit || ''));

const recordLines = (records) => (records || [])
  .map((rec) => rec.type + '  TTL=' + dash(rec.ttl) + '  ' + rec.value).join('\n');
function fmtDuration(sec) {
  if (!sec) return '—';
  const d = Math.floor(sec / 86400);
  const h = Math.floor((sec % 86400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  if (d > 0) return d + ' 天 ' + h + ' 小时';
  if (h > 0) return h + ' 小时 ' + m + ' 分';
  return m + ' 分钟';
}
function ago(ts) {
  if (!ts) return '—';
  const s = Math.floor(Date.now() / 1000) - ts;
  if (s < 60) return s + ' 秒前';
  if (s < 3600) return Math.floor(s / 60) + ' 分钟前';
  if (s < 86400) return Math.floor(s / 3600) + ' 小时前';
  return Math.floor(s / 86400) + ' 天前';
}

const _getCache = new Map();
const _GET_TTL = 2500;

function invalidateCache() { _getCache.clear(); }

async function apiCached(path, ttl) {
  const hit = _getCache.get(path);
  const now = Date.now();
  if (hit && now - hit.t < (ttl || _GET_TTL)) return hit.v;
  const v = await api(path);
  _getCache.set(path, { t: now, v });
  return v;
}

async function api(path, opts) {
  if (opts && opts.method && opts.method !== 'GET') invalidateCache();
  const request = Object.assign(
    { headers: { 'Content-Type': 'application/json' }, credentials: 'include' },
    opts || {});
  const res = await fetch(
    (window.dnsStackApiUrl || ((p) => p))(path), request);
  let body = null;
  try { body = await res.json(); } catch (e) {  }
  if (res.status === 401 && body && body.need_login) {
    location.replace('login' + (location.hash || ''));
    throw new Error('会话已过期，正在跳转到登录页');
  }
  if (!res.ok) {
    const msg = (body && (body.message || body.error || body.detail)) || ('HTTP ' + res.status);
    const err = new Error(msg);
    err.status = res.status;
    err.body = body;
    throw err;
  }
  return body;
}

function toast(title, body, kind) {
  const el = document.createElement('div');
  el.className = 'toast ' + (kind || '');
  setHtml(el, html`<div class="t-title">${title}</div>${
    body ? html`<div class="t-body">${String(body).slice(0, 2000)}</div>` : raw('')}`);
  $('#toasts').appendChild(el);
  setTimeout(() => {
    el.style.opacity = '0';
    setTimeout(() => el.remove(), 250);
  }, kind === 'err' ? 12000 : 6000);
}

const stateHtml = (text, kind) => html`<div class="state ${kind || ''}">${text}</div>`;
const LOADING = raw('<div class="state"><span class="spinner"></span> 加载中…</div>');
const EMPTY = (t) => stateHtml(t || '暂无数据');
const errState = (e) => stateHtml('加载失败：' + e.message, 'error');
const rowSpan = (n, content) => html`<tr><td colspan="${n}">${content}</td></tr>`;

const ICON_PLAY = raw('<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><polygon points="6.5 4.8 19.5 12 6.5 19.2" fill="currentColor" stroke="none"/></svg>');
const ICON_PAUSE = raw('<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="6" y="4.8" width="4" height="14.4" rx="1.2" fill="currentColor" stroke="none"/><rect x="14" y="4.8" width="4" height="14.4" rx="1.2" fill="currentColor" stroke="none"/></svg>');
const ICON_WARN = raw('<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="width:12px;height:12px;vertical-align:-1.5px;margin-right:3px"><path d="M10.3 3.9 1.9 18a2 2 0 0 0 1.7 3h16.8a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/><line x1="12" y1="9" x2="12" y2="13.5"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>');

function setBtnState(btn, icon, label) {
  if (btn) setHtml(btn, html`${icon}${label}`);
}

function debounce(fn, ms) {
  let t = 0;
  return function () { clearTimeout(t); t = setTimeout(fn, ms); };
}

function textInflation() {
  try {
    const probe = document.createElement('span');
    probe.setAttribute('aria-hidden', 'true');
    probe.style.cssText = 'position:absolute;left:-9999px;top:0;font-size:14px;line-height:1';
    probe.textContent = 'M';
    document.body.appendChild(probe);
    const actual = parseFloat(getComputedStyle(probe).fontSize) || 14;
    probe.remove();
    return actual / 14;
  } catch (e) { return 1; }
}

function findOverflowingElements(limit) {
  const vw = document.documentElement.clientWidth;
  const hits = [];
  document.querySelectorAll('.page.active *').forEach((el) => {
    const r = el.getBoundingClientRect();
    if (r.width && (r.right > vw + 1 || r.left < -1)) {
      hits.push({ el: el, 标签: el.tagName.toLowerCase(), 类: el.className,
                  左: Math.round(r.left), 右: Math.round(r.right) });
    }
  });
  return hits.slice(0, limit || 8);
}

function showDiagnostics() {
  const de = document.documentElement;
  const vv = window.visualViewport;
  const cs = getComputedStyle(de);
  const bg = cs.getPropertyValue('--bg').trim();
  const inflate = textInflation();
  const over = de.scrollWidth - de.clientWidth;
  const sup = (prop, val) => {
    try { return (window.CSS && CSS.supports && CSS.supports(prop, val)) ? '是' : '否'; }
    catch (e) { return '未知'; }
  };
  const supSel = (sel) => {
    try { return (window.CSS && CSS.supports && CSS.supports('selector(' + sel + ')')) ? '是' : '否'; }
    catch (e) { return '否'; }
  };
  const bp = [440, 560, 640, 760, 860].filter(
    (w) => window.matchMedia('(max-width:' + w + 'px)').matches);

  const rows = [
    ['浏览器', navigator.userAgent],
    ['屏幕', screen.width + '×' + screen.height + '  dpr=' + (window.devicePixelRatio || 1)],
    ['布局视口', window.innerWidth + '×' + window.innerHeight],
    ['视觉视口', vv ? (Math.round(vv.width) + '×' + Math.round(vv.height)
        + '  scale=' + (Math.round(vv.scale * 1000) / 1000)
        + '  offset=' + Math.round(vv.offsetLeft)) : '不支持 visualViewport'],
    ['文字放大', Math.round(inflate * 100) + '%  (14px 实际渲染为 '
        + (Math.round(inflate * 14 * 10) / 10) + 'px)'],
    ['正文字号', getComputedStyle(document.body).fontSize],
    ['横向溢出', 'scrollWidth=' + de.scrollWidth + '  clientWidth=' + de.clientWidth
        + (over > 2 ? '  ← 溢出 ' + over + 'px' : '  (无)')],
    ['样式表', bg ? '已加载 (--bg=' + bg + ')' : '🔴 未加载或解析失败'],
    ['生效断点', bp.length ? bp.map((w) => '≤' + w).join(' ') : '无(按桌面布局渲染)'],
    ['特性支持', ':has()=' + supSel(':has(*)')
        + '  color-mix=' + sup('color', 'color-mix(in srgb, red, blue)')
        + '  min()=' + sup('width', 'min(10px, 2vw)')
        + '  safe-area=' + sup('padding-left', 'env(safe-area-inset-left)')],
    ['当前页', state.page + '  主题=' + (de.dataset.theme || '?')],
  ];

  const culprits = findOverflowingElements(6).map(
    (h) => h.标签 + (h.类 ? '.' + String(h.类).trim().split(/\s+/)[0] : '')
         + ' [' + h.左 + '→' + h.右 + ']');

  openDrawer('环境诊断');
  setHtml($('#drawerBody'), html`
    <div class="hint mb-8">下面是这台设备的真实状态。显示异常时把这一屏截图发出来，
      比描述现象快得多。此处不发起任何网络请求。</div>
    ${kvList(rows.map(([k, v]) => [k, html`<span class="mono">${v}</span>`]))}
    ${culprits.length ? html`<h4>越界元素（当前页）</h4>
      <pre class="block">${culprits.join('\n')}</pre>` : raw('')}
    <div class="hint">字大得异常 → 看「文字放大」是否 >100%；
      左右被切 → 看「横向溢出」；整页排版全丢 → 看「样式表」。</div>`);
}

function initTheme() {
  const saved = localStorage.getItem('dns-stack-theme');
  const prefersLight = window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches;
  document.documentElement.dataset.theme = saved || (prefersLight ? 'light' : 'dark');
  const toggle = () => {
    const next = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
    document.documentElement.dataset.theme = next;
    localStorage.setItem('dns-stack-theme', next);
  };
  const a = $('#themeToggle'); if (a) a.addEventListener('click', toggle);
  const b = $('#themeToggleMobile'); if (b) b.addEventListener('click', toggle);
}

function initSidebarFold() {
  const btn = $('#btnSideFold');
  if (!btn) return;
  const KEY = 'dns-stack-sidebar-fold';
  if (localStorage.getItem(KEY) === '1') document.body.classList.add('sb-fold');
  btn.addEventListener('click', () => {
    const on = document.body.classList.toggle('sb-fold');
    localStorage.setItem(KEY, on ? '1' : '0');
    btn.title = on ? '展开侧栏' : '收起侧栏';
    btn.setAttribute('aria-label', btn.title);
  });
}

function initSession() {
  const dot = $('#accessDot');
  const txt = $('#accessText');
  if (dot && txt) {
    const local = ['localhost', '127.0.0.1', '[::1]', '::1'].indexOf(location.hostname) >= 0;
    if (location.protocol === 'https:') {
      dot.className = 'dot ok';
      txt.textContent = 'HTTPS 已加密 · ' + location.host;
    } else if (local) {
      dot.className = 'dot ok';
      txt.textContent = '本机访问 · ' + location.host;
    } else {
      dot.className = 'dot err';
      txt.textContent = '明文连接 · ' + location.host;
    }
  }

  const logout = async () => {
    if (!confirm('确定退出登录？')) return;
    try { await api('/api/logout', { method: 'POST' }); } catch (e) {  }
    location.replace('login');
  };
  const locBtn = $('#btnMyLocRefresh');
  if (locBtn) locBtn.addEventListener('click', () => loadMyLocation(true));

  ['#btnLogout', '#btnLogoutMobile'].forEach((sel) => {
    const el = $(sel); if (el) el.addEventListener('click', logout);
  });
}

const state = {
  page: 'overview',
  overviewTimer: null,
  liveES: null, liveOn: false, liveLoaded: false,
  logES: null, logFollow: false, logLines: [],
  queryPage: 1, queryPages: 1,
  domMetric: 'new',
  domPage: 1, domPages: 1,
  tsData: null,
  upstreamLatency: {},
  upstreamTags: [],
};

const PAGE_TITLES = {
  overview: '概览', queries: '查询', tools: '工具', settings: '设置',
};

const PAGE_DESCS = {
  overview: '解析链路与系统资源的整体健康',
  queries: '逐条查询记录与域名聚合统计',
  tools: '解析测试、位置探测与日志',
  settings: '登录方式、规则、服务与审计',
};

const SETTING_TAB_LOADERS = {
  security: loadSecurity,
  rules: loadRules,
  services: loadOps,
  audit: loadAudit,
};
const _settingsLoaded = {};

function loadSettingTab(name) {
  if (_settingsLoaded[name]) return;
  _settingsLoaded[name] = true;
  (SETTING_TAB_LOADERS[name] || function () {})();
}

function switchPage(page) {
  state.page = page;
  $$('.page').forEach((p) => p.classList.toggle('active', p.id === 'page-' + page));
  $$('#nav button').forEach((b) => b.classList.toggle('active', b.dataset.page === page));
  $('#pageTitle').textContent = PAGE_TITLES[page] || page;
  const desc = $('#pageDesc');
  if (desc) desc.textContent = PAGE_DESCS[page] || '';

  if (page !== 'queries' && state.liveOn) stopLive();
  if (page !== 'tools' && state.logFollow) stopLogFollow();
  if (state.overviewTimer) { clearInterval(state.overviewTimer); state.overviewTimer = null; }

  const loaders = {
    overview: startOverview,
    queries: function () {
      initLivePage();
    },
    tools: function () {
      loadMyLocation();
    },
    settings: function () {
      const active = $('#settingTabs button.active');
      loadSettingTab(active ? active.dataset.stab : 'security');
    },
  };
  (loaders[page] || function () {})();
  location.hash = page;
}

function startOverview() {
  loadTimeseries();
  let sinceModules = Infinity;
  const tick = async () => {
    state.overviewTimer = 0;
    if (state.page !== 'overview') return;
    if (!document.hidden) {
      try { await loadOverview(); } catch (e) {  }
      if (sinceModules >= 30000) {
        sinceModules = 0;
        try { await loadModules(); } catch (e) {  }
      }
      sinceModules += 5000;
    }
    if (state.page === 'overview') state.overviewTimer = setTimeout(tick, 5000);
  };
  tick();
}

function cacheUpstreams(list) {
  if (!list || !list.length) return;
  const lat = {};
  const tags = [];
  list.forEach((u) => {
    tags.push(u.tag);
    if (u.avg_latency_ms !== null && u.avg_latency_ms !== undefined) lat[u.tag] = u.avg_latency_ms;
  });
  state.upstreamLatency = lat;
  state.upstreamTags = tags;
  syncRespByOptions();
}

function syncRespByOptions() {
  const sel = $('#fRespBy');
  if (!sel) return;
  const want = ['cache', ...state.upstreamTags];
  const have = Array.from(sel.options).map((o) => o.value).filter(Boolean);
  if (want.length === have.length && want.every((v, i) => v === have[i])) return;
  const cur = sel.value;
  const opts = [html`<option value="">全部上游</option>`,
    html`<option value="cache">缓存直接返回</option>`,
    ...state.upstreamTags.map((t) => html`<option value="${t}">${t}</option>`)];
  setHtml(sel, html`${opts}`);

  sel.value = (cur && want.indexOf(cur) >= 0) ? cur : '';
}

async function loadOverview() {
  try {

    const d = await apiCached('/api/overview');
    const alive = (d.mosproxy && d.mosproxy.available) || (d.unbound && d.unbound.available);
    $('#healthDot').className = 'dot ' + (alive ? 'ok' : 'err');
    cacheUpstreams(d.upstreams);
    renderOverviewStats(d);
    renderOverviewSystem(d.system);
    renderMosproxy(d.mosproxy);
    renderUnbound(d.unbound);
    renderOverviewUpstreams(d.upstreams);
  } catch (e) {
    setHtml($('#ovStats'), stateHtml('概览数据加载失败：' + e.message, 'error'));
    $('#healthDot').className = 'dot err';
  }
}

function renderOverviewUpstreams(list) {
  const body = $('#ovUpstreamBody');
  if (!body) return;
  if (!list || !list.length) { setHtml(body, rowSpan(6, EMPTY('暂无上游数据'))); return; }
  setHtml(body, html`${list.map((u) => {
    const ratio = u.success_ratio;
    const rc = ratio === null || ratio === undefined || u.stale_failures ? 'var(--text-muted)'
      : (ratio >= 99 ? 'var(--ok)' : (ratio >= 95 ? 'var(--warn)' : 'var(--err)'));
    return html`<tr>
      <td class="mono">${u.tag}</td>
      <td><span class="badge ${u.online ? 'ok' : 'err'}">${u.online ? '在线' : '离线'}</span></td>
      <td class="mono" style="color:${rc}">${ratio === null || ratio === undefined ? '—' : ratio + '%'}</td>
      <td class="mono">${dash(u.avg_latency_ms, ' ms')}</td>
      <td class="mono">${dash(u.p95_latency_ms, ' ms')}</td>
      <td class="dim">${u.direction || '—'}</td>
    </tr>`;
  })}`);
}

const statCard = (num, label, sub, cls, title) => html`<div class="card stat">
    <div class="num ${cls || ''}" title="${title || ''}">${num}</div>
    <div class="label">${label}</div>
    ${sub ? html`<div class="sub">${sub}</div>` : raw('')}
  </div>`;

function renderOverviewStats(d) {
  const m = d.mosproxy || {}, ev = d.events || {};
  const hit = m.cache_hit_ratio || 0;
  const errR = m.error_ratio || 0;
  setHtml($('#ovStats'), html`${[
    statCard(m.available ? fmtNum(m.query_total) : '—', '累计查询量',
      m.available ? '开机至今 · 每秒 ' + (m.qps || 0) + ' 次' : '指标不可用', 'accent',
      m.available ? fmtNumFull(m.query_total) : ''),
    statCard(m.available ? hit.toFixed(1) + '%' : '—', '缓存命中率',
      m.available ? '100 次查询省下 ' + Math.round(hit) + ' 次解析' : '',
      hit >= 50 ? 'ok' : (hit >= 20 ? 'warn' : '')),
    statCard(m.available ? errR.toFixed(2) + '%' : '—', '上游失败率',
      m.available ? '失败 ' + fmtNum(m.upstream_err_total) + ' / ' + fmtNum(m.upstream_query_total) : '',
      errR > 5 ? 'err' : (errR > 1 ? 'warn' : 'ok')),
    eventsCard(ev, m),
    latencyCard(ev.latency, m),
    routingCard(d.routing),
  ]}`);
}

function eventsCard(ev, m) {
  if (ev.error) return statCard('—', '近 1 小时请求', ev.error, 'warn');
  if (m && m.available && (m.qps || 0) > 0 && (ev.last_5m || 0) === 0) {
    return statCard('采集已停', '近 1 小时请求',
      'mosproxy 仍在处理查询(QPS ' + m.qps + ')，但 5 分钟内无事件入库。'
      + '执行 sudo dns-stack health 查看 collector', 'err');
  }
  return statCard(fmtNum(ev.last_1h || 0), '近 1 小时请求',
    '近 5 分钟 ' + fmtNum(ev.last_5m || 0) + ' · 域名 ' + fmtNum(ev.domains || 0), '',
    fmtNumFull(ev.last_1h || 0));
}

function routingCard(rt) {
  if (!rt) return '';
  if (rt.error) return statCard('—', '递归出口分流', rt.error, 'warn');
  const direct4 = rt.direct4_count || 0;
  const zones = rt.cn_zones_count || 0;
  const authority = rt.cn_authority_count || 0;

  const fault =
      !rt.chain_active ? ['分流链失效', '正在以直连方式查询境外权威，答案可能已被污染']
    : !rt.tunnel_active ? ['隧道未就绪', '境外查询会直接失败，不会自动回落']
    : direct4 < 1000 ? ['大陆集合过小', '仅 ' + fmtNum(direct4) + ' 段，国内查询会被误导进隧道']
    : (zones > 0 && authority === 0)
      ? ['权威集合为空', fmtNum(zones) + ' 个直连域名的权威一段也未收录，解析会改走隧道']
    : null;

  const ex = rt.exits || {};
  const cnLine = exitLine('大陆直连', ex.direct_geo, ex.direct_ip, '未配置');
  const hkLine = exitLine('香港隧道', ex.tunnel_geo, ex.tunnel_ip, '未建立');

  if (fault) {
    return html`<div class="card stat err">
      <div class="num">${fault[0]}</div>
      <div class="label">递归出口分流</div>
      <div class="sub">${fault[1]}</div>
      ${exitPathHtml(cnLine, hkLine)}
    </div>`;
  }
  return html`<div class="card stat ok">
    <div class="num">正常</div>
    <div class="label">递归出口分流</div>
    ${exitPathHtml(cnLine, hkLine)}
  </div>`;
}

function exitLine(name, geo, ip, emptyText) {
  const g = geo || {};
  const label = g.label || (ip ? '归属未知' : emptyText);
  return { name: name, label: label, ip: ip || '', known: !!g.label };
}

function exitPathHtml(cn, hk) {
  const row = (e) => html`<div class="exit-line">
    <span class="exit-name">${e.name}</span>
    <span class="exit-geo${e.known ? '' : ' dim'}">${e.label}</span>
    ${e.ip ? html`<span class="exit-ip">${e.ip}</span>` : ''}
  </div>`;
  return html`<div class="exit-path">${row(cn)}${row(hk)}</div>`;
}

function latencyCard(lat, m) {
  if (lat && lat.samples) {
    const p50 = lat.p50;
    const sub = '半数快于此 · 最慢 5% 超 ' + dash(lat.p95, ' ms') +
      (lat.slow_1s ? ' · 卡顿 ' + fmtNum(lat.slow_1s) + ' 次' : '');
    return statCard(dash(p50, ' ms'), '响应速度（近 1 小时）', sub,
      p50 === null || p50 === undefined ? '' : (p50 <= 20 ? 'ok' : (p50 <= 200 ? 'warn' : 'err')));
  }
  const avg = m && m.avg_latency_ms;
  return statCard(dash(avg, ' ms'), '上游平均耗时',
    m && m.latency_samples ? '取样 ' + fmtNum(m.latency_samples) + ' 次（不含缓存命中）' : '暂无样本',
    avg === null || avg === undefined ? '' : (avg <= 50 ? 'ok' : (avg <= 200 ? 'warn' : 'err')));
}

function renderOverviewSystem(sys) {
  if (!sys) { setHtml($('#ovSystem'), EMPTY('系统信息不可用')); return; }
  const bar = (pct, label, detail) => {
    const cls = pct > 90 ? 'err' : (pct > 75 ? 'warn' : '');
    return html`<div style="margin-bottom:14px">
      <div class="res-head">
        <span>${label}</span><span class="mono dim">${detail}</span>
      </div>
      <div class="progress"><div class="fill ${cls}" style="width:${Math.min(pct, 100)}%"></div></div>
    </div>`;
  };
  const parts = [];
  if (sys.memory) {
    parts.push(bar(sys.memory.percent, '内存',
      fmtBytes(sys.memory.used) + ' / ' + fmtBytes(sys.memory.total) + ' (' + sys.memory.percent + '%)'));
  }
  if (sys.disk) {
    parts.push(bar(sys.disk.percent, '磁盘',
      fmtBytes(sys.disk.used) + ' / ' + fmtBytes(sys.disk.total) + ' (' + sys.disk.percent + '%)'));
  }
  if (sys.load) {
    const pct = Math.min(sys.load['1m'] / (sys.cpu_count || 1) * 100, 100);
    parts.push(bar(pct, 'CPU 负载（' + sys.cpu_count + ' 核）',
      sys.load['1m'] + ' / ' + sys.load['5m'] + ' / ' + sys.load['15m']));
  }
  parts.push(html`<div class="hint">系统已运行 ${fmtDuration(sys.uptime_seconds)}</div>`);
  setHtml($('#ovSystem'), html`${parts}`);
}

const kvList = (pairs) => html`<dl class="kv">${
  pairs.map(([k, v]) => html`<dt>${k}</dt><dd>${v}</dd>`)}</dl>`;

const barRows = (items) => {
  const total = items.reduce((s, x) => s + x.count, 0) || 1;
  return html`${items.map((x) => html`<div class="bar-row">
    <span class="name">${x.name}</span>
    <span class="track"><span class="fill" style="width:${(x.count / total * 100).toFixed(1)}%"></span></span>
    <span class="val">${fmtNum(x.count)}</span></div>`)}`;
};

function renderMosproxy(m) {
  if (!m || !m.available) {
    setHtml($('#ovMosproxy'), stateHtml((m && m.message) || 'mosproxy 指标不可用', 'error'));
    return;
  }

  const rejected = (m.rejected_cc || 0) + (m.rejected_qps || 0);
  const rejectVal = (n) => (n > 0 ? html`<span class="badge warn">${fmtNum(n)}</span>` : fmtNum(n));
  setHtml($('#ovMosproxy'), html`${[
    kvList([
      ['累计请求', fmtNum(m.query_total) + (m.query_total_synthetic ? '（缓存 + 上游合计）' : '')],
      ['当前 QPS', m.qps],
      ['缓存命中', fmtNum(m.cache_hit_total) + '（' + m.cache_hit_ratio + '%）'],
      ['缓存条目', fmtNum(m.cache_entries)],
      ['预取次数', fmtNum(m.prefetch_total)],
      ['上游请求', fmtNum(m.upstream_query_total)],
      ['上游失败', fmtNum(m.upstream_err_total)],
      ['并发超限被拒', rejectVal(m.rejected_cc)],
      ['QPS 超限被拒', rejectVal(m.rejected_qps)],
    ]),
    rejected > 0 ? html`<div class="hint text-warn mt-8">
      ${ICON_WARN}累计 ${fmtNum(rejected)} 次查询被限流拒绝。
      需要放宽请调高 <code>LIMIT_QPS</code>，或在云安全组限制 443/853 来源。
    </div>` : raw(''),
  ]}`);
}

function renderUnbound(u) {
  if (!u || !u.available) {
    setHtml($('#ovUnbound'), stateHtml((u && u.message) || 'Unbound 统计不可用', 'error'));
    return;
  }
  const note = (text) => raw(
    '<span class="note-xs"> ' + esc(text) + '</span>');
  setHtml($('#ovUnbound'), kvList([
    ['累计查询', fmtNum(u.queries)],
    ['缓存命中', fmtNum(u.cache_hits) + '（' + u.cache_hit_ratio + '%）'],
    ['缓存未命中', fmtNum(u.cache_miss)],
    ['预取次数', fmtNum(u.prefetch)],
    ['平均递归耗时', html`${u.recursion_time_avg_ms} ms${note('不含缓存命中')}`],
    ['递归耗时中位数', html`${u.recursion_time_median_ms} ms${note('不含缓存命中')}`],
    ['当前排队请求', html`${fmtNum(u.requestlist_current)}${note('瞬时值，个位数属正常')}`],
    ['权威应答带回 ECS', u.subnet_queries
      ? html`${fmtNum(u.subnet_queries)}${note('其中 ' + fmtNum(u.subnet_cache_hits)
          + ' 条由 ECS 缓存回答')}`
      : html`<span class="badge warn">0</span>${note('CDN 只能按解析器位置调度')}`],
  ]));
}

async function loadTimeseries() {
  const span = Number($('#tsSpan').value || 3600);
  try {
    state.tsData = await api('/api/timeseries?span=' + span + '&buckets=72');
    drawChart(state.tsData);
  } catch (e) { state.tsData = null; }
}

function drawChart(d) {
  const wrap = $('#tsChart');
  if (!wrap || !d || !d.series || !d.series.length) return;
  const w = wrap.clientWidth, h = wrap.clientHeight;
  if (!w || !h) return;

  const pad = { l: 38, r: 6, t: 8, b: 18 };
  const cw = w - pad.l - pad.r, ch = h - pad.t - pad.b;
  const series = d.series;
  const keys = ['cn', 'foreign', 'cache', 'reject'];
  let max = 0;
  series.forEach((p) => keys.forEach((k) => { if (p[k] > max) max = p[k]; }));
  if (max < 3) max = 3;

  const xAt = (i) => pad.l + cw * i / Math.max(series.length - 1, 1);
  const yAt = (v) => pad.t + ch - ch * v / max;

  const grid = [];
  for (let i = 0; i <= 3; i++) {
    const y = Math.round(pad.t + ch - ch * i / 3) + 0.5;
    grid.push(html`<line class="g-line" x1="${pad.l}" y1="${y}" x2="${pad.l + cw}" y2="${y}"/>`);
    grid.push(html`<text class="g-tick" x="${pad.l - 5}" y="${y + 3}">${Math.round(max * i / 3)}</text>`);
  }

  const tickIdx = [0, Math.floor(series.length / 2), series.length - 1];
  const kept = tickIdx.filter((v, n) => series[v] && tickIdx.indexOf(v) === n);
  const anchorAt = (i) => (i === 0 ? 'start' : (i === series.length - 1 ? 'end' : 'middle'));
  const ticks = kept.map((i) => html`<text class="g-time" text-anchor="${anchorAt(i)}"
      x="${xAt(i)}" y="${h - 5}">${fmtClock(series[i].t)}</text>`);

  const paths = keys.map((k) => {
    const dAttr = series.map(
      (p, i) => (i ? 'L' : 'M') + xAt(i).toFixed(1) + ' ' + yAt(p[k] || 0).toFixed(1)).join(' ');
    return html`<path class="s-${k}" d="${dAttr}"/>`;
  });

  setHtml(wrap, html`<svg width="${w}" height="${h}" viewBox="0 0 ${w} ${h}"
    role="img" aria-label="请求量趋势图">${grid}${ticks}${paths}</svg>`);
}

function initLivePage() {
  if (!state.upstreamTags.length) {
    apiCached('/api/overview')
      .then((d) => { cacheUpstreams(d.upstreams); if (state.page === 'queries') loadQueries(state.queryPage); })
      .catch(() => {  });
  }
  if (!state.liveLoaded) { state.liveLoaded = true; loadQueries(1); }
}

const ROUTE_CLS = { cn: 'cn', foreign: 'foreign', recursive: 'cn', cache: 'cache', reject: 'reject' };

const DIRECTION_BADGE = {
  direct:   ['cn', '整条递归全程直连'],
  hongkong: ['foreign', '整条递归经隧道出网'],
  adaptive: ['cn', '按权威 IP 逐跳分流'],
};

const cnBadge = (inCn) => raw(
  inCn === true ? '<span class="badge cn">大陆节点</span>'
  : inCn === false ? '<span class="badge foreign">境外节点</span>'
  : '<span class="badge unknown">归属未知</span>');

function alignedList(items, cols) {
  const w = cols.map((c) => Math.max(...items.map((it) => String(c(it) || '').length)));
  return items.map((it) =>
    cols.map((c, i) => String(c(it) || '').padEnd(i === cols.length - 1 ? 0 : w[i])).join('  ')
  ).join('\n');
}

function routingSummary(rt) {
  if (!rt) return EMPTY('暂无判定信息');
  const [cls, text] = DIRECTION_BADGE[rt.direction] || ['unknown', rt.direction || '未知'];
  const parts = [];

  parts.push(html`<div class="drawer-prose">
    <span class="badge ${cls}">${text}</span>
    ${rt.manual_rule ? html` <span class="badge accent">人工规则 ${rt.manual_rule}</span>` : ''}
  </div>`);
  if (rt.reason) {
    parts.push(html`<div class="drawer-prose">${rt.reason}</div>`);
  }

  if (rt.result_ip) {
    parts.push(html`<div class="drawer-prose" style="margin-top:8px">
      ★ 最终命中 <span class="mono"><b>${rt.result_ip}</b></span>${geoTag(rt.result_geo)}
      ${cnBadge(rt.result_in_cn)}</div>`);
  }

  if (rt.authorities && rt.authorities.length) {
    const lines = alignedList(rt.authorities, [
      (a) => a.ns,
      (a) => a.ip,
      (a) => (a.in_cn === true ? '大陆' : a.in_cn === false ? '境外' : '未知') + geoTag(a.geo),
    ]);
    parts.push(html`<details class="drawer-details">
      <summary>权威分布（${rt.zone_queried || ''}）</summary>
      <div class="dd-body"><pre class="block">${lines}</pre></div>
    </details>`);
  }

  const detailRows = [];
  const ex = rt.exits;
  if (ex && ex.available) {
    detailRows.push(['出口线路', html`
      ${exitPathHtml(
        exitLine('大陆直连', ex.direct_geo, ex.direct_ip, '未配置'),
        exitLine('香港隧道', ex.tunnel_geo, ex.tunnel_ip, '未建立'))}
      ${ex.tunnel_note ? html`<div class="note-xs text-warn">${ex.tunnel_note}</div>` : ''}`]);
  } else if (ex) {
    detailRows.push(['出口线路', html`<span class="badge warn">取不到：${ex.error || '未知原因'}</span>`]);
  }
  if (rt.viewer_subnet) {
    detailRows.push(['查询身份', html`<span class="mono">${rt.viewer_subnet}</span>　${ecsVerdict(rt.ecs)}`]);
  } else if (rt.result_ip) {
    detailRows.push(['查询身份', raw('<span class="badge warn">未带 ECS</span>　'
      + '<span class="note-xs">内网访问取不到公网子网，以下为默认节点</span>')]);
  }
  if (rt.zone) detailRows.push(['直连区域', html`<span class="mono">${rt.zone}</span>`]);
  if (rt.view_comparison) detailRows.push(['CN / HK 对照', html`<span class="mono">${rt.view_comparison}</span>`]);

  const gs = rt.geoip_status;
  if (gs && !gs.available) {
    detailRows.push(['归属库', html`<span class="badge warn">不可用${gs.error ? '：' + gs.error : ''}</span>`]);
  } else if (gs && gs.degraded) {
    detailRows.push(['归属库', html`<span class="badge accent">降级运行</span>
      <span class="note-xs">省份标注会减少</span>`]);
  }

  if (detailRows.length) {
    parts.push(html`<details class="drawer-details">
      <summary>更多判定细节</summary>
      <div class="dd-body">${kvList(detailRows)}</div>
    </details>`);
  }

  if (rt.result_ips_geo && rt.result_ips_geo.length > 1) {
    const lines = alignedList(rt.result_ips_geo, [
      (r) => r.ip,
      (r) => (r.in_cn === true ? '大陆' : r.in_cn === false ? '境外' : '未知') + geoTag(r.geo),
    ]);
    parts.push(html`<details class="drawer-details">
      <summary>全部 A 记录归属（${rt.result_ips_geo.length} 条）</summary>
      <div class="dd-body"><pre class="block">${lines}</pre></div>
    </details>`);
  }

  return html`${parts}`;
}

let _myLocBusy = false;

async function loadMyLocation(force) {
  const box = $('#myLocation');
  if (!box || _myLocBusy) return;
  _myLocBusy = true;
  const btn = $('#btnMyLocRefresh');
  if (btn) btn.disabled = true;
  setHtml(box, LOADING);
  try {
    if (force) _getCache.delete('/api/my-location');
    const d = await apiCached('/api/my-location', 30000);
    setHtml(box, d.error ? stateHtml(d.error, 'error') : myLocationHtml(d));
    const sn = $('#testSubnet');
    if (sn && d.ecs && !sn.value.trim()) sn.value = d.ecs;
  } catch (e) {
    setHtml(box, errState(e));
  } finally {
    _myLocBusy = false;
    if (btn) btn.disabled = false;
  }
}

const field = (label, value) => html`<div class="fld">
    <div class="fld-k">${label}</div>
    <div class="fld-v">${value}</div>
  </div>`;

function myLocationHtml(d) {
  const g = d.geo || {};
  const where = [...new Set([g.region, g.city].filter(Boolean))].join(' ')
    || g.country || '—';
  const carrier = g.carrier || g.as_org || '—';

  const normCarrier = (s) => (s || '').replace(/^中国/, '').trim();
  const myCarrier = normCarrier(g.carrier);

  const nodes = (d.nodes || []).map((n) => {
    const ng = n.geo || {};
    const sameCarrier = !!(normCarrier(ng.carrier) && myCarrier
      && normCarrier(ng.carrier) === myCarrier);
    const sameRegion = !!(ng.region && g.region && ng.region === g.region);
    const tags = [];
    if (ng.is_cloud) {
      tags.push(sameRegion ? '<span class="pill ok">本地云节点</span>'
        : '<span class="pill accent">云节点</span>');
    } else if (sameCarrier && sameRegion) tags.push('<span class="pill ok">本地节点</span>');
    else if (sameCarrier) tags.push('<span class="pill ok">同运营商</span>');
    else if (normCarrier(ng.carrier) && myCarrier) tags.push('<span class="pill warn">跨运营商</span>');
    if (ng.country && ng.country !== g.country) {
      tags.push('<span class="pill warn">境外</span>');
    }
    if (n.ecs && !n.ecs.honored) {
      tags.push('<span class="pill">未按位置调度</span>');
    }
    return html`<div class="probe" title="${geoWhy(ng)}${ecsWhy(n.ecs)}">
      <div class="probe-h">
        <span class="probe-n">${n.name}</span>
        ${raw(tags.join(''))}
      </div>
      <div class="probe-g">${ng.label || (n.ip ? '归属未知' : n.error || '解析失败')}</div>
      <div class="probe-ip mono">${n.ip || ''}</div>
    </div>`;
  });

  return html`<div class="loc-grid">
    <div class="loc-me">
      ${field('你的 IP', html`<span class="mono">${d.client_ip}</span>`)}
      ${field('位置', where)}
      ${field('运营商', carrier)}
      ${field('发给权威的子网', html`<span class="mono">${d.ecs || '—'}</span>`)}
    </div>
    <div class="loc-nodes">${nodes.length ? nodes : EMPTY('暂无探测结果')}</div>
  </div>`;
}

function geoWhy(g) {
  if (!g) return '';
  if (!g.available) return '归属库不可用' + (g.error ? '：' + g.error : '');
  if (!g.label) return '库可用，但未收录该 IP';
  const parts = [];
  if (g.region) parts.push('地区 ' + g.region);
  if (g.carrier) parts.push('运营商 ' + g.carrier);
  if (g.owner) parts.push('机构 ' + g.owner);
  if (g.asn) parts.push('AS' + g.asn + (g.as_org ? ' ' + g.as_org : ''));
  if (g.country) parts.push('国家 ' + g.country);
  if (g.source) parts.push('数据源 ' + g.source);
  return parts.join('\n');
}

function ecsWhy(e) {
  if (!e) return '\nECS 未回显：无法确认权威是否按位置调度';
  return e.honored
    ? `\nECS ${e.subnet} → 权威按 /${e.scope} 调度`
    : `\nECS ${e.subnet} → 权威回 scope=0，此答案对所有子网通用`;
}

const IP_SOURCE_KIND = { qqwry: 'cn', maxmind: 'global', dbip: 'global', ipsb: 'online' };
const IP_FIELDS = [
  ['country', '国家/地区'], ['region', '省/州'], ['city', '城市'],
  ['asn', 'ASN'], ['as_org', 'AS 组织'], ['carrier', '运营商'], ['owner', '注册主体'],
];

function ipFieldValue(rec, key) {
  if (!rec) return '';
  const v = rec[key];
  if (v === null || v === undefined || v === '') return '';
  return String(v);
}

function ipRoutingRow(routing) {
  if (!routing) return [];
  const tri = (v, yes, no) => v === true
    ? raw('<span class="badge cn">' + yes + '</span>')
    : v === false ? raw('<span class="badge foreign">' + no + '</span>')
    : raw('<span class="badge unknown">未知</span>');
  return [
    ['大陆网段 direct4', tri(routing.direct4, '在集合内', '不在')],
    ['墙内权威段', tri(routing.cn_authority, '是', '否')],
    ['共享 anycast', routing.shared_anycast === true
      ? raw('<span class="badge warn">是，已排除出直连</span>')
      : raw('<span class="badge ok">否</span>')],
    ['已知污染地址', routing.polluted === true
      ? raw('<span class="badge err">是</span>')
      : raw('<span class="badge ok">否</span>')],
    ['全局可路由', tri(routing.global, '是', '保留/私有')],
  ];
}

function ipFreshnessHtml(freshness) {
  if (!freshness) return '';
  const names = {
    cnip: '纯真 qqwry', asn: 'GeoLite2 ASN', city: 'GeoLite2 City',
    dbip_asn: 'DB-IP ASN', dbip_city: 'DB-IP Country',
  };
  const rows = Object.keys(names).filter((k) => freshness[k]).map((k) => {
    const f = freshness[k];
    if (!f.available) {
      return html`<tr><td>${names[k]}</td><td colspan="2"><span class="badge unknown">未安装${f.error ? '：' + f.error : ''}</span></td></tr>`;
    }
    const age = f.age_days;
    const cls = age === undefined ? 'unknown' : age <= 7 ? 'ok' : age <= 30 ? 'warn' : 'err';
    const text = age === undefined ? '未知' : age + ' 天前';
    return html`<tr><td>${names[k]}</td>
      <td>${f.build_epoch ? fmtTime(f.build_epoch) : '—'}</td>
      <td>${raw('<span class="badge ' + cls + '">' + esc(text) + '</span>')}</td></tr>`;
  });
  if (!rows.length) return '';
  return html`<div class="card">
    <h3>归属库时效</h3>
    <div class="table-wrap"><table class="tbl">
      <thead><tr><th>数据库</th><th>构建时间</th><th>距今</th></tr></thead>
      <tbody>${rows}</tbody></table></div>
    <div class="hint">库停更不会让解析失败，只会让归属悄悄变旧——所以这里必须能看见。</div>
  </div>`;
}

function renderIpLookup(d) {
  const box = $('#ipResult');
  const diverged = {};
  (d.divergences || []).forEach((x) => { diverged[x.field] = true; });
  const sources = d.sources || [];

  const head = sources.map((s) => {
    const kind = IP_SOURCE_KIND[s.name] || '';
    const tag = kind === 'cn' ? '国内' : kind === 'online' ? '在线' : '全球';
    return html`<th>${s.label}<span class="src-tag ${kind}">${tag}</span></th>`;
  });

  const body = IP_FIELDS.map(([key, label]) => {
    const cells = sources.map((s) => {
      if (!s.available) return html`<td class="dim">—</td>`;
      const v = ipFieldValue(s.record, key);
      return v ? html`<td>${v}</td>` : html`<td class="dim">—</td>`;
    });
    return html`<tr class="${diverged[key] ? 'row-diverged' : ''}">
      <th class="rowhead">${label}${diverged[key] ? raw('<span class="badge warn sm">分歧</span>') : ''}</th>
      ${cells}</tr>`;
  });

  const unavailable = sources.filter((s) => !s.available);

  setHtml(box, html`
    <div class="card ip-head">
      <div class="ip-addr mono">${d.ip}</div>
      <div class="ip-meta">
        <span class="badge accent">IPv${d.version}</span>
        ${(d.reverse_dns || []).length
          ? html`<span class="mono dim">PTR ${(d.reverse_dns || []).join(' , ')}</span>`
          : raw('<span class="dim">无 PTR 记录</span>')}
      </div>
    </div>

    <div class="card">
      <h3>多源对照</h3>
      <div class="table-wrap"><table class="tbl ip-matrix">
        <thead><tr><th class="rowhead"></th>${head}</tr></thead>
        <tbody>${body}</tbody></table></div>
      ${(d.divergences || []).length
        ? html`<div class="hint text-warn">标为分歧的只有 ASN 与国家码——它们是各源都给规范值、可以机器比对的字段。省市与组织名各源语言与写法不同，并列展示供人工判断，不做自动比对。</div>`
        : html`<div class="hint">各源在 ASN 与国家码上完全一致。</div>`}
      ${unavailable.length
        ? html`<div class="hint">未参与本次查询：${unavailable.map((s) => s.label + (s.error ? '（' + s.error + '）' : '')).join('、')}</div>`
        : ''}
    </div>

    <div class="card">
      <h3>本机分流事实</h3>
      ${kvList(ipRoutingRow(d.routing))}
      <div class="hint">这一组来自本机的规则集合，与上面的归属库无关：递归方向只看 direct4 与 cn_authority。</div>
    </div>

    ${ipFreshnessHtml(d.freshness)}
  `);
}

async function loadIpLookup() {
  const box = $('#ipResult');
  const value = $('#ipQuery').value.trim();
  setHtml(box, stateHtml('查询中…'));
  try {
    renderIpLookup(await api('/api/ip-lookup' + (value ? '?ip=' + encodeURIComponent(value) : '')));
  } catch (e) {
    setHtml(box, errState(e));
  }
}

function geoTag(g) {
  return g && g.available && g.label ? '  [' + g.label + ']' : '';
}

function ecsVerdict(e) {
  if (!e) {
    return raw('<span class="badge warn">应答未回显 ECS</span>　'
      + '<span class="note-xs">权威没带 CLIENT-SUBNET，无法确认是否按位置调度</span>');
  }
  if (e.honored) {
    return html`<span class="badge ok">已按位置调度 /${e.scope}</span>`;
  }
  return raw('<span class="badge warn">权威未按位置调度</span>　'
    + '<span class="note-xs">应答 scope=0，对所有子网通用</span>');
}

const EXIT_NAMES = {
  cache: '缓存命中', direct: '大陆直连', tunnel: '香港隧道',
  hongkong: '香港递归', reject: '已拒绝', unknown: '未知',
};
const EXIT_CLS = { cache: 'cache', direct: 'cn', tunnel: 'foreign', hongkong: 'foreign', reject: 'reject' };

const exitBadge = (path) => html`<span class="badge ${EXIT_CLS[path] || 'unknown'}">${EXIT_NAMES[path] || path}</span>`;

const ROUTED_EXITS = { direct: 1, tunnel: 1, hongkong: 1 };

const routeBadge = (r) => {
  const badge = html`<span class="badge ${ROUTE_CLS[r.route] || 'unknown'}">${r.route_name || r.route}</span>`;
  return ROUTED_EXITS[r.exit_path]
    ? html`${badge} <span class="exit-tag">${EXIT_NAMES[r.exit_path] || r.exit_path}</span>`
    : badge;
};
const rcodeBadge = (r) =>
  html`<span class="badge ${r.rcode === 0 ? 'ok' : (r.rcode === 3 ? 'warn' : 'err')}">${r.rcode_name}</span>`;

function latencyCell(r) {
  const ms = r.elapsed_ms;
  if (ms !== null && ms !== undefined) {
    const v = ms >= 10 ? ms.toFixed(0) : ms.toFixed(2);
    const color = ms <= 5 ? 'var(--ok)' : (ms <= 100 ? 'var(--warn)' : 'var(--err)');
    return html`<span style="color:${color}" title="本次查询实际耗时">${v} ms</span>`;
  }
  if (r.cache_hit) return html`<span style="color:var(--text-dim)" title="缓存命中，未经上游">—</span>`;
  const avg = state.upstreamLatency[r.resp_by];
  if (avg === undefined) return html`<span style="color:var(--text-dim)">—</span>`;
  return html`<span style="color:var(--text-dim)"
    title="当前 mosproxy 未提供单次耗时，这里退回显示上游 ${r.resp_by} 的平均延迟">~${avg} ms</span>`;
}

const queryRow = (r, isNew) => html`<tr class="clickable" data-domain="${r.domain}">
    <td class="mono dim">${fmtClock(r.ts)}</td>
    <td class="mono wrap">${r.domain}</td>
    <td class="mono">${r.qtype_name}</td>
    <td>${rcodeBadge(r)}</td>
    <td>${routeBadge(r)}</td>
    <td class="mono dim">${r.resp_by || '—'}</td>
    <td class="mono">${latencyCell(r)}</td>
    <td>${r.cache_hit ? raw('<span class="badge cache">是</span>')
                       : raw('<span style="color:var(--text-dim)">否</span>')}</td>
    <td>${r.id === null || r.id === undefined ? ''
        : html`<button class="row-del" data-qid="${r.id}" title="删除这条记录">删除</button>`}</td>
  </tr>`;

async function deleteQuery(id, btn) {
  if (!confirm('删除这条查询记录？')) return;
  try {
    const d = await api('/api/action/delete_query', {
      method: 'POST', body: JSON.stringify({ id: Number(id) }),
    });
    if (d && d.ok === false) { toast('删除失败', d.message || '', 'err'); return; }
    const tr = btn && btn.closest('tr');
    const body = $('#liveBody');
    if (tr) tr.remove();
    if (body && !body.querySelector('tr')) setHtml(body, rowSpan(9, EMPTY('暂无记录')));
    toast('已删除该条记录', '', 'ok');
  } catch (e) { toast('删除失败', e.message, 'err'); }
}

async function downloadExport(dataset, format) {
  return downloadBundle('/api/export?dataset=' + dataset + '&format=' + format,
                        'dns-stack-' + dataset + '.' + format);
}

async function downloadBundle(path, fallbackName) {
  try {
    const res = await fetch((window.dnsStackApiUrl || ((p) => p))(path),
      { credentials: 'include' });
    if (!res.ok) {
      let msg = 'HTTP ' + res.status;
      try { const b = await res.json(); msg = b.error || b.detail || msg; } catch (e) {  }
      throw new Error(msg);
    }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = fallbackName;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  } catch (e) { toast('导出失败', e.message, 'err'); }
}

async function runMigrationImport(dryRun) {
  const input = $('#migrationFile');
  const out = $('#migrationImportResult');
  const file = input && input.files && input.files[0];
  if (!file) { toast('请先选择迁移包', '需要本面板导出的 .tar.gz', 'warn'); return; }
  if (!dryRun && !confirm(
    '导入会按清单覆盖本机规则/状态文件（覆盖前自动备份）。确认继续？')) return;
  setHtml(out, dryRun ? '试算中…' : '导入中…');
  const form = new FormData();
  form.append('bundle', file);
  form.append('dry_run', dryRun ? 'true' : 'false');
  try {
    const res = await fetch(
      (window.dnsStackApiUrl || ((p) => p))('/api/migration-import'),
      { method: 'POST', credentials: 'include', body: form });
    const body = await res.json();
    if (!res.ok) throw new Error(body.error || ('HTTP ' + res.status));
    const rep = body.report;
    if (!rep) {
      setHtml(out, '<span class="bad">' + esc(body.stderr || body.error || '未返回报告') + '</span>');
      return;
    }
    const counts = {};
    (rep.applied || []).forEach((it) => { counts[it.action] = (counts[it.action] || 0) + 1; });
    const parts = [];
    if (counts['written']) parts.push('已写入 ' + counts['written']);
    if (counts['would-write']) parts.push('将写入 ' + counts['would-write']);
    if (counts['unchanged']) parts.push('内容相同 ' + counts['unchanged']);
    const skipped = (rep.skipped || []);
    let html = '<b>' + (rep.dry_run ? '试算' : '导入') + '结果：</b>' + esc(parts.join('，') || '无变化');
    if (rep.backup_dir) html += '<br>原文件已备份到 <code>' + esc(rep.backup_dir) + '</code>';
    if (skipped.length) {
      html += '<br><b>跳过 ' + skipped.length + ' 项：</b><ul>';
      skipped.slice(0, 8).forEach((it) => {
        html += '<li><code>' + esc(it.path) + '</code> — ' + esc(it.reason) + '</li>';
      });
      html += '</ul>';
    }
    setHtml(out, html);
    toast(rep.dry_run ? '试算完成' : '导入完成', parts.join('，') || '无变化', 'ok');
    if (!rep.dry_run) { loadOverview(); loadRules(); }
  } catch (e) {
    setHtml(out, '<span class="bad">' + esc(e.message) + '</span>');
    toast('导入失败', e.message, 'err');
  }
}

function bindMigrationImport() {
  const dry = $('#btnMigrationDryRun');
  if (dry) dry.addEventListener('click', () => runMigrationImport(true));
  const real = $('#btnMigrationImport');
  if (real) real.addEventListener('click', () => runMigrationImport(false));
}

async function loadQueries(page) {
  page = page || 1;
  const body = $('#liveBody');
  setHtml(body, rowSpan(9, LOADING));
  const params = new URLSearchParams({ page: String(page), size: '50' });
  const filters = {
    domain: $('#fDomain').value.trim(),
    qtype: $('#fQtype').value,
    route: $('#fRoute').value,
    rcode: $('#fRcode').value,
    resp_by: $('#fRespBy').value,
  };
  Object.keys(filters).forEach((k) => { if (filters[k]) params.set(k, filters[k]); });
  const sinceSec = Number($('#fSince').value || 0);
  if (sinceSec) params.set('since', String(Math.floor(Date.now() / 1000) - sinceSec));

  try {
    const d = await api('/api/queries?' + params.toString());
    state.queryPage = d.page;
    state.queryPages = d.pages || 1;
    if (!d.items.length) {
      setHtml(body, rowSpan(9, EMPTY('没有符合条件的请求记录')));
    } else {
      setHtml(body, html`${d.items.map((r) => queryRow(r, false))}`);
    }
    $('#liveCount').textContent = d.total_capped
      ? '超过 ' + fmtNum(d.total) + ' 条记录（已按上限计数）'
      : '共 ' + fmtNum(d.total) + ' 条记录';
    $('#pageInfo').textContent = d.page + ' / ' + (d.pages || 1) + (d.total_capped ? '+' : '');
    $('#btnPrev').disabled = d.page <= 1;
    $('#btnNext').disabled = d.page >= (d.pages || 1);
  } catch (e) {
    setHtml(body, rowSpan(9, errState(e)));
    $('#liveCount').textContent = '—';
  }
}

function startLive() {
  if (state.liveES) return;
  state.liveOn = true;
  setBtnState($('#btnLiveToggle'), ICON_PAUSE, '暂停实时');
  $('#liveDot').className = 'dot live';
  $('#liveStatus').textContent = '实时流已连接';

  const es = new EventSource(
    (window.dnsStackApiUrl || ((p) => p))('/api/queries/stream'),
    { withCredentials: true });
  state.liveES = es;
  es.onmessage = (ev) => {
    try {
      const d = JSON.parse(ev.data);
      if (!d.events || !d.events.length) return;
      const f = $('#fDomain').value.trim().toLowerCase();
      const rt = $('#fRoute').value;
      const qt = $('#fQtype').value;
      const rc = $('#fRcode').value;
      const rb = $('#fRespBy').value;
      const rows = d.events.filter((r) =>
        (!f || (r.domain || '').toLowerCase().indexOf(f) >= 0) &&
        (!rt || r.route === rt) &&
        (!qt || r.qtype_name === qt) &&
        (!rc || r.rcode_name === rc) &&
        (!rb || r.resp_by === rb));
      if (!rows.length) return;
      const body = $('#liveBody');
      const placeholder = body.querySelector('td[colspan]');
      if (placeholder) setHtml(body, raw(''));
      prependHtml(body, html`${rows.map((r) => queryRow(r, true))}`);
      trimChildren(body, 300);
    } catch (e) {  }
  };
  es.onerror = () => {
    $('#liveDot').className = 'dot warn';
    $('#liveStatus').textContent = '连接中断，正在自动重连…';  // EventSource 自带重连
  };
  es.onopen = () => {
    $('#liveDot').className = 'dot live';
    $('#liveStatus').textContent = '实时流已连接';
  };
}

function stopLive() {
  if (state.liveES) { state.liveES.close(); state.liveES = null; }
  state.liveOn = false;
  setBtnState($('#btnLiveToggle'), ICON_PLAY, '开启实时');
  $('#liveDot').className = 'dot idle';
  $('#liveStatus').textContent = '实时流已暂停';
}

function openDrawer(title) {
  $('#drawerTitle').textContent = title;
  setHtml($('#drawerBody'), LOADING);
  $('#drawer').classList.add('open');
  $('#drawerMask').classList.add('open');
}
function closeDrawer() {
  $('#drawer').classList.remove('open');
  $('#drawerMask').classList.remove('open');
}

const SERVER_NAMES = {
  'local-unbound': '本机 Unbound 递归',
  'foreign-hk': '香港 Unbound 递归',
  'cn-unbound': '国内 Unbound 递归（专用接口）',
};

async function showDomain(domain) {
  openDrawer(domain);
  try {
    const d = await api('/api/domain/' + encodeURIComponent(domain) + '?live=true');
    const parts = [];

    parts.push(html`<h4>递归出口</h4>`);
    parts.push(routingSummary(d.routing));

    if (d.aggregate) {
      const a = d.aggregate;
      parts.push(html`<h4>累计统计</h4>`);
      parts.push(kvList([
        ['请求次数', fmtNum(a.occurrence_count)],
        ['失败次数', fmtNum(a.fail_count || 0)],
        ['最近状态', a.last_rcode_name || '—'],
        ['最近路由', a.last_route_name || '—'],
        ['首次出现', fmtTime(a.first_seen_at) + '（' + ago(a.first_seen_at) + '）'],
        ['最后请求', fmtTime(a.last_seen_at) + '（' + ago(a.last_seen_at) + '）'],
      ]));
    }

    if (d.by_upstream && d.by_upstream.length) {
      parts.push(html`<h4>响应来源分布</h4>`);
      parts.push(barRows(d.by_upstream.map((x) => ({ name: x.resp_by, count: x.count }))));
    }

    if (d.live) {
      parts.push(html`<h4>实时解析结果</h4>`);
      Object.keys(d.live).forEach((server) => {
        const types = d.live[server];
        const blocks = [];
        Object.keys(types).forEach((qtype) => {
          const r = types[qtype];
          if (r.error || !r.records || !r.records.length) return;
          blocks.push(html`<pre class="block">${recordLines(r.records)}</pre>`);
          if (r.query_time_ms !== null && r.query_time_ms !== undefined) {
            blocks.push(html`<div class="hint">耗时 ${r.query_time_ms} ms</div>`);
          }
        });
        if (!blocks.length) {
          const statuses = Object.keys(types).map((k) => types[k].status).filter(Boolean).join(' / ');
          blocks.push(html`<div class="hint">无应答记录（状态：${statuses || '查询失败'}）</div>`);
        }
        parts.push(html`<div style="margin-bottom:12px">
          <div class="probe-head">${SERVER_NAMES[server] || server}</div>
          ${blocks}</div>`);
      });
    }

    if (d.classification) {
      const c = d.classification;
      const cls = c.status === 'cn' ? 'cn' : (c.status === 'gfw' ? 'foreign' : 'unknown');
      parts.push(html`<h4>分类器判定（规则构建节点）</h4>`);
      parts.push(kvList([
        ['当前分类', html`<span class="badge ${cls}">${c.status}</span>`],
        ['判定依据', c.last_result || '—'],
        ['最终 IP', (c.final_ips || []).join(', ') || '—'],
        ['CNAME 链', (c.cname_chain || []).join(' → ') || '无'],
        ['人工覆盖', c.manual_override || '无'],
      ]));
    }

    if (d.recent && d.recent.length) {
      parts.push(html`<h4>最近 ${d.recent.length} 次请求</h4>`);
      parts.push(html`<div class="table-wrap"><table>
        <thead><tr><th>时间</th><th>类型</th><th>状态</th><th>路由</th><th>来源</th></tr></thead>
        <tbody>${d.recent.map((r) => html`<tr>
          <td class="mono">${fmtTime(r.ts)}</td>
          <td class="mono">${r.qtype_name}</td>
          <td>${rcodeBadge(r)}</td>
          <td>${routeBadge(r)}</td>
          <td class="mono">${r.resp_by || '—'}</td></tr>`)}</tbody></table></div>`);
    }

    parts.push(html`<div class="drawer-foot">
      <button class="danger sm" id="btnDelDomain">删除该域名的统计记录</button>
      <span class="hint">只清除面板里的统计，不影响实际解析。</span>
    </div>`);

    setHtml($('#drawerBody'), parts.length ? html`${parts}` : EMPTY('没有该域名的记录'));
    const delBtn = $('#btnDelDomain');
    if (delBtn) delBtn.addEventListener('click', () => deleteDomain(domain));
  } catch (e) {
    setHtml($('#drawerBody'), errState(e));
  }
}

async function deleteDomain(domain) {
  if (!confirm('删除「' + domain + '」的全部统计记录？\n\n只影响面板统计，不影响这个域名的实际解析。')) return;
  try {
    const d = await api('/api/action/delete_domain', {
      method: 'POST', body: JSON.stringify({ domain: domain }),
    });
    if (d && d.ok === false) { toast('删除失败', d.message || '', 'err'); return; }
    toast('已删除', domain, 'ok');
    closeDrawer();
    if (state.page === 'queries') loadDomains(state.domPage);
    if (state.page === 'settings') loadCollected();
  } catch (e) { toast('删除失败', e.message, 'err'); }
}

async function loadDomains(page) {
  state.domPage = page || 1;
  loadDomainSummary();
  const body = $('#domBody');
  setHtml(body, rowSpan(6, LOADING));
  const params = new URLSearchParams({
    metric: state.domMetric,
    page: String(state.domPage),
    size: $('#domLimit').value || '50',
  });
  const s = $('#domSearch').value.trim();
  const r = $('#domRoute').value;
  if (s) params.set('search', s);
  if (r) params.set('route', r);

  try {
    const d = await api('/api/domains?' + params.toString());
    state.domPages = d.pages || 1;
    $('#domCount').textContent = '共 ' + fmtNum(d.total || 0) + ' 个域名';
    $('#domPageInfo').textContent = (d.page || 1) + ' / ' + (d.pages || 1);
    $('#btnDomPrev').disabled = (d.page || 1) <= 1;
    $('#btnDomNext').disabled = (d.page || 1) >= (d.pages || 1);
    renderDomainHead(state.domMetric);
    if (!d.items.length) { setHtml(body, rowSpan(6, EMPTY())); return; }

    if (state.domMetric === 'slow') {
      setHtml(body, html`${d.items.map((x) => {
        const avg = x.avg_ms, cls = avg >= 1000 ? 'var(--err)' : (avg >= 200 ? 'var(--warn)' : 'var(--ok)');
        return html`<tr class="clickable" data-domain="${x.domain}">
          <td class="mono wrap">${x.domain}</td>
          <td class="mono" style="color:${cls}">${avg} ms</td>
          <td class="mono dim">${x.max_ms} ms</td>
          <td class="mono">${fmtNum(x.samples)}</td>
          <td class="mono dim" colspan="3">${fmtTime(x.last_seen_at)}</td>
        </tr>`;
      })}`);
      return;
    }

    setHtml(body, html`${d.items.map((x) => {
      const n = x.node || {};
      const g = n.geo || {};
      const label = g.label;
      const why = geoWhy(g);
      return html`<tr class="clickable" data-domain="${x.domain}">
      <td class="mono wrap">${x.domain}</td>
      <td class="node-cell" title="${why}">${n.ip
        ? html`<span class="node-geo">${label || '归属未知'}</span><span class="node-ip mono">${n.ip}</span>`
        : raw('<span class="node-geo dim">—</span>')}</td>
      <td class="mono">${fmtNum(x.occurrence_count)}</td>
      <td class="mono" style="color:${x.fail_count > 0 ? 'var(--err)' : 'var(--text-dim)'}">${fmtNum(x.fail_count)}</td>
      <td class="mono">${dash(x.last_rcode_name)}</td>
      <td class="mono dim">${fmtTime(x.last_seen_at)}</td>
    </tr>`;
    })}`);
  } catch (e) {
    setHtml(body, rowSpan(6, errState(e)));
    $('#domCount').textContent = '—';
  }
}

function renderDomainHead(metric) {
  const head = $('#domHead');
  const body = $('#domBody');
  if (body) body.dataset.metric = metric;
  if (!head) return;
  setHtml(head, metric === 'slow'
    ? html`<th>域名</th><th style="width:90px">平均耗时</th><th style="width:90px">最慢一次</th>
           <th style="width:70px">样本数</th><th colspan="3">最后请求</th>`
    : html`<th>域名</th><th style="width:160px">解析节点</th>
           <th style="width:80px">请求次数</th><th style="width:70px">失败次数</th>
           <th style="width:88px">最近状态</th><th style="width:130px">最后请求</th>`);
}

async function loadDomainSummary() {
  try {
    const d = await api('/api/domains/summary');
    const byRoute = {};
    (d.by_route || []).forEach((x) => { byRoute[x.route] = x.count; });
    const byExit = {};
    (d.by_exit || []).forEach((x) => { byExit[x.path] = x.count; });
    const exitCount = (k) => byExit[k] || 0;
    setHtml($('#domSummary'), html`${[
      statCard(fmtNum(exitCount('direct')), '大陆直连', '近 24 小时', 'ok'),
      statCard(fmtNum(exitCount('tunnel') + exitCount('hongkong')), '香港隧道', '近 24 小时', 'accent'),
      statCard(fmtNum(d.new_24h || 0), '近 24 小时新增',
        '近 1 小时活跃 ' + fmtNum(d.active_1h || 0)),
      statCard(fmtNum(d.failing || 0), '近 24 小时失败',
        '历史累计 ' + fmtNum(d.failed_ever || 0) + ' 个曾失败过',
        d.failing > 0 ? 'warn' : 'ok'),
    ]}`);

    const barList = (items, el) => {
      setHtml($(el), (items && items.length) ? barRows(items) : EMPTY());
    };
    barList(d.by_qtype, '#domQtype');
    barList(d.by_rcode, '#domRcode');
  } catch (e) {
    setHtml($('#domSummary'), errState(e));
  }
}



const RULE_SOURCE_FIELDS = [
  ['rsRawBase', 'github_raw_base'],
  ['rsMirror1', 'github_mirror_1'],
  ['rsMirror2', 'github_mirror_2'],
  ['rsRepo', 'github_repository'],
  ['rsBranch', 'github_branch'],
];

function fillRuleSources(sources) {
  const s = sources || {};
  RULE_SOURCE_FIELDS.forEach(([id, key]) => {
    const el = $('#' + id);
    if (el) el.value = s[key] || '';
  });
}

async function saveRuleSources() {
  const args = {};
  RULE_SOURCE_FIELDS.forEach(([id, key]) => { args[key] = $('#' + id).value.trim(); });
  await runOp('set_rule_sources', '保存规则源', args, true);
}

const SYNC_STALE_SEC = 3600;

function syncHealth(ts) {
  if (window.PANEL_ROLE !== 'cn-resolver') return '本角色不同步规则';
  if (!ts) return raw('<span class="badge unknown">尚未同步过</span>');
  const age = Math.floor(Date.now() / 1000) - ts;
  return age > SYNC_STALE_SEC
    ? html`<span class="badge err">已中断</span> 最后一次成功同步在${ago(ts)}`
    : html`<span class="badge ok">正常</span> 最近一次成功同步：${ago(ts)}`;
}

async function loadRules() {
  loadCollected();
  try {
    const d = await apiCached('/api/rules');
    setHtml($('#rulesInfo'), kvList([
      ['cn.txt', html`<b>${fmtNum(d.cn_count)}</b> 个域名`],
      ['gfw.txt', html`<b>${fmtNum(d.gfw_count)}</b> 个域名`],
      ['cn-ip-cidr.txt', fmtNum(d.cn_cidr_count) + ' 段'],
      ['polluted-ip-cidr.txt', fmtNum(d.polluted_cidr_count) + ' 段'],
      ['manual-gfw.txt', fmtNum(d.manual_gfw_count) + ' 条（人工维护）'],
      ['规则最后变化', d.updated_at ? ago(d.updated_at) : '—'],
      ['同步链路', syncHealth(d.last_sync_at)],
    ]));

    fillRuleSources(d.sources);

    setHtml($('#syncHistory'), (d.history && d.history.length)
      ? html`<pre class="block">${d.history.slice(0, 15).join('\n')}</pre>`
      : EMPTY('暂无同步记录'));

    setHtml($('#rollbackList'), (d.rollback_versions && d.rollback_versions.length)
      ? html`<div class="table-wrap"><table>
          <thead><tr><th>版本</th><th>条目</th><th>时间</th></tr></thead>
          <tbody>${d.rollback_versions.map((v) => html`<tr>
            <td class="mono">${v.name}</td>
            <td class="mono">${fmtNum(v.count)}</td>
            <td class="mono dim">${fmtTime(v.mtime)}</td></tr>`)}</tbody>
        </table></div>`
      : EMPTY('暂无历史版本'));
  } catch (e) {
    setHtml($('#rulesInfo'), errState(e));
  }

  loadCacheInfo();

  try {
    const c = await apiCached('/api/cert');
    if (!c.exists) { setHtml($('#certInfo'), EMPTY('未找到证书文件')); return; }
    const days = c.days_left;
    const cls = (days === null || days === undefined) ? '' : (days <= 2 ? 'err' : (days <= 5 ? 'warn' : 'ok'));
    setHtml($('#certInfo'), html`${[
      kvList([
        ['剩余有效期', html`<span class="badge ${cls}">${dash(days, ' 天')}</span>`],
        ['生效时间', c.not_before || '—'],
        ['过期时间', c.not_after || '—'],
        ['适用地址', c.san || '—'],
        ['签发机构', c.issuer || '—'],
      ]),
      html`<div class="hint">Let's Encrypt IP 证书约 6 天，每 6 小时自动检查续签。</div>`,
    ]}`);
  } catch (e) {
    setHtml($('#certInfo'), errState(e));
  }
}

function fmtTtl(sec) {
  if (sec === null || sec === undefined) return '—';
  if (sec === 0) return '已关闭';
  if (sec % 86400 === 0) return (sec / 86400) + ' 天';
  if (sec % 3600 === 0) return (sec / 3600) + ' 小时';
  return sec + ' 秒';
}

async function loadCacheInfo() {
  try {
    const d = await api('/api/cache');
    const mp = d.mosproxy || {}, ub = d.unbound || {};
    setHtml($('#cacheInfo'), kvList([
      ['mosproxy 乐观缓存', html`<b>${fmtTtl(mp.optimistic_ttl)}</b>`],
      ['mosproxy 最大 TTL', fmtTtl(mp.maximum_ttl)],
      ['Unbound 过期兜底', html`<b>${fmtTtl(ub['serve-expired-ttl'])}</b>`],
      ['Unbound 等待阈值', ub['serve-expired-client-timeout'] !== undefined
        ? ub['serve-expired-client-timeout'] + ' ms（超过就先回旧记录）' : '—'],
      ['Unbound 最大 TTL', fmtTtl(ub['cache-max-ttl'])],
    ]));
    const sel = $('#cacheTtl');
    if (sel && mp.optimistic_ttl !== null && mp.optimistic_ttl !== undefined) {
      const cur = String(mp.optimistic_ttl);
      if (Array.from(sel.options).some((o) => o.value === cur)) sel.value = cur;
    }
  } catch (e) {
    setHtml($('#cacheInfo'), errState(e));
  }
}

async function runDnsTest() {
  const domain = $('#testDomain').value.trim();
  if (!domain) { toast('请输入要测试的域名', '', 'err'); return; }
  const qtype = $('#testQtype').value;
  const subnetEl = $('#testSubnet');
  const subnet = subnetEl ? subnetEl.value.trim() : '';
  if (subnet) {
    const m = subnet.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/);
    if (!m || m.slice(1, 5).some((o) => Number(o) > 255) || Number(m[5]) > 32) {
      toast('子网格式不对', '应为 a.b.c.0/24 这样的 IPv4 网段，每段 0-255，前缀不超过 32', 'err');
      return;
    }
  }
  const btn = $('#btnTest');
  btn.disabled = true;
  btn.textContent = '测试中…';
  setHtml($('#testResult'), html`<div class="card">${LOADING}</div>`);

  try {
    const body = { domain: domain, qtype: qtype, servers: ['local-unbound', 'foreign-hk'] };
    if (subnet) body.subnet = subnet;
    const d = await api('/api/dns-test', { method: 'POST', body: JSON.stringify(body) });
    const cards = Object.keys(d.results).map((server) => {
      const r = d.results[server];
      const name = SERVER_NAMES[server] || server;
      if (r.error) {
        return html`<div class="card"><h3>${name}</h3>${stateHtml(r.error, 'error')}</div>`;
      }
      const recs = r.records || [];
      const ipsGeo = r.ips_geo || [];
      const geoMap = {};
      ipsGeo.forEach((x) => { geoMap[x.ip] = x.geo; });
      const recLines = recs.map((rec) => {
        const base = rec.type + '  TTL=' + (rec.ttl === null || rec.ttl === undefined ? '—' : rec.ttl) + '  ' + rec.value;
        const g = geoMap[rec.value];
        return g && g.label ? base + '  [' + g.label + ']' : base;
      }).join('\n');
      return html`<div class="card">
        <h3><span>${name}</span>
          <span class="badge ${r.status === 'NOERROR' ? 'ok' : 'err'}">${r.status || '—'}</span></h3>
        ${recs.length ? html`<pre class="block">${recLines}</pre>` : EMPTY('无应答记录')}
        ${ipsGeo.length ? html`<div class="ipgeo-list">${ipsGeo.map((x) => {
          const g = x.geo || {};
          const inCn = g.country === '中国' || g.country === 'China' || g.country === '香港' || g.country === 'Hong Kong'
            || g.country === '台湾' || g.country === 'Taiwan' || g.country === '澳门';
          return html`<div class="ipgeo-row" title="${geoWhy(g)}">
            <span class="mono">${x.ip}</span>
            <span class="badge ${g.available ? (inCn ? 'cn' : 'foreign') : 'unknown'}">${g.label || '归属未知'}</span>
            ${g.asn ? html`<span class="mono dim">${'AS' + g.asn}</span>` : ''}
          </div>`;
        })}</div>` : ''}
        <div class="hint">递归耗时 ${dash(r.query_time_ms, ' ms')}
          · 含面板往返共 ${dash(r.panel_elapsed_ms, ' ms')}</div>
      </div>`;
    });

    setHtml($('#testResult'), html`
      <div class="card"><h3>递归出口判定</h3>${routingSummary(d.routing)}</div>
      <div class="grid c2">${cards}</div>`);
  } catch (e) {
    setHtml($('#testResult'), html`<div class="card">${stateHtml('测试失败：' + e.message, 'error')}</div>`);
  } finally {
    btn.disabled = false;
    btn.textContent = '开始测试';
  }
}

function logLineNode(line, search) {
  let cls = '';
  if (/\b(error|err|fatal|failed|failure|panic)\b/i.test(line)) cls = 'lvl-err';
  else if (/\b(warn|warning)\b/i.test(line)) cls = 'lvl-warn';

  if (!search) return html`<div class="log-line ${cls}">${line}</div>`;
  const lower = line.toLowerCase();
  const needle = search.toLowerCase();
  const segs = [];
  let i = 0;
  while (true) {
    const idx = lower.indexOf(needle, i);
    if (idx < 0) { segs.push(html`${line.slice(i)}`); break; }
    segs.push(html`${line.slice(i, idx)}`);
    segs.push(html`<mark>${line.slice(idx, idx + needle.length)}</mark>`);
    i = idx + needle.length;
  }
  return html`<div class="log-line ${cls}">${segs}</div>`;
}

function renderLogs() {
  const search = $('#logSearch').value.trim();
  const view = $('#logView');
  const lines = search
    ? state.logLines.filter((l) => l.toLowerCase().indexOf(search.toLowerCase()) >= 0)
    : state.logLines;
  if (!lines.length) {
    setHtml(view, EMPTY(search ? '没有匹配的日志行' : '暂无日志'));
    return;
  }
  const atBottom = view.scrollHeight - view.scrollTop - view.clientHeight < 60;
  setHtml(view, html`${lines.map((l) => logLineNode(l, search))}`);
  if (atBottom) view.scrollTop = view.scrollHeight;
}

async function loadLogs() {
  const view = $('#logView');
  setHtml(view, LOADING);
  const params = new URLSearchParams({
    unit: $('#logUnit').value,
    lines: $('#logLines').value,
  });
  const p = $('#logPriority').value;
  if (p) params.set('priority', p);
  try {
    const d = await api('/api/logs?' + params.toString());
    state.logLines = d.lines || [];
    renderLogs();
    view.scrollTop = view.scrollHeight;
  } catch (e) {
    setHtml(view, stateHtml('日志加载失败：' + e.message, 'error'));
  }
}

function startLogFollow() {
  if (state.logES) return;
  state.logFollow = true;
  setBtnState($('#btnLogFollow'), ICON_PAUSE, '暂停');
  $('#btnLogFollow').classList.add('primary');

  const params = new URLSearchParams({ unit: $('#logUnit').value });
  const p = $('#logPriority').value;
  if (p) params.set('priority', p);

  const es = new EventSource(
    (window.dnsStackApiUrl || ((p) => p))('/api/logs/stream?' + params.toString()),
    { withCredentials: true });
  state.logES = es;
  es.onmessage = (ev) => {
    try {
      const d = JSON.parse(ev.data);
      if (d.error) { toast('日志流错误', d.error, 'err'); return; }
      if (d.lines && d.lines.length) {
        state.logLines = state.logLines.concat(d.lines);
        if (state.logLines.length > 3000) state.logLines = state.logLines.slice(-2000);

        const view = $('#logView');
        if (!$('#logSearch').value.trim() && !view.querySelector('.state')) {
          const atBottom = view.scrollHeight - view.scrollTop - view.clientHeight < 60;
          appendHtml(view, html`${d.lines.map((l) => logLineNode(l, ''))}`);
          while (view.children.length > state.logLines.length) view.firstElementChild.remove();
          if (atBottom) view.scrollTop = view.scrollHeight;
        } else {
          renderLogs();
        }
      }
    } catch (e) {  }
  };
  es.onerror = () => { toast('日志实时流中断', '正在自动重连…', 'err'); };
}

function stopLogFollow() {
  if (state.logES) { state.logES.close(); state.logES = null; }
  state.logFollow = false;
  setBtnState($('#btnLogFollow'), ICON_PLAY, '实时');
  $('#btnLogFollow').classList.remove('primary');
}

let _collectedBound = false;
let _collected = null;          // 缓存整份数据，切标签/筛选不再重新请求
let _dataSet = 'cn_zones';

const DATA_SETS = {
  cn_zones: { name: '直连域名', unit: '个', hint: '递归链中出现过大陆权威，因此整条递归都走直连' },
  polluted: { name: '污染 IP', unit: '个', hint: '实测捕获的 GFW 伪造应答地址' },
};

function renderDataList() {
  const box = $('#dataList');
  if (!box || !_collected) return;
  const meta = DATA_SETS[_dataSet] || {};
  const all = (_collected.data || {})[_dataSet] || [];
  const kw = ($('#dataSearch') || {}).value || '';
  const items = kw ? all.filter((x) => x.indexOf(kw.trim().toLowerCase()) >= 0) : all;
  const LIMIT = 500;
  const shown = items.slice(0, LIMIT);
  const dmeta = (_collected.data_meta || {})[_dataSet];
  const serverTruncated = dmeta && dmeta.truncated;

  setHtml(box, html`
    <div class="hint" style="margin-bottom:6px">
      ${meta.hint || ''} · 共 <b>${fmtNum(serverTruncated ? dmeta.total : all.length)}</b> ${meta.unit || ''}
      ${kw ? html`· 筛选出 ${fmtNum(items.length)} 条` : ''}
      ${items.length > LIMIT ? html`· 仅显示前 ${LIMIT} 条，请用筛选框缩小范围` : ''}
      ${serverTruncated
        ? html`<span class="badge warn wrap" style="margin-left:6px">服务端已截断：只传回 ${fmtNum(dmeta.returned)} / ${fmtNum(dmeta.total)} 条，筛选也查不到其余部分</span>`
        : ''}
    </div>
    ${shown.length
      ? html`<div class="data-grid">${shown.map((x) => html`<span class="data-item">${x}</span>`)}</div>`
      : EMPTY(kw ? '没有匹配项' : '暂无数据')}`);
}

async function loadCollected() {
  if (!_collectedBound) {
    const b = $('#btnReloadCollected');
    if (b) b.addEventListener('click', () => { invalidateCache(); loadCollected(); });
    const tabs = $('#dataTabs');
    if (tabs) tabs.addEventListener('click', (e) => {
      const btn = e.target.closest('button[data-set]');
      if (!btn) return;
      $$('#dataTabs button').forEach((x) => x.classList.toggle('active', x === btn));
      _dataSet = btn.dataset.set;
      renderDataList();
    });
    const s = $('#dataSearch');
    if (s) s.addEventListener('input', renderDataList);
    _collectedBound = !!(b && tabs);
  }
  try {
    const d = await apiCached('/api/collected');
    _collected = d;
    const ip = d.ip || {};

    setHtml($('#collectStats'), html`${[
      statCard(fmtNum(d.domains_total), '已采集域名', '近 24 小时活跃 ' + fmtNum(d.domains_active_24h)),
      statCard(fmtNum(d.queries_24h), '近 24 小时查询', '', 'accent'),
      statCard(fmtNum(ip.cn_zones), '直连域名', '权威在大陆，全程直连', 'ok'),
      statCard(fmtNum(ip.polluted), '污染 IP', fmtNum(ip.polluted_cidr) + ' 段',
        ip.polluted > 0 ? 'warn' : ''),
    ]}`);

    renderDataList();

    const rows = d.failing_domains || [];
    setHtml($('#failingDomains'), rows.length
      ? html`<div class="table-wrap"><table>
          <thead><tr><th>注册域</th><th style="text-align:right">子域</th>
            <th style="text-align:right">失败</th></tr></thead>
          <tbody>${rows.map((x) => html`<tr>
            <td><a href="#" class="dom-link" data-domain="${x.domain}">${x.domain}</a></td>
            <td style="text-align:right" class="mono">${fmtNum(x.subdomains)}</td>
            <td style="text-align:right" class="mono">${fmtNum(x.count)}</td></tr>`)}</tbody>
        </table></div>`
      : EMPTY('近 24 小时无解析失败'));
    $$('#failingDomains .dom-link').forEach((a) => a.addEventListener('click', (ev) => {
      ev.preventDefault(); showDomain(a.dataset.domain);
    }));
  } catch (e) {
    setHtml($('#collectStats'), errState(e));
  }
}

let _authBound = false;
function bindAuthButtons() {
  if (_authBound) return;
  const s = $('#btnSaveOAuth'); if (s) s.addEventListener('click', saveOAuth);
  const t = $('#btnTogglePwd'); if (t) t.addEventListener('click', togglePassword);
  const ts = $('#btnTotpSetup'); if (ts) ts.addEventListener('click', totpSetup);
  const te = $('#btnTotpEnable'); if (te) te.addEventListener('click', totpEnable);
  const td = $('#btnTotpDisable'); if (td) td.addEventListener('click', totpDisable);
  const tc = $('#btnTotpCancel');
  if (tc) tc.addEventListener('click', function () {
    $('#totpSecret').value = ''; $('#totpUri').value = ''; $('#totpCode').value = '';
    $('#totpSetup').hidden = true; $('#btnTotpSetup').hidden = false;
  });
  _authBound = !!(s && t);
}

const secState = { auth: null, doh: null };

function renderPosture() {
  const box = $('#posture');
  if (!box) return;
  const a = secState.auth, o = (a && a.oauth) || {}, d = secState.doh;
  const local = ['localhost', '127.0.0.1', '[::1]', '::1'].indexOf(location.hostname) >= 0;
  const https = location.protocol === 'https:';

  const items = [
    ['密码登录', a ? (a.password_disabled ? ['已关闭', 'idle'] : ['启用中', 'ok']) : ['—', 'idle']],
    ['二次认证', a ? (a.totp_enabled
        ? ['已启用', TOTP_ENABLE_ALLOWED ? 'ok' : 'err']
        : [TOTP_ENABLE_ALLOWED ? '未启用' : '不可用', 'idle']) : ['—', 'idle']],
    ['GitHub 登录', a ? (o.verified_once ? ['已验证', 'ok']
        : o.ready ? ['待验证', 'warn'] : ['未配置', 'idle']) : ['—', 'idle']],
    ['传输加密', https ? ['HTTPS', 'ok'] : local ? ['本机直连', 'ok'] : ['明文', 'err']],
    ['接入路径', d ? (d.is_default ? ['默认路径', 'warn'] : ['私密路径', 'ok']) : ['—', 'idle']],
  ];
  setHtml(box, html`${items.map(([k, [v, cls]]) => html`
    <div class="posture-item is-${cls}">
      <div class="posture-k">${k}</div>
      <div class="posture-v" title="${v}">${v}</div>
    </div>`)}`);
}

function renderAccessInfo() {
  const box = $('#accessBox');
  if (!box) return;
  const local = ['localhost', '127.0.0.1', '[::1]', '::1'].indexOf(location.hostname) >= 0;
  const https = location.protocol === 'https:';
  setHtml($('#accessBadge'), https ? html`<span class="badge ok">已加密</span>`
    : local ? html`<span class="badge unknown">本机</span>`
    : html`<span class="badge err">明文</span>`);
  setHtml(box, html`${kvList([
    ['当前地址', html`<span class="mono">${location.host}</span>`],
    ['传输', https ? raw('<span class="badge ok">HTTPS</span>')
      : local ? raw('<span class="badge unknown">HTTP · 仅本机</span>')
      : raw('<span class="badge err">HTTP 明文</span>')],
    ['会话有效期', '12 小时'],
  ])}
  ${https || local ? raw('') : html`<div class="hint text-warn">
    密码会以明文经过网络，请改用 HTTPS 或只从本机访问。</div>`}`);
}

async function loadAuthConfig() {
  try {
    const d = await apiCached('/api/auth/config');
    const o = d.oauth || {};
    secState.auth = d;

    $('#oaCallback').textContent =
      (window.dnsStackApiUrl || ((p) => p))('/api/oauth/github/callback');
    $('#oaClientId').value = o.client_id || '';
    $('#oaUsers').value = (o.allowed_users || []).join(' ');

    setHtml($('#pwBadge'), d.password_disabled
      ? html`<span class="badge err">已关闭</span>`
      : html`<span class="badge ok">启用中</span>`);
    setHtml($('#oauthBadge'), o.verified_once ? html`<span class="badge ok">已验证</span>`
      : o.ready ? html`<span class="badge warn">待验证</span>`
      : html`<span class="badge unknown">未配置</span>`);

    const chip = (state, text) => html`<span class="sec-chip is-${state}">${text}</span>`;
    setHtml($('#oauthChips'), html`${[
      o.client_id ? chip('ok', 'Client ID 已填') : chip('idle', 'Client ID 未填'),
      o.secret_set ? chip('ok', 'Secret 已设置') : chip('idle', 'Secret 未设置'),
      o.verified_once ? chip('ok', '通路已验证') : chip('warn', '通路未验证'),
      chip((o.allowed_users || []).length ? 'ok' : 'idle',
        '允许账号 ' + ((o.allowed_users || []).join('、') || '未指定')),
    ]}`);

    const btn = $('#btnTogglePwd');
    const wantDisable = !d.password_disabled;
    const blocked = wantDisable && !o.verified_once;
    btn.textContent = d.password_disabled ? '重新启用密码登录' : '关闭密码登录';
    btn.className = d.password_disabled ? 'primary sm' : 'danger sm';
    btn.dataset.disable = d.password_disabled ? '0' : '1';
    btn.disabled = blocked;
    $('#pwToggleHint').textContent = blocked
      ? '需先用 GitHub 成功登录一次'
      : (d.password_disabled ? '当前只能用 GitHub 登录' : '');

    renderTotp(d.totp_enabled);
    renderPosture();
  } catch (e) {
    setHtml($('#oauthChips'), stateHtml('读取失败：' + e.message, 'error'));
  }
}

const TOTP_ENABLE_ALLOWED = false;

function renderTotp(enabled) {
  setHtml($('#totpBadge'), enabled
    ? (TOTP_ENABLE_ALLOWED ? html`<span class="badge ok">已启用</span>`
                           : html`<span class="badge err">已启用·登录受阻</span>`)
    : html`<span class="badge unknown">${TOTP_ENABLE_ALLOWED ? '未启用' : '不可用'}</span>`);
  const setup = $('#btnTotpSetup');
  setup.hidden = enabled;
  setup.disabled = !TOTP_ENABLE_ALLOWED;
  setup.title = TOTP_ENABLE_ALLOWED ? '' : '登录页当前不提供验证码输入入口，启用会导致密码登录永久失败';
  $('#btnTotpDisable').hidden = !enabled;   // 已启用时必须能停用——这是逃生口
  $('#totpSetup').hidden = true;
}

async function totpSetup() {
  if (!TOTP_ENABLE_ALLOWED) {
    toast('二次认证不可启用',
      '登录页当前不渲染验证码输入框，启用后密码登录会永久失败。'
      + '需要启用请先恢复登录页的验证码输入框。', 'err');
    return;
  }
  try {
    const d = await api('/api/auth/totp/setup', { method: 'POST' });
    $('#totpSecret').value = d.secret;
    $('#totpUri').value = d.uri;
    $('#totpCode').value = '';
    $('#totpSetup').hidden = false;
    $('#btnTotpSetup').hidden = true;
    $('#totpCode').focus();
  } catch (e) { toast('生成失败', e.message, 'err'); }
}

async function totpEnable() {
  const code = $('#totpCode').value.trim();
  if (!/^\d{6}$/.test(code)) { toast('验证码格式不对', '请输入验证器上显示的 6 位数字', 'err'); return; }
  try {
    const r = await api('/api/auth/totp/enable', {
      method: 'POST', body: JSON.stringify({ code: code }),
    });
    $('#totpSecret').value = '';
    $('#totpUri').value = '';
    toast('二次认证', r.message || '已启用', 'ok');
    invalidateCache();
    loadAuthConfig();
  } catch (e) { toast('启用失败', e.message, 'err'); }
}

async function totpDisable() {
  const pw = prompt('停用二次认证需要重新输入面板密码：');
  if (!pw) return;
  try {
    const r = await api('/api/auth/totp/disable', {
      method: 'POST', body: JSON.stringify({ password: pw }),
    });
    toast('二次认证', r.message || '已停用', 'ok');
    invalidateCache();
    loadAuthConfig();
  } catch (e) { toast('停用失败', e.message, 'err'); }
}

async function saveOAuth() {
  try {
    const r = await api('/api/auth/oauth', {
      method: 'POST',
      body: JSON.stringify({
        client_id: $('#oaClientId').value.trim(),
        client_secret: $('#oaSecret').value,
        allowed_users: $('#oaUsers').value,
      }),
    });
    $('#oaSecret').value = '';
    toast('GitHub OAuth', r.message || '已保存', 'ok');
    invalidateCache();
    loadAuthConfig();
  } catch (e) { toast('保存失败', e.message, 'err'); }
}

async function togglePassword() {
  const want = $('#btnTogglePwd').dataset.disable === '1';
  if (want && !confirm('关闭后只能用 GitHub 登录。若 GitHub 不可达，需在服务器执行 sudo dns-stack panel-password 才能恢复。确认关闭？')) return;
  try {
    const r = await api('/api/auth/password-toggle', {
      method: 'POST', body: JSON.stringify({ disabled: want }),
    });
    toast('登录方式', r.message || '已更新', 'ok');
    invalidateCache();
    loadAuthConfig();
  } catch (e) { toast('操作失败', e.message, 'err'); }
}

let _modulesBound = false;
async function loadOps() {
  if (!_modulesBound) {
    const b = $('#btnReloadModules');
    if (b) { b.addEventListener('click', () => { invalidateCache(); loadModules(); }); _modulesBound = true; }
  }
  loadModules();
  loadBackups();
  renderRoleExtra();
}

async function loadSecurity() {
  bindAuthButtons();
  renderPosture();
  renderAccessInfo();
  loadAuthConfig();
  loadDohInfo();
}

async function loadDohInfo() {
  const box = $('#dohBox');
  const badge = $('#dohBadge');
  try {
    const d = await api('/api/doh');
    secState.doh = d;
    renderPosture();
    setHtml(badge, d.is_default
      ? html`<span class="badge warn">未设私密路径</span>`
      : html`<span class="badge ok">已启用私密路径</span>`);
    setHtml(box, html`<pre class="block" id="dohUrl">${d.doh_url}</pre>
      <div class="row mt-8">
        <button class="sm" id="btnCopyDoh">复制地址</button>
        <button class="danger sm" data-op="rotate_doh_path">轮换私密路径</button>
      </div>
      ${d.is_default
        ? html`<div class="hint text-warn">
            当前是默认路径 /dns-query，任何人拿到本机 IP 都能当公共 DNS 用。
            建议点「轮换私密路径」换成随机地址。</div>`
        : html`<div class="hint">路径在 TLS 内部传输，探测其它路径一律 404。
            轮换后所有客户端都要同步换新地址。</div>`}`);
  } catch (e) {
    setHtml(box, errState(e));
    setHtml(badge, raw(''));
  }
}

function copyDohUrl() {
  const url = ($('#dohUrl') || {}).textContent || '';
  const fallback = () => {
    const r = document.createRange();
    r.selectNodeContents($('#dohUrl'));
    const s = window.getSelection(); s.removeAllRanges(); s.addRange(r);
    toast('已选中地址', '按 Ctrl+C / ⌘C 复制', 'ok');
  };
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(url)
      .then(() => toast('已复制接入地址', url, 'ok'))
      .catch(fallback);
  } else fallback();
}

const MOD_STATE = {
  ok: { dot: 'ok', text: '正常' },
  warn: { dot: 'warn', text: '需关注' },
  down: { dot: 'err', text: '已中断' },
  unknown: { dot: 'idle', text: '未知' },
};

const IMPL_LABEL = { go: 'Go 原生', shell: 'Shell 脚本', external: '外部组件' };

function until(ts) {
  if (!ts) return '';
  const s = ts - Math.floor(Date.now() / 1000);
  if (s <= 0) return '即将运行';
  if (s < 60) return s + ' 秒后';
  if (s < 3600) return Math.floor(s / 60) + ' 分钟后';
  if (s < 86400) return Math.floor(s / 3600) + ' 小时后';
  return Math.floor(s / 86400) + ' 天后';
}

function moduleRow(m) {
  const st = MOD_STATE[m.state] || MOD_STATE.unknown;
  const facts = [];
  if (m.kind === 'job') {
    if (m.last_run) facts.push('上次 ' + ago(m.last_run));
    if (m.next_run) facts.push('下次 ' + until(m.next_run));
  } else {
    if (m.last_run) facts.push('已运行 ' + ago(m.last_run).replace('前', ''));
    if (m.memory) facts.push('内存 ' + fmtBytes(m.memory));
    if (m.restarts) facts.push('重启 ' + m.restarts + ' 次');
  }
  const art = m.artifact;
  if (art && art.exists && art.lines) facts.push('产出 ' + fmtNum(art.lines) + ' 条');
  else if (art && !art.exists) facts.push('尚无产出文件');

  return html`<div class="mod ${m.state}">
    <span class="dot ${st.dot}"></span>
    <div class="mod-main">
      <div class="mod-title">
        <b>${m.name}</b>
        ${m.critical ? html`<span class="badge warn">关键</span>` : ''}
        <span class="mod-unit mono dim" title="systemd 单元名">${m.unit}</span>
      </div>
      <div class="mod-purpose">${m.purpose}</div>
    </div>
    <div class="mod-side">
      <span class="mod-state ${m.state}">${m.note || st.text}</span>
      ${facts.length ? html`<span class="mod-facts dim">${facts.join(' · ')}</span>` : ''}
    </div>
  </div>`;
}

function renderSysBar(d) {
  const bar = $('#sysBar');
  if (!bar) return;
  const st = MOD_STATE[d.verdict] || MOD_STATE.unknown;
  const c = d.counts || {};
  const detail = (d.verdict === 'ok')
    ? html`<span class="dim">${d.total} 个模块协同工作，全部就绪</span>`
    : html`<ul class="sys-issues">${(d.attention || []).slice(0, 4).map((x) => html`<li>${x}</li>`)}</ul>`;
  setHtml(bar, html`<div class="sys-card ${d.verdict}">
    <div class="sys-head">
      <span class="dot ${st.dot}"></span>
      <b class="sys-headline">${d.headline}</b>
      <span class="sys-counts mono dim">正常 ${c.ok || 0} · 关注 ${c.warn || 0} · 中断 ${c.down || 0}</span>
      <button class="ghost sm" data-page-jump="settings" data-tab="services">查看模块</button>
    </div>
    <div class="sys-body">${detail}</div>
  </div>`);
}

async function loadModules() {
  const box = $('#moduleGroups');
  try {
    const d = await apiCached('/api/modules');
    renderSysBar(d);
    const impl = d.impl || {};
    setHtml($('#moduleImpl'), html`共 ${d.total} 个模块：${
      Object.keys(IMPL_LABEL).filter((k) => impl[k])
        .map((k) => IMPL_LABEL[k] + ' ' + impl[k]).join(' · ')}`);
    if (!box) return;
    const groups = d.groups || [];
    if (!groups.length) { setHtml(box, EMPTY()); return; }
    setHtml(box, html`${groups.map((g) => {
      const st = MOD_STATE[g.state] || MOD_STATE.unknown;
      return html`<div class="mod-group">
        <div class="mod-group-head">
          <span class="dot ${st.dot}"></span><b>${g.name}</b>
          <span class="dim">${g.modules.length} 个模块</span>
        </div>
        ${g.modules.map(moduleRow)}
      </div>`;
    })}`);
  } catch (e) {
    setHtml(box, errState(e));
    setHtml($('#sysBar'), stateHtml('模块状态加载失败：' + e.message, 'error'));
  }
}

async function loadBackups() {
  try {
    const d = await api('/api/backups');
    const list = (items, empty) => (items && items.length)
      ? html`<div class="table-wrap"><table>
          <thead><tr><th>文件</th><th>大小</th><th>时间</th></tr></thead>
          <tbody>${items.map((x) => html`<tr>
            <td class="mono wrap">${x.name}</td>
            <td class="mono">${fmtBytes(x.size)}</td>
            <td class="mono dim">${fmtTime(x.mtime)}</td></tr>`)}</tbody>
        </table></div>`
      : EMPTY(empty);
    setHtml($('#backupList'), list(d.backups, '暂无备份文件'));
    setHtml($('#exportList'), list(d.exports, '暂无导出包'));
  } catch (e) {
    setHtml($('#backupList'), errState(e));
  }
}

function renderRoleExtra() {
  if (window.PANEL_ROLE === 'global-builder') {
    setHtml($('#opsRoleExtra'), raw(
      '<div class="card"><h3>规则生成（规则构建角色）</h3>' +
      '<div class="row">' +
      '<button class="primary sm" data-op="rebuild_rules">一键重建规则</button>' +
      '<button class="sm" data-op="pull_candidates">拉取候选域名</button>' +
      '<button class="sm" data-op="classify_start">立即执行分类</button>' +
      '<button class="sm" data-op="classify_authority">按权威位置分类</button>' +
      '<button class="sm" data-op="build_rules">生成规则文件</button>' +
      '<button class="sm" data-op="update_reference_data">更新 PSL 参考数据</button>' +
      '<button class="danger sm" data-op="publish_github">发布到 GitHub</button>' +
      '</div><div class="hint">一键重建只生成本地四文件，不会自动推送 GitHub。</div></div>'));
    return;
  }
  if (window.PANEL_ROLE === 'cn-resolver') {
    setHtml($('#opsRoleExtra'), raw(
      '<div class="card"><h3>递归分流数据</h3>' +
      '<div class="row"><button class="primary sm" data-op="refresh_routing">刷新 direct4 / 权威 / ECS</button>' +
      '</div><div class="hint">只刷新数据产物并执行校验，不修改防火墙、WireGuard 配置或监听端口。</div></div>'));
    return;
  }
  setHtml($('#opsRoleExtra'), raw(''));
}

async function changePassword(e) {
  e.preventDefault();
  const btn = $('#btnPw');
  const msg = $('#pwMsg');
  const oldPw = $('#pwOld').value;
  const newPw = $('#pwNew').value;
  const again = $('#pwNew2').value;

  const fail = (t) => { msg.textContent = t; msg.className = 'login-msg show'; };
  msg.className = 'login-msg';

  if (!oldPw || !newPw) return fail('请填写当前密码与新密码');
  if (newPw.length < 12) return fail('新密码至少 12 位');
  if (newPw !== again) return fail('两次输入的新密码不一致');
  if (!confirm('确认修改面板密码？\n\n所有其它设备上的登录状态会立即失效。')) return;

  btn.disabled = true;
  const label = btn.textContent;
  btn.textContent = '提交中…';
  try {
    const d = await api('/api/password', {
      method: 'POST',
      body: JSON.stringify({ old_password: oldPw, new_password: newPw }),
    });
    $('#pwForm').reset();
    msg.textContent = '';
    toast('密码已更新', d.message || '', 'ok');
    loadAudit();
  } catch (err) {
    fail(err.message);
  }
  btn.disabled = false;
  btn.textContent = label;
}

let _auditBound = false;
async function loadAudit() {
  if (!_auditBound) {
    const b = $('#btnReloadAudit');
    if (b) { b.addEventListener('click', () => { invalidateCache(); loadAudit(); }); _auditBound = true; }
  }
  const body = $('#auditBody');
  try {
    const d = await api('/api/audit?limit=200');
    if (!d.items.length) { setHtml(body, rowSpan(6, EMPTY('暂无审计记录'))); return; }
    setHtml(body, html`${d.items.map((x) => html`<tr>
      <td class="mono dim">${fmtTime(x.ts)}</td>
      <td class="mono">${x.operation}</td>
      <td><span class="badge ${x.ok ? 'ok' : 'err'}">${x.ok ? '成功' : '失败'}</span></td>
      <td class="mono wrap dim">${x.args || '—'}</td>
      <td class="wrap mono audit-msg">${(x.message || '').slice(0, 200)}</td>
      <td>${x.id === null || x.id === undefined ? ''
          : html`<button class="row-del" data-aid="${x.id}" title="删除这条审计记录">删除</button>`}</td>
    </tr>`)}`);
  } catch (e) {
    setHtml(body, rowSpan(6, errState(e)));
  }
}

async function deleteAudit(id, btn) {
  if (!confirm('删除这条审计记录？')) return;
  try {
    const d = await api('/api/action/delete_audit', {
      method: 'POST', body: JSON.stringify({ id: Number(id) }),
    });
    if (d && d.ok === false) { toast('删除失败', d.message || '', 'err'); return; }
    const tr = btn && btn.closest('tr');
    const body = $('#auditBody');
    if (tr) tr.remove();
    if (body && !body.querySelector('tr')) setHtml(body, rowSpan(6, EMPTY('暂无审计记录')));
    toast('已删除该条记录', '', 'ok');
  } catch (e) { toast('删除失败', e.message, 'err'); }
}

let OPS_META = {};

async function loadOpsMeta() {
  try {
    const d = await api('/api/ops');
    OPS_META = {};
    (d.ops || []).forEach((o) => { OPS_META[o.op] = o; });
  } catch (e) {  }
}

const CONFIRM_NOTE = {
  rotate_doh_path: '新路径生效后，所有客户端（sing-box / Surge / iOS 描述文件）'
    + '都必须换成新地址，未更新的客户端会立即解析失败。\n'
    + '轮换过程会重启 mosproxy 并自动校验，校验不过会自动回滚。',
  set_rule_sources: '拉取地址写错会导致下次规则同步失败（sync-rules 每 5 分钟运行一次）。'
    + '镜像留空表示不使用该镜像。',
};

async function runOp(op, label, args, isDangerous) {
  args = args || {};
  if (isDangerous) {
    const note = CONFIRM_NOTE[op] || '这是危险操作，可能中断服务或覆盖数据。';
    if (!confirm('确认执行「' + label + '」？\n\n' + note)) return;
    args.confirm = true;
  }
  toast('正在执行：' + label, '请稍候…');
  try {
    const d = await api('/api/action/' + op, { method: 'POST', body: JSON.stringify(args) });
    if (d.ok) toast(label + ' 完成', (d.message || d.stdout || '').slice(0, 800), 'ok');
    else toast(label + ' 失败', (d.message || d.stderr || '').slice(0, 800), 'err');

    invalidateCache();
    if (['sync_rules', 'rollback_rules', 'cert_check', 'cert_renew', 'build_rules',
      'rebuild_rules', 'classify_authority', 'set_rule_sources'].indexOf(op) >= 0
      && state.page === 'settings') loadRules();
    if (['restart_mosproxy', 'restart_unbound'].indexOf(op) >= 0) setTimeout(loadModules, 1500);
    if (['backup', 'export'].indexOf(op) >= 0) loadBackups();
    if (op === 'rotate_doh_path') { loadDohInfo(); setTimeout(loadModules, 1500); }
    if (op === 'clear_audit') loadAudit();
    if (['clear_domains', 'clear_domains_all', 'purge_legacy'].indexOf(op) >= 0) {
      loadCollected();
      if (state.page === 'queries') loadDomains(1);
      if (state.page === 'overview') loadOverview();
    }
    if (op === 'set_arch_epoch') { loadCollected(); loadOverview(); }
  } catch (e) {
    if (e.status === 428 && e.body && e.body.need_confirm) {
      if (confirm(e.body.message + '\n\n确认继续？')) {
        args.confirm = true;
        return runOp(op, label, args, false);
      }
      return;
    }
    toast(label + ' 出错', e.message, 'err');
  }
}

function jumpTo(page, tab) {
  switchPage(page);
  if (!tab) return;
  const btn = $('#settingTabs button[data-stab="' + tab + '"]');
  if (btn) btn.click();
}

function bindEvents() {
  $('#nav').addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-page]');
    if (btn) switchPage(btn.dataset.page);
  });

  document.addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-page-jump]');
    if (btn) jumpTo(btn.dataset.pageJump, btn.dataset.tab);
  });

  const bindTabs = (tabsSel, attr, onSwitch) => {
    const tabs = $(tabsSel);
    if (!tabs) return;
    tabs.addEventListener('click', (e) => {
      const btn = e.target.closest('button[' + attr + ']');
      if (!btn) return;
      $$(tabsSel + ' button').forEach((b) => b.classList.toggle('active', b === btn));
      const name = btn.getAttribute(attr);
      $$('.tab-panel', tabs.closest('.page')).forEach((p) =>
        p.classList.toggle('active', p.id === attr.replace('data-', '') + '-' + name));
      if (onSwitch) onSwitch(name);
    });
  };
  bindTabs('#queryTabs', 'data-qtab', (name) => {
    if (name !== 'live' && state.liveOn) stopLive();
    if (name === 'domains') loadDomains(1);
  });
  bindTabs('#toolTabs', 'data-ttab', (name) => {
    if (name !== 'logs' && state.logFollow) stopLogFollow();
    if (name === 'location') loadMyLocation();
    if (name === 'ip' && !$('#ipResult').firstChild) loadIpLookup();
  });
  bindTabs('#settingTabs', 'data-stab', (name) => loadSettingTab(name));

  $('#btnIpLookup').addEventListener('click', loadIpLookup);
  $('#ipQuery').addEventListener('keydown', (e) => { if (e.key === 'Enter') loadIpLookup(); });
  $('#tsSpan').addEventListener('change', loadTimeseries);

  $('#btnSearch').addEventListener('click', () => loadQueries(1));
  $('#fDomain').addEventListener('keydown', (e) => { if (e.key === 'Enter') loadQueries(1); });
  $('#btnReset').addEventListener('click', () => {
    ['#fDomain', '#fQtype', '#fRoute', '#fRcode', '#fRespBy'].forEach((s) => { $(s).value = ''; });
    $('#fSince').value = '0';
    loadQueries(1);
  });
  ['#fQtype', '#fRoute', '#fRcode', '#fRespBy', '#fSince'].forEach((s) => {
    const el = $(s); if (el) el.addEventListener('change', () => loadQueries(1));
  });
  $('#btnPrev').addEventListener('click', () => {
    if (state.queryPage > 1) loadQueries(state.queryPage - 1);
  });
  $('#btnNext').addEventListener('click', () => {
    if (state.queryPage < state.queryPages) loadQueries(state.queryPage + 1);
  });
  $('#btnLiveToggle').addEventListener('click', () => { state.liveOn ? stopLive() : startLive(); });
  $('#btnClearLive').addEventListener('click', () => {
    setHtml($('#liveBody'), rowSpan(9, EMPTY('已清空')));
  });
  const bindExport = (id, dataset, format) => {
    const el = $(id);
    if (el) el.addEventListener('click', () => downloadExport(dataset, format));
  };
  bindExport('#btnExportQueriesJson', 'queries', 'json');
  bindExport('#btnExportQueriesCsv', 'queries', 'csv');
  bindExport('#btnExportDomainsJson', 'domains', 'json');
  bindExport('#btnExportDomainsCsv', 'domains', 'csv');
  const btnMigration = $('#btnExportMigration');
  if (btnMigration) btnMigration.addEventListener('click', () => downloadBundle(
    '/api/migration-export', 'dns-stack-migration.tar.gz'));
  bindMigrationImport();

  document.addEventListener('click', (e) => {
    const delQ = e.target.closest('button.row-del[data-qid]');
    if (delQ) { deleteQuery(delQ.dataset.qid, delQ); return; }
    const delA = e.target.closest('button.row-del[data-aid]');
    if (delA) { deleteAudit(delA.dataset.aid, delA); return; }

    const tr = e.target.closest('tr.clickable[data-domain]');
    if (tr) { showDomain(tr.dataset.domain); return; }

    if (e.target.closest('#btnCopyDoh')) { copyDohUrl(); return; }

    const btn = e.target.closest('button[data-op]');
    if (!btn) return;
    const op = btn.dataset.op;
    const meta = OPS_META[op] || {};
    let args = {};
    if (btn.dataset.args) { try { args = JSON.parse(btn.dataset.args); } catch (err) { args = {}; } }
    const dangerous = meta.dangerous !== undefined ? meta.dangerous : btn.classList.contains('danger');
    runOp(op, meta.label || btn.textContent.trim(), args, dangerous);
  });

  const diagBtn = $('#btnDiag');
  if (diagBtn) diagBtn.addEventListener('click', showDiagnostics);

  $('#drawerClose').addEventListener('click', closeDrawer);
  $('#drawerMask').addEventListener('click', closeDrawer);
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeDrawer(); });

  $('#domTabs').addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-metric]');
    if (!btn) return;
    $$('#domTabs button').forEach((b) => b.classList.toggle('active', b === btn));
    state.domMetric = btn.dataset.metric;
    loadDomains(1);   // 换指标等于换了排序口径，必须回到第一页
  });
  const rd = $('#btnReloadDomains');
  if (rd) rd.addEventListener('click', () => { invalidateCache(); loadDomains(1); });
  $('#btnDomSearch').addEventListener('click', () => loadDomains(1));
  $('#domSearch').addEventListener('keydown', (e) => { if (e.key === 'Enter') loadDomains(1); });
  $('#domRoute').addEventListener('change', () => loadDomains(1));
  $('#domLimit').addEventListener('change', () => loadDomains(1));
  $('#btnDomPrev').addEventListener('click', () => {
    if (state.domPage > 1) loadDomains(state.domPage - 1);
  });
  $('#btnDomNext').addEventListener('click', () => {
    if (state.domPage < state.domPages) loadDomains(state.domPage + 1);
  });

  $('#btnSetCacheTtl').addEventListener('click', async () => {
    const ttl = Number($('#cacheTtl').value);
    const label = $('#cacheTtl').selectedOptions[0].textContent;
    if (!confirm('把乐观缓存时长设为「' + label + '」？\n\n'
      + 'Unbound 立即生效；mosproxy 需要重启后才生效。')) return;
    await runOp('set_cache_ttl', '调整乐观缓存时长', { ttl: ttl }, false);
    loadCacheInfo();
  });

  const btnRS = $('#btnSaveRuleSources');
  if (btnRS) btnRS.addEventListener('click', saveRuleSources);

  const pwForm = $('#pwForm');
  if (pwForm) pwForm.addEventListener('submit', changePassword);

  $('#btnTest').addEventListener('click', runDnsTest);
  $('#testDomain').addEventListener('keydown', (e) => { if (e.key === 'Enter') runDnsTest(); });

  $('#btnLogRefresh').addEventListener('click', loadLogs);
  $('#btnLogFollow').addEventListener('click', () => {
    state.logFollow ? stopLogFollow() : startLogFollow();
  });
  $('#btnLogClear').addEventListener('click', () => { state.logLines = []; renderLogs(); });
  $('#logSearch').addEventListener('input', debounce(renderLogs, 120));
  $('#logUnit').addEventListener('change', () => {
    state.logLines = [];
    if (state.logFollow) { stopLogFollow(); startLogFollow(); }
    loadLogs();
  });
  $('#logPriority').addEventListener('change', loadLogs);

  window.addEventListener('hashchange', () => {
    const target = location.hash.replace(/^#/, '');
    if (!target || target === state.page || !PAGE_TITLES[target]) return;
    switchPage(target);
  });

  document.addEventListener('visibilitychange', () => {
    if (!document.hidden && state.page === 'overview') loadOverview();
  });

  let _resizeRaf = 0;
  window.addEventListener('resize', () => {
    if (_resizeRaf) return;
    _resizeRaf = requestAnimationFrame(() => {
      _resizeRaf = 0;
      if (state.tsData) drawChart(state.tsData);
    });
  });
}

function resetFilterControls() {
  ['#fDomain', '#fQtype', '#fRoute', '#fRcode', '#fRespBy', '#domSearch', '#domRoute', '#logSearch']
    .forEach((s) => { const el = $(s); if (el) el.value = ''; });
  const defaults = { '#fSince': '0', '#domLimit': '50', '#logLines': '200', '#logPriority': '', '#tsSpan': '3600' };
  Object.keys(defaults).forEach((s) => { const el = $(s); if (el) el.value = defaults[s]; });
}

async function loadBootstrap() {
  let d = {};
  try {
    d = await api('/api/bootstrap');
  } catch (e) {
    toast('初始化失败', '取不到面板角色等基础信息：' + e.message, 'err');
    return;
  }
  window.PANEL_ROLE = d.role || 'unknown';
  const roleEl = $('#roleName');
  if (roleEl) roleEl.textContent = d.role_name || '未知角色';

  if (d.auth_enabled) {
    document.querySelectorAll('.auth-only').forEach((el) => { el.hidden = false; });
  }

  const sel = $('#logUnit');
  if (sel && d.log_units && d.log_units.length) {
    setHtml(sel, html`${d.log_units.map((u) => html`<option value="${u}">${u}</option>`)}`);
  }
}

(async function init() {
  initTheme();
  initSidebarFold();
  initSession();
  resetFilterControls();
  bindEvents();
  await Promise.all([loadBootstrap(), loadOpsMeta()]);
  const hash = location.hash.replace('#', '');
  switchPage(PAGE_TITLES[hash] ? hash : 'overview');
})();
