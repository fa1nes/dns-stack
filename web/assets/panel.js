
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

const _loadSeq = {};

function latestOnly(key) {
  const mine = (_loadSeq[key] = (_loadSeq[key] || 0) + 1);
  return () => mine === _loadSeq[key];
}

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

const ICON_WARN = raw('<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="width:12px;height:12px;vertical-align:-1.5px;margin-right:3px"><path d="M10.3 3.9 1.9 18a2 2 0 0 0 1.7 3h16.8a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/><line x1="12" y1="9" x2="12" y2="13.5"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>');

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
  const bp = [440, 560, 640, 760, 860, 1180].filter(
    (w) => window.matchMedia('(max-width:' + w + 'px)').matches);
  const coarse = window.matchMedia('(pointer: coarse)').matches;
  const controlSizes = () => {
    const seen = new Map();
    const probes = [
      ['输入框', '.filters input[type="text"], .filters input[type="search"]'],
      ['下拉框', '.filters .xsel-btn'],
      ['按钮', '.filters button:not(.xsel-btn):not(.icon)'],
    ];
    probes.forEach(([label, sel]) => {
      const el = Array.from(document.querySelectorAll(sel))
        .find((node) => node.offsetParent !== null);
      if (!el) return;
      const size = getComputedStyle(el).fontSize;
      if (!seen.has(size)) seen.set(size, []);
      seen.get(size).push(label);
    });
    if (!seen.size) return '本页没有并排的表单控件';
    const parts = Array.from(seen, ([size, labels]) => labels.join('/') + '=' + size);
    return parts.join('  ') + (seen.size === 1 ? '  ✓ 一致'
      : '  🔴 同一组筛选控件出现 ' + seen.size + ' 种字号');
  };

  const cellSpills = () => {
    const worst = new Map();
    let cells = 0;
    $$('.page.active td, .page.active th').forEach((cell) => {
      if (getComputedStyle(cell).display === 'none' || !cell.offsetParent) return;
      cells++;
      const box = cell.getBoundingClientRect();
      Array.from(cell.children).forEach((el) => {
        const r = el.getBoundingClientRect();
        const over = Math.round(Math.max(r.right - box.right, box.left - r.left));
        if (over <= 0) return;
        const key = (cell.cellIndex + 1) + ':' + (el.className || el.tagName);
        if (!worst.has(key) || worst.get(key) < over) worst.set(key, over);
      });
    });
    if (!cells) return '本页没有表格';
    if (!worst.size) return cells + ' 个单元格，内容都在格内  ✓';
    const list = Array.from(worst, ([key, over]) => '第' + key.split(':')[0]
      + '列 ' + key.split(':').slice(1).join(':') + ' 超出 ' + over + 'px');
    return '🔴 ' + list.slice(0, 3).join('；')
      + (list.length > 3 ? ' 等 ' + list.length + ' 处' : '');
  };

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
    ['生效断点', (bp.length ? bp.map((w) => '≤' + w).join(' ') : '无(按桌面布局渲染)')
        + '  指针=' + (coarse ? 'coarse(触摸)' : 'fine(鼠标)')],
    ['控件字号', controlSizes()],
    ['单元格溢出', cellSpills()],
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

const THEME_KEY = 'dns-stack-theme';
const THEME_LABEL = { auto: '跟随系统', light: '浅色', dark: '深色' };
const THEME_ICON = {
  auto: raw('<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="8.5"/><path d="M12 3.5v17a8.5 8.5 0 0 0 0-17z" fill="currentColor" stroke="none"/></svg>'),
  light: raw('<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M12 2.5v2M12 19.5v2M4.6 4.6l1.4 1.4M18 18l1.4 1.4M2.5 12h2M19.5 12h2M4.6 19.4 6 18M18 6l1.4-1.4"/></svg>'),
  dark: raw('<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg>'),
};
const prefersLight = window.matchMedia('(prefers-color-scheme: light)');

function themeMode() {
  try {
    const v = localStorage.getItem(THEME_KEY);
    return v === 'light' || v === 'dark' ? v : 'auto';
  } catch (e) { return 'auto'; }
}

function applyTheme() {
  const mode = themeMode();
  const dark = mode === 'dark' || (mode === 'auto' && !prefersLight.matches);
  document.documentElement.dataset.theme = dark ? 'dark' : 'light';
  const meta = $('meta[name="theme-color"]');
  if (meta) meta.content = dark ? '#0a0e15' : '#f6f8fa';
  $$('.theme-btn').forEach((b) => {
    setHtml(b, html`${THEME_ICON[mode]}${b.id === 'themeToggle' ? html`<span class="lbl">${THEME_LABEL[mode]}</span>` : raw('')}`);
    b.title = '主题：' + THEME_LABEL[mode];
    b.setAttribute('aria-label', b.title);
  });
}

function initTheme() {
  applyTheme();
  const next = { auto: 'light', light: 'dark', dark: 'auto' };
  const cycle = () => {
    const mode = next[themeMode()];
    try {
      if (mode === 'auto') localStorage.removeItem(THEME_KEY);
      else localStorage.setItem(THEME_KEY, mode);
    } catch (e) {  }
    document.documentElement.classList.add('theme-switching');
    applyTheme();
    setTimeout(() => document.documentElement.classList.remove('theme-switching'), 260);
    toast('主题：' + THEME_LABEL[mode], '', 'ok');
  };
  $$('.theme-btn').forEach((b) => b.addEventListener('click', cycle));
  prefersLight.addEventListener('change', () => { if (themeMode() === 'auto') applyTheme(); });
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

const isLocalHost = () => ['localhost', '127.0.0.1', '[::1]', '::1'].indexOf(location.hostname) >= 0;

function transport() {
  if (location.protocol === 'https:') return { cls: 'ok', label: 'HTTPS 加密', detail: 'HTTPS 加密' };
  if (isLocalHost()) return { cls: 'ok', label: '本机直连', detail: 'HTTP，只经过本机回环' };
  return { cls: 'err', label: '明文连接', detail: 'HTTP 明文' };
}

async function logout() {
  if (!confirm('确定退出登录？')) return;
  try { await api('/api/logout', { method: 'POST' }); } catch (e) {  }
  location.replace('login');
}

function initSession() {
  const dot = $('#accessDot');
  const txt = $('#accessText');
  if (dot && txt) {
    const state = location.protocol === 'https:' ? ['dot ok', 'HTTPS 已加密']
      : isLocalHost() ? ['dot ok', '本机访问'] : ['dot err', '明文连接'];
    dot.className = state[0];
    setHtml(txt, html`${state[1]}<span class="access-host mono">${location.host}</span>`);
  }

  const locBtn = $('#btnMyLocRefresh');
  if (locBtn) locBtn.addEventListener('click', () => loadMyLocation(true));

  ['#btnLogout', '#btnLogoutMobile'].forEach((sel) => {
    const el = $(sel); if (el) el.addEventListener('click', logout);
  });
}

const state = {
  page: 'overview',
  overviewTimer: null,
  sysModules: null, sysHealth: null,
  liveES: null, liveOn: false, liveLoaded: false, livePaused: false,
  syncingSelects: false,
  logES: null, logFollow: false, logLines: [],
  queryPage: 1, queryPages: 1,
  domMetric: 'new',
  domPage: 1, domPages: 1,
  tsData: null,
  upstreamLatency: {},
};

const PAGE_TITLES = {
  overview: '概览', queries: '查询', tools: '工具', settings: '设置', account: '账号',
};

const PAGE_DESCS = {
  overview: '解析是否健康、快不快',
  queries: '每一条请求和域名统计',
  tools: '解析测试、CDN 就近、IP 与日志',
  settings: '接入、域名规则、缓存与维护',
  account: '登录方式与会话',
};

const SETTING_TAB_LOADERS = {
  entry: loadEntry,
  rules: loadAccess,
  data: loadData,
  ops: loadOps,
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
  latestOnly('overview-loop');
  if (state.overviewTimer) { clearTimeout(state.overviewTimer); state.overviewTimer = null; }

  const loaders = {
    overview: startOverview,
    queries: function () {
      const active = $('#queryTabs button.active');
      if (!active || active.dataset.qtab === 'live') initLivePage();
      else loadDomains(state.domPage || 1);
    },
    tools: function () {
      const active = $('#toolTabs button.active');
      openToolTab(active ? active.dataset.ttab : 'test');
    },
    settings: function () {
      const active = $('#settingTabs button.active');
      loadSettingTab(active ? active.dataset.stab : 'entry');
    },
    account: loadAccount,
  };
  (loaders[page] || function () {})();
  location.hash = page;
}

function openToolTab(name) {
  if (name !== 'logs' && state.logFollow) stopLogFollow();
  if (name === 'location') loadMyLocation();
  if (name === 'ip' && !$('#ipResult').firstChild) loadIpLookup();
  if (name === 'cdn' && !$('#cdnHitResult').firstChild) loadCdnHit('');
  if (name === 'logs' && !state.logLines.length) loadLogs();
}

function startOverview() {
  loadTimeseries();
  const alive = latestOnly('overview-loop');
  let sinceModules = Infinity;
  const tick = async () => {
    state.overviewTimer = 0;
    if (!alive() || state.page !== 'overview') return;
    if (!document.hidden) {
      try { await loadOverview(); } catch (e) {  }
      if (sinceModules >= 30000) {
        sinceModules = 0;
        try { await loadModules(); } catch (e) {  }
      }
      sinceModules += 5000;
    }
    if (!alive() || state.page !== 'overview') return;
    state.overviewTimer = setTimeout(tick, 5000);
  };
  tick();
}

function cacheUpstreams(list) {
  const lat = {};
  (list || []).forEach((u) => {
    if (u.avg_latency_ms !== null && u.avg_latency_ms !== undefined) lat[u.tag] = u.avg_latency_ms;
  });
  state.upstreamLatency = lat;
}

async function loadOverview() {
  try {
    const d = await apiCached('/api/overview');
    const health = overviewHealth(d);
    const dot = $('#healthDot');
    dot.className = 'dot ' + health.level;
    dot.title = health.reasons.length ? health.reasons.join('\n') : '解析正常';
    state.sysHealth = health;
    renderAlert();
    cacheUpstreams(d.upstreams);
    renderOverviewStats(d);
    renderRouteCard(d.routing);
    renderOverviewUpstreams(d.upstreams);
    renderOverviewSystem(d.system, d.mosproxy);
    renderResolver(d.mosproxy, d.unbound);
  } catch (e) {
    setHtml($('#ovStats'), stateHtml('概览加载失败：' + e.message, 'error'));
    $('#healthDot').className = 'dot err';
  }
}

function overviewHealth(d) {
  const down = [];
  const degraded = [];
  if (!(d.mosproxy && d.mosproxy.available)) down.push('mosproxy 没有响应');
  if (!(d.unbound && d.unbound.available)) down.push('本机 Unbound 没有响应');
  (d.upstreams || []).forEach((u) => {
    if (!u.online) degraded.push(upstreamName(u.tag) + ' 离线');
  });
  const fault = routingFault(d.routing);
  if (fault) degraded.push(fault[0] + '：' + fault[1]);
  return { level: down.length ? 'err' : (degraded.length ? 'warn' : 'ok'), reasons: down.concat(degraded) };
}

function renderAlert() {
  const box = $('#ovAlert');
  if (!box) return;
  const health = state.sysHealth || { level: 'ok', reasons: [] };
  const mods = state.sysModules;
  const issues = health.reasons.concat(mods && mods.verdict !== 'ok' ? (mods.attention || []) : []);
  if (!issues.length) { setHtml(box, raw('')); return; }
  const bad = health.level === 'err' || (mods && mods.verdict === 'down');
  setHtml(box, html`<div class="callout ${bad ? 'err' : ''} alert-bar">
    <ul>${issues.slice(0, 5).map((x) => html`<li>${x}</li>`)}</ul>
    <button class="sm" data-page-jump="settings" data-tab="ops">查看</button>
  </div>`);
}

const UPSTREAM_NAMES = {
  'local-unbound': ['本机 Unbound', ''],
  'foreign-hk': ['香港 Unbound', '本机解析失败时接手，也负责「香港解析」名单'],
  'cn-unbound': ['国内 Unbound', ''],
};
const upstreamName = (tag) => (UPSTREAM_NAMES[tag] || [tag])[0];

function renderOverviewUpstreams(list) {
  const body = $('#ovUpstreamBody');
  if (!body) return;
  if (!list || !list.length) { setHtml(body, rowSpan(6, EMPTY('暂无上游数据'))); return; }
  setHtml(body, html`${list.map((u) => {
    const [name, note] = UPSTREAM_NAMES[u.tag] || [u.tag, ''];
    const ratio = u.success_ratio;
    return html`<tr>
      <td><span class="up-name">${name}</span>${note ? html`<span class="up-note">${note}</span>` : raw('')}</td>
      <td><span class="badge ${u.online ? 'ok' : 'err'}">${u.online ? '在线' : '离线'}</span></td>
      <td class="mono">${fmtNum(u.query_total)}</td>
      <td class="mono ${u.err_total > 0 ? 'text-warn' : 'dim'}"
        title="${ratio === null || ratio === undefined ? '' : '成功率 ' + ratio + '%'}">${fmtNum(u.err_total)}</td>
      <td class="mono">${dash(u.avg_latency_ms, ' ms')}</td>
      <td class="mono">${dash(u.p95_latency_ms, ' ms')}</td>
    </tr>`;
  })}`);
}

const statCard = (num, label, sub, cls, title) => html`<div class="card stat">
    <div class="label">${label}</div>
    <div class="num ${cls || ''}" title="${title || ''}">${num}</div>
    ${sub ? html`<div class="sub">${sub}</div>` : raw('')}
  </div>`;

function renderOverviewStats(d) {
  const m = d.mosproxy || {}, ev = d.events || {};
  const hit = m.cache_hit_ratio || 0;
  setHtml($('#ovStats'), html`${[
    eventsCard(ev, m),
    statCard(m.available ? hit.toFixed(1) + '%' : '—', '缓存命中',
      m.available ? '累计 ' + fmtNum(m.query_total) + ' 次' : '取不到指标',
      hit >= 50 ? 'ok' : (hit >= 20 ? 'warn' : ''), m.available ? fmtNumFull(m.query_total) + ' 次' : ''),
    latencyCard(ev.latency, m),
    failureCard(ev),
  ]}`);
}

function eventsCard(ev, m) {
  if (ev.error) return statCard('—', '近 1 小时请求', ev.error, 'warn');
  if (m && m.available && (m.qps || 0) > 0 && (ev.last_5m || 0) === 0) {
    return statCard('采集已停', '近 1 小时请求', '有查询进来，但 5 分钟没记下任何一条', 'err');
  }
  return statCard(fmtNum(ev.last_1h || 0), '近 1 小时请求',
    '每秒 ' + ((m && m.qps) || 0) + ' 次 · ' + fmtNum(ev.domains || 0) + ' 个域名', '', fmtNumFull(ev.last_1h || 0));
}

function latencyCard(lat, m) {
  if (lat && lat.samples) {
    const p50 = lat.p50;
    const sub = 'P95 ' + dash(lat.p95, ' ms') +
      (lat.slow_1s ? ' · 超过 1 秒 ' + fmtNum(lat.slow_1s) + ' 次' : '') +
      (lat.sampled ? ' · 按最近 ' + fmtNum(lat.sampled_from) + ' 条' : '');
    return statCard(dash(p50, ' ms'), '响应速度', sub,
      p50 === null || p50 === undefined ? '' : (p50 <= 20 ? 'ok' : (p50 <= 200 ? 'warn' : 'err')),
      '中位数 · 平均 ' + dash(lat.avg, ' ms'));
  }
  const avg = m && m.avg_latency_ms;
  return statCard(dash(avg, ' ms'), '响应速度', '近 1 小时没有样本，显示上游平均',
    avg === null || avg === undefined ? '' : (avg <= 50 ? 'ok' : (avg <= 200 ? 'warn' : 'err')));
}

function failureCard(ev) {
  const total = ev.total_24h || 0, failed = ev.failed_24h || 0;
  const rate = total ? failed * 100 / total : 0;
  const card = statCard(total ? rate.toFixed(2) + '%' : '—', '解析失败',
    html`24 小时 ${fmtNum(failed)} 次 · <a href="#" data-page-jump="queries" data-tab="domains" data-metric="fail">看是谁</a>`,
    !total ? '' : (rate < 1 ? 'ok' : (rate < 5 ? 'warn' : 'err')), fmtNumFull(failed) + ' / ' + fmtNumFull(total));
  return card;
}

function routingFault(rt) {
  if (!rt || rt.error) return null;
  const direct4 = rt.direct4_count || 0;
  const zones = rt.cn_zones_count || 0;
  if (rt.chain_active === false) return ['分流失效', '境外查询正直连出去，结果可能被污染'];
  if (rt.tunnel_active === false) return ['隧道断开', '境外查询会失败'];
  if (direct4 > 0 && direct4 < 1000) return ['大陆网段太少', '只有 ' + fmtNum(direct4) + ' 段，国内查询会被误送去香港'];
  if (zones > 0 && (rt.cn_authority_count || 0) === 0) return ['国内权威为空', '直连域名会改走香港'];
  return null;
}

function renderRouteCard(rt) {
  const box = $('#ovRoute');
  if (!box) return;
  if (!rt) { setHtml(box, EMPTY()); return; }
  if (rt.error) { setHtml(box, stateHtml(rt.error, 'error')); return; }
  const fault = routingFault(rt);
  const ex = rt.exits || {};
  const exit = (geo, ip, empty) => {
    const g = geo || {};
    return html`<span>${g.label || (ip ? '位置未知' : empty)}</span>${ip ? html`<span class="mono dim ip-tail">${ip}</span>` : raw('')}`;
  };
  setHtml(box, html`
    <div class="route-state ${fault ? 'err' : 'ok'}">
      <span class="dot ${fault ? 'err' : 'ok'}"></span>
      <b>${fault ? fault[0] : '分流正常'}</b>
      ${fault ? html`<span class="dim">${fault[1]}</span>` : raw('')}
    </div>
    ${kvList([
      ['国内出口', exit(ex.direct_geo, ex.direct_ip, '未配置')],
      ['香港出口', exit(ex.tunnel_geo, ex.tunnel_ip, '未建立')],
      ['大陆网段', fmtNum(rt.direct4_count || 0) + ' 段'],
      ['国内权威', fmtNum(rt.cn_authority_count || 0) + ' 段 · ' + fmtNum(rt.cn_zones_count || 0) + ' 个域名'],
    ])}
    ${ex.tunnel_note ? html`<div class="hint text-warn">${ex.tunnel_note}</div>` : raw('')}`);
}

function renderOverviewSystem(sys, m) {
  if (!sys) { setHtml($('#ovSystem'), EMPTY('取不到系统信息')); return; }
  const bar = (pct, label, detail) => {
    const cls = pct > 90 ? 'err' : (pct > 75 ? 'warn' : '');
    return html`<div class="res">
      <div class="res-head"><span>${label}</span><span class="mono dim">${detail}</span></div>
      <div class="progress"><div class="fill ${cls}" style="width:${Math.min(pct, 100)}%"></div></div>
    </div>`;
  };
  const parts = [];
  if (sys.memory) {
    parts.push(bar(sys.memory.percent, '内存', fmtBytes(sys.memory.used) + ' / ' + fmtBytes(sys.memory.total)));
  }
  if (sys.disk) {
    parts.push(bar(sys.disk.percent, '磁盘', '剩余 ' + fmtBytes(sys.disk.free) + ' / ' + fmtBytes(sys.disk.total)));
  }
  if (sys.load) {
    const pct = Math.min(sys.load['1m'] / (sys.cpu_count || 1) * 100, 100);
    parts.push(bar(pct, '负载（' + sys.cpu_count + ' 核）',
      sys.load['1m'] + ' · ' + sys.load['5m'] + ' · ' + sys.load['15m']));
  }
  const rejected = m ? (m.rejected_cc || 0) + (m.rejected_qps || 0) : 0;
  parts.push(html`<div class="hint">已运行 ${fmtDuration(sys.uptime_seconds)}${rejected
    ? html` · <span class="text-warn">限流拒绝 ${fmtNum(rejected)} 次（并发 ${fmtNum(m.rejected_cc)} / QPS ${fmtNum(m.rejected_qps)}）</span>`
    : raw('')}</div>`);
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

function renderResolver(m, u) {
  const box = $('#ovResolver');
  if (!box) return;
  const left = m && m.available ? kvList([
    ['缓存条目', fmtNum(m.cache_entries)],
    ['后台刷新', fmtNum(m.prefetch_total) + ' 次'],
    ['转发上游', fmtNum(m.upstream_query_total) + ' 次'],
  ]) : stateHtml((m && m.message) || '取不到 mosproxy 指标', 'error');
  const right = u && u.available ? kvList([
    ['Unbound 命中', u.cache_hit_ratio + '%'],
    ['递归耗时', '中位 ' + u.recursion_time_median_ms + ' ms · 平均 ' + u.recursion_time_avg_ms + ' ms'],
    ['带子网应答', u.subnet_queries ? fmtNum(u.subnet_queries) + ' 次'
      : html`<span class="text-warn">0 · CDN 只能按服务器位置选节点</span>`],
  ]) : stateHtml((u && u.message) || '取不到 Unbound 统计', 'error');
  setHtml(box, html`<div class="two-col">${left}${right}</div>`);
}

async function loadTimeseries() {
  const span = Number($('#tsSpan').value || 3600);
  const fresh = latestOnly('timeseries');
  try {
    const d = await api('/api/timeseries?span=' + span + '&buckets=72');
    if (!fresh()) return;
    state.tsData = d;
    drawChart(state.tsData);
  } catch (e) {
    if (!fresh()) return;
    state.tsData = null;
    setHtml($('#tsChart'), errState(e));
  }
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
  if (!state.liveLoaded) { state.liveLoaded = true; loadQueries(1); }
  if (!state.livePaused) startLive();
}

const ROUTE_CLS = { cn: 'cn', foreign: 'foreign', recursive: 'cn', cache: 'cache', reject: 'reject', failed: 'warn' };

const cnBadge = (inCn) => raw(
  inCn === true ? '<span class="badge cn">国内节点</span>'
  : inCn === false ? '<span class="badge foreign">境外节点</span>'
  : '<span class="badge unknown">位置未知</span>');

const geoText = (g) => html`<span class="geo">${(g && g.label) || '位置未知'}</span>`;

const PATH_TEXT = {
  direct: ['ok', '权威直连'],
  tunnel: ['foreign', '权威经香港'],
  mixed: ['warn', '部分直连'],
  hongkong: ['foreign', '整条走香港'],
  unknown: ['unknown', '权威没问到'],
};
const RULE_TEXT = { cn: '国内解析', hk: '香港解析' };

function routeActions(rt, domain) {
  const target = (rt && (rt.rule_domain || rt.zone)) || domain;
  const buttons = [];
  if (!rt || rt.rule !== 'cn') buttons.push(html`<button class="sm" data-route-add="cn" data-domain="${target}">走国内</button>`);
  if (!rt || rt.rule !== 'hk') buttons.push(html`<button class="sm" data-route-add="hk" data-domain="${target}">走香港</button>`);
  if (rt && rt.rule) buttons.push(html`<button class="sm" data-route-remove="${rt.rule}" data-domain="${rt.rule_domain}">移出名单</button>`);
  buttons.push(html`<button class="sm" data-flush="${target}">清缓存</button>`);
  return html`<div class="row route-actions">${buttons}</div>`;
}

function routingSummary(rt, domain) {
  if (!rt) return raw('');
  const [cls, pathText] = PATH_TEXT[rt.path] || PATH_TEXT.unknown;
  const hops = rt.authorities || [];
  const direct = hops.filter((a) => a.exit === 'direct').length;
  const rows = [];
  if (rt.result_ip) {
    rows.push(['答案', html`<span class="mono">${rt.result_ip}</span> ${geoText(rt.result_geo)} ${cnBadge(rt.result_in_cn)}`]);
  }
  rows.push(['权威', html`<span class="badge ${cls}">${pathText}</span>${hops.length
    ? html` <span class="dim">${hops.length} 个，${direct} 个直连</span>` : raw('')}`]);
  rows.push(['名单', rt.rule
    ? html`<span class="badge accent">${RULE_TEXT[rt.rule]}</span> <span class="mono dim">${rt.rule_domain}</span>`
    : html`<span class="dim">未加入</span>`]);
  if (rt.viewer_subnet) rows.push(['子网', html`<span class="mono">${rt.viewer_subnet}</span> ${ecsVerdict(rt.ecs)}`]);
  const gs = rt.geoip_status;
  if (gs && !gs.available) rows.push(['归属库', html`<span class="badge warn">不可用</span>`]);

  const more = [];
  if (hops.length) {
    more.push(html`<details class="drawer-details"><summary>权威 · ${rt.zone || ''}</summary>
      <div class="dd-body"><table class="mini"><tbody>${hops.map((a) => html`<tr>
        <td class="mono">${a.ns}</td><td class="mono dim">${a.ip}</td><td>${geoText(a.geo)}</td>
        <td><span class="badge ${a.exit === 'direct' ? 'cn' : 'foreign'}">${a.exit === 'direct' ? '直连' : '经香港'}</span></td>
      </tr>`)}</tbody></table></div></details>`);
  }
  if (rt.result_ips_geo && rt.result_ips_geo.length > 1) {
    more.push(html`<details class="drawer-details"><summary>全部地址 · ${rt.result_ips_geo.length}</summary>
      <div class="dd-body"><table class="mini"><tbody>${rt.result_ips_geo.map((r) => html`<tr>
        <td class="mono">${r.ip}</td><td>${geoText(r.geo)}</td><td>${cnBadge(r.in_cn)}</td>
      </tr>`)}</tbody></table></div></details>`);
  }
  return html`${kvList(rows)}
    ${rt.result_ip && !rt.viewer_subnet ? html`<div class="hint">这次没带你的子网，按地区分配节点的网站，你实际拿到的地址可能不同</div>` : raw('')}
    ${routeActions(rt, domain)}${more}`;
}

async function routeChange(btn) {
  const domain = btn.dataset.domain;
  const add = btn.dataset.routeAdd;
  const list = add || btn.dataset.routeRemove;
  const action = add ? 'route_add' : 'route_remove';
  const label = (add ? '加入' : '移出') + RULE_TEXT[list];
  await withBusy(btn, () => accessAction(action, label, { list: list, domains: [domain] }));
  if (state.page === 'tools' && $('#testDomain').value.trim()) runDnsTest();
  else if ($('#drawer').classList.contains('open')) showDomain($('#drawerTitle').textContent);
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
      tags.push(sameRegion ? '<span class="pill ok">本地云</span>'
        : '<span class="pill accent">云</span>');
    } else if (sameCarrier && sameRegion) tags.push('<span class="pill ok">本地节点</span>');
    else if (sameCarrier) tags.push('<span class="pill ok">同运营商</span>');
    else if (normCarrier(ng.carrier) && myCarrier) tags.push('<span class="pill warn">跨运营商</span>');
    if (ng.country && ng.country !== g.country) {
      tags.push('<span class="pill warn">境外</span>');
    }
    if (n.ecs && !n.ecs.honored) {
      tags.push('<span class="pill">不分地区</span>');
    }
    return html`<div class="probe" title="${geoWhy(ng)}${ecsWhy(n.ecs)}">
      <div class="probe-h">
        <span class="probe-n">${n.name}</span>
        ${raw(tags.join(''))}
      </div>
      <div class="probe-g">${ng.label || (n.ip ? '位置未知' : n.error || '解析失败')}</div>
      <div class="probe-ip mono">${n.ip || ''}</div>
    </div>`;
  });

  return html`<div class="loc-grid">
    <div class="loc-me">
      ${field('你的 IP', html`<span class="mono">${d.client_ip}</span>`)}
      ${field('位置', where)}
      ${field('运营商', carrier)}
      ${field('代你询问的子网', html`<span class="mono">${d.ecs || '—'}</span>`)}
    </div>
    <div class="loc-nodes">${nodes.length ? nodes : EMPTY('暂无探测结果')}</div>
  </div>`;
}

function geoWhy(g) {
  if (!g) return '';
  if (!g.available) return '归属库不可用' + (g.error ? '：' + g.error : '');
  if (!g.label) return '归属库里没有这个 IP';
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
  if (!e) return '\n看不出是否按地区作答';
  return e.honored ? `\n按 ${e.subnet} 的地区作答（/${e.scope}）` : '\n不分地区，所有人拿到同一个地址';
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
    ['大陆网段', tri(routing.direct4, '在内', '不在')],
    ['国内权威', tri(routing.cn_authority, '是', '否')],
    ['共享 anycast', routing.shared_anycast === true
      ? raw('<span class="badge warn">是，不直连</span>')
      : raw('<span class="badge ok">否</span>')],
    ['污染地址', routing.polluted === true
      ? raw('<span class="badge err">是</span>')
      : raw('<span class="badge ok">否</span>')],
    ['公网地址', tri(routing.global, '是', '保留/私有')],
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
    <h3>归属库</h3>
    <div class="table-wrap"><table class="tbl">
      <thead><tr><th>数据库</th><th>构建时间</th><th>距今</th></tr></thead>
      <tbody>${rows}</tbody></table></div>

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
      <h3>归属</h3>
      <div class="table-wrap"><table class="tbl ip-matrix">
        <thead><tr><th class="rowhead"></th>${head}</tr></thead>
        <tbody>${body}</tbody></table></div>
      ${(d.divergences || []).length ? html`<div class="hint text-warn">标「分歧」的行各库说法不一</div>` : raw('')}
      ${unavailable.length
        ? html`<div class="hint">没查：${unavailable.map((s) => s.label + (s.error ? '（' + s.error + '）' : '')).join('、')}</div>`
        : ''}
    </div>

    <div class="card">
      <h3>在本机分流里</h3>
      ${kvList(ipRoutingRow(d.routing))}
    </div>

    ${ipFreshnessHtml(d.freshness)}
  `);
}

async function loadIpLookup() {
  const box = $('#ipResult');
  const value = $('#ipQuery').value.trim();
  setHtml(box, stateHtml('查询中…'));
  const fresh = latestOnly('ip-lookup');
  try {
    const d = await api('/api/ip-lookup' + (value ? '?ip=' + encodeURIComponent(value) : ''));
    if (!fresh()) return;
    renderIpLookup(d);
  } catch (e) {
    if (!fresh()) return;
    setHtml(box, errState(e));
  }
}

function ecsVerdict(e) {
  if (!e) return html`<span class="badge unknown" title="应答里没有子网信息，可能来自缓存">看不出是否按地区</span>`;
  if (e.honored) return html`<span class="badge ok">按地区作答 /${e.scope}</span>`;
  return html`<span class="badge warn">不分地区</span>`;
}

const routeBadge = (r) =>
  html`<span class="badge ${ROUTE_CLS[r.route] || 'unknown'}">${r.route_name || r.route}</span>`;
const rcodeBadge = (r) =>
  html`<span class="badge ${r.rcode === 0 ? 'ok' : (r.rcode === 3 ? 'warn' : 'err')}">${r.rcode_name}</span>`;

function latencyCell(r) {
  const ms = r.elapsed_ms;
  if (ms !== null && ms !== undefined) {
    const v = ms >= 10 ? ms.toFixed(0) : ms.toFixed(1);
    const cls = ms <= 50 ? 'ok' : (ms <= 800 ? 'warn' : 'err');
    return html`<span class="lat ${cls}">${v} ms</span>`;
  }
  const avg = r.cache_hit ? undefined : state.upstreamLatency[r.resp_by];
  if (avg === undefined) return html`<span class="dim">—</span>`;
  return html`<span class="dim" title="这条没有单次耗时，显示的是上游平均">~${avg} ms</span>`;
}

const ICON_DEL = raw('<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><line x1="7" y1="7" x2="17" y2="17"/><line x1="17" y1="7" x2="7" y2="17"/></svg>');

const queryRow = (r) => html`<tr class="clickable" data-domain="${r.domain}">
    <td class="mono dim">${fmtClock(r.ts)}</td>
    <td class="mono wrap">${r.domain}</td>
    <td class="mono">${r.qtype_name}</td>
    <td>${rcodeBadge(r)}</td>
    <td>${routeBadge(r)}</td>
    <td class="mono">${latencyCell(r)}</td>
    <td>${r.id === null || r.id === undefined ? ''
        : html`<button class="row-del" data-qid="${r.id}" title="删除这条记录" aria-label="删除">${ICON_DEL}</button>`}</td>
  </tr>`;

async function deleteRecord(op, args, opts) {
  if (!confirm(opts.confirm)) return;
  try {
    const d = await api('/api/action/' + op, { method: 'POST', body: JSON.stringify(args) });
    if (d && d.ok === false) { toast('删除失败', d.message || '', 'err'); return; }
    const tr = opts.btn && opts.btn.closest('tr');
    if (tr) tr.remove();
    toast(opts.done, opts.detail || '', 'ok');
    opts.after();
  } catch (e) { toast('删除失败', e.message, 'err'); }
}

function deleteQuery(id, btn) {
  return deleteRecord('delete_query', { id: Number(id) }, {
    confirm: '删除这条请求记录？', btn, done: '已删除',
    after: () => { invalidateCache(); loadQueries(state.queryPage); },
  });
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
    setTimeout(() => URL.revokeObjectURL(url), 10000);
  } catch (e) { toast('导出失败', e.message, 'err'); }
}

async function runMigrationImport(dryRun) {
  const input = $('#migrationFile');
  const out = $('#migrationImportResult');
  const file = input && input.files && input.files[0];
  if (!file) { toast('请先选择迁移包', '需要本面板导出的 .tar.gz', 'warn'); return; }
  if (!dryRun && !confirm(
    '导入会按清单覆盖本机规则/状态文件（覆盖前自动备份）。确认继续？')) return;
  const buttons = ['#btnMigrationDryRun', '#btnMigrationImport'].map((sel) => $(sel)).filter(Boolean);
  buttons.forEach((b) => { b.disabled = true; });
  setHtml(out, html`<div class="state"><span class="spinner"></span> ${dryRun ? '试算中…' : '导入中…'}</div>`);
  const form = new FormData();
  form.append('bundle', file);
  form.append('dry_run', dryRun ? 'true' : 'false');
  try {
    const res = await fetch(
      (window.dnsStackApiUrl || ((p) => p))('/api/migration-import'),
      { method: 'POST', credentials: 'include', body: form });
    let body = {};
    try { body = await res.json(); } catch (e) { body = {}; }
    if (!res.ok) throw new Error(body.error || ('HTTP ' + res.status));
    const rep = body.report;
    if (!rep) {
      setHtml(out, stateHtml(body.stderr || body.error || '未返回报告', 'error'));
      return;
    }
    const counts = {};
    (rep.applied || []).forEach((it) => { counts[it.action] = (counts[it.action] || 0) + 1; });
    const parts = [];
    if (counts['written']) parts.push('已写入 ' + counts['written']);
    if (counts['would-write']) parts.push('将写入 ' + counts['would-write']);
    if (counts['unchanged']) parts.push('内容相同 ' + counts['unchanged']);
    const skipped = rep.skipped || [];
    setHtml(out, html`<div class="import-report">
      <div><b>${rep.dry_run ? '试算' : '导入'}结果：</b>${parts.join('，') || '无变化'}</div>
      ${rep.backup_dir ? html`<div>原文件已备份到 <code>${rep.backup_dir}</code></div>` : ''}
      ${skipped.length ? html`<div><b>跳过 ${skipped.length} 项：</b></div>
        <ul>${skipped.slice(0, 8).map((it) => html`<li><code>${it.path}</code> — ${it.reason}</li>`)}</ul>` : ''}
    </div>`);
    toast(rep.dry_run ? '试算完成' : '导入完成', parts.join('，') || '无变化', 'ok');
    if (!rep.dry_run) { invalidateCache(); loadOverview(); loadData(); }
  } catch (e) {
    setHtml(out, stateHtml(e.message, 'error'));
    toast('导入失败', e.message, 'err');
  } finally {
    buttons.forEach((b) => { b.disabled = false; });
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
  setHtml(body, rowSpan(7, LOADING));
  const params = new URLSearchParams({ page: String(page), size: '50' });
  const filters = {
    domain: $('#fDomain').value.trim(),
    qtype: $('#fQtype').value,
    route: $('#fRoute').value,
    rcode: $('#fRcode').value,
  };
  Object.keys(filters).forEach((k) => { if (filters[k]) params.set(k, filters[k]); });
  const sinceSec = Number($('#fSince').value || 0);
  if (sinceSec) params.set('since', String(Math.floor(Date.now() / 1000) - sinceSec));

  const fresh = latestOnly('queries');
  try {
    const d = await api('/api/queries?' + params.toString());
    if (!fresh()) return;
    state.queryPage = d.page;
    state.queryPages = d.pages || 1;
    if (!d.items.length) {
      setHtml(body, rowSpan(7, EMPTY('没有符合条件的请求')));
    } else {
      setHtml(body, html`${d.items.map((r) => queryRow(r))}`);
    }
    $('#liveCount').textContent = (d.total_capped ? '超过 ' : '共 ') + fmtNum(d.total) + ' 条';
    $('#pageInfo').textContent = d.page + ' / ' + (d.pages || 1) + (d.total_capped ? '+' : '');
    $('#btnPrev').disabled = d.page <= 1;
    $('#btnNext').disabled = d.page >= (d.pages || 1);
  } catch (e) {
    if (!fresh()) return;
    setHtml(body, rowSpan(7, errState(e)));
    $('#liveCount').textContent = '—';
  }
}

function setLiveStatus(dot, text) {
  $('#liveDot').className = 'dot ' + dot;
  $('#liveStatus').textContent = text;
}

function startLive() {
  if (state.liveES) return;
  state.liveOn = true;
  state.livePaused = false;
  $('#btnLiveToggle').textContent = '暂停';
  setLiveStatus('idle', '连接中…');

  const es = new EventSource(
    (window.dnsStackApiUrl || ((p) => p))('/api/queries/stream'),
    { withCredentials: true });
  state.liveES = es;
  es.onmessage = (ev) => {
    try {
      const d = JSON.parse(ev.data);
      if (!d.events || !d.events.length || state.queryPage !== 1) return;
      const f = $('#fDomain').value.trim().toLowerCase();
      const rt = $('#fRoute').value;
      const qt = $('#fQtype').value;
      const rc = $('#fRcode').value;
      const rows = d.events.filter((r) =>
        (!f || (r.domain || '').toLowerCase().indexOf(f) >= 0) &&
        (!rt || r.route === rt) &&
        (!qt || r.qtype_name === qt) &&
        (!rc || r.rcode_name === rc));
      if (!rows.length) return;
      const body = $('#liveBody');
      const placeholder = body.querySelector('td[colspan]');
      if (placeholder) setHtml(body, raw(''));
      prependHtml(body, html`${rows.map((r) => queryRow(r))}`);
      $$('tr', body).slice(0, rows.length).forEach((tr) => tr.classList.add('fresh'));
      trimChildren(body, 300);
    } catch (e) {  }
  };
  es.onerror = () => setLiveStatus('warn', '断开了，正在重连…');
  es.onopen = () => setLiveStatus('live', '实时');
}

function stopLive(paused) {
  if (state.liveES) { state.liveES.close(); state.liveES = null; }
  state.liveOn = false;
  if (paused) state.livePaused = true;
  $('#btnLiveToggle').textContent = '继续';
  setLiveStatus('idle', paused ? '已暂停' : '未连接');
}

let _drawerReturnFocus = null;

function openDrawer(title) {
  const drawer = $('#drawer');
  if (!drawer.classList.contains('open')) _drawerReturnFocus = document.activeElement;
  $('#drawerTitle').textContent = title;
  setHtml($('#drawerBody'), LOADING);
  drawer.hidden = false;
  requestAnimationFrame(() => {
    drawer.classList.add('open');
    $('#drawerMask').classList.add('open');
  });
  $('#drawerClose').focus({ preventScroll: true });
}
function closeDrawer() {
  const drawer = $('#drawer');
  if (!drawer.classList.contains('open')) return;
  drawer.classList.remove('open');
  $('#drawerMask').classList.remove('open');
  setTimeout(() => { if (!drawer.classList.contains('open')) drawer.hidden = true; }, 260);
  if (_drawerReturnFocus && document.contains(_drawerReturnFocus)) _drawerReturnFocus.focus({ preventScroll: true });
  _drawerReturnFocus = null;
}

function recordList(records, ipsGeo) {
  const geo = {};
  (ipsGeo || []).forEach((x) => { geo[x.ip] = x; });
  if (!records || !records.length) return EMPTY('没有记录');
  return html`<table class="mini records"><tbody>${records.map((rec) => {
    const g = geo[rec.value];
    return html`<tr>
      <td class="mono rtype">${rec.type}</td>
      <td class="mono wrap">${rec.value}</td>
      <td>${g ? html`${geoText(g.geo)} ${cnBadge(g.in_cn)}` : raw('')}</td>
      <td class="mono dim ttl">${rec.ttl === null || rec.ttl === undefined ? '' : rec.ttl + 's'}</td>
    </tr>`;
  })}</tbody></table>`;
}

const SERVER_LABEL = { 'local-unbound': '本机', 'foreign-hk': '香港' };
const RESP_NAME = { cache: '缓存', 'local-unbound': '本机', 'foreign-hk': '香港', '(无)': '没有回答' };

async function showDomain(domain) {
  openDrawer(domain);
  const fresh = latestOnly('domain-detail');
  try {
    const d = await api('/api/domain/' + encodeURIComponent(domain) + '?live=true');
    if (!fresh()) return;
    const parts = [routingSummary(d.routing, domain)];

    if (d.live) {
      parts.push(html`<h4>现在解析</h4><div class="grid c2 tight">${Object.keys(d.live).map((server) => {
        const types = d.live[server];
        const records = [];
        Object.keys(types).forEach((qt) => { (types[qt].records || []).forEach((r) => records.push(r)); });
        const seen = {};
        const unique = records.filter((r) => {
          const k = r.type + r.value;
          if (seen[k]) return false;
          seen[k] = true;
          return true;
        });
        const errors = Object.keys(types).map((k) => types[k].error).filter(Boolean);
        const empty = errors.length
          ? html`<span class="badge err" title="${errors[0]}">出错</span>`
          : html`<span class="badge unknown">没有记录</span>`;
        return html`<div class="sub-card"><div class="sub-head">${SERVER_LABEL[server] || server}
          ${unique.length ? raw('') : empty}</div>
          ${unique.length ? recordList(unique) : raw('')}</div>`;
      })}</div>`);
    }

    if (d.aggregate) {
      const a = d.aggregate;
      parts.push(html`<h4>统计</h4>`);
      parts.push(kvList([
        ['请求', fmtNum(a.occurrence_count) + ' 次' + (a.fail_count ? '，失败 ' + fmtNum(a.fail_count) + ' 次' : '')],
        ['最近', (a.last_rcode_name || '—') + ' · ' + (a.last_route_name || '—')],
        ['首次', fmtTime(a.first_seen_at) + '（' + ago(a.first_seen_at) + '）'],
        ['最后', fmtTime(a.last_seen_at) + '（' + ago(a.last_seen_at) + '）'],
      ]));
    }
    if (d.by_upstream && d.by_upstream.length > 1) {
      parts.push(html`<h4>谁回答的</h4>`);
      parts.push(barRows(d.by_upstream.map((x) => ({ name: RESP_NAME[x.resp_by] || x.resp_by, count: x.count }))));
    }
    if (d.recent && d.recent.length) {
      parts.push(html`<h4>最近 ${d.recent.length} 次</h4>`);
      parts.push(html`<table class="mini"><tbody>${d.recent.map((r) => html`<tr>
          <td class="mono dim">${fmtTime(r.ts)}</td>
          <td class="mono">${r.qtype_name}</td>
          <td>${rcodeBadge(r)}</td>
          <td>${routeBadge(r)}</td></tr>`)}</tbody></table>`);
    }
    parts.push(html`<div class="drawer-foot">
      <button class="danger sm" id="btnDelDomain">删除统计</button>
      <span class="hint m0">只删面板里的记录，不影响解析</span>
    </div>`);

    setHtml($('#drawerBody'), html`${parts}`);
    const delBtn = $('#btnDelDomain');
    if (delBtn) delBtn.addEventListener('click', () => deleteDomain(domain));
  } catch (e) {
    if (!fresh()) return;
    setHtml($('#drawerBody'), errState(e));
  }
}

function deleteDomain(domain) {
  return deleteRecord('delete_domain', { domain: domain }, {
    confirm: '删除「' + domain + '」的全部统计？\n\n只删面板里的记录，不影响解析。',
    done: '已删除', detail: domain,
    after: () => {
      closeDrawer();
      if (state.page === 'queries') loadDomains(state.domPage);
      if (state.page === 'settings') loadCollected();
    },
  });
}

const EXTRA_FILTERS = ['#fQtype', '#fRoute', '#fRcode', '#fSince'];

function setFilterMore(open) {
  const box = $('#filterMore');
  const btn = $('#btnFilterMore');
  if (!box || !btn) return;
  box.hidden = !open;
  btn.setAttribute('aria-expanded', open ? 'true' : 'false');
  btn.classList.toggle('active', open);
}

function syncFilterCount(settle) {
  const active = EXTRA_FILTERS.filter((s) => {
    const el = $(s);
    return el && el.value && el.value !== '0';
  }).length;
  const badge = $('#filterCount');
  if (badge) {
    badge.textContent = String(active);
    badge.hidden = active === 0;
  }
  if (settle || active > 0) setFilterMore(active > 0);
}

const DOM_COUNT_LABEL = {
  new: (n) => n + ' 个域名',
  recent: (n) => n + ' 个域名',
  count: (n) => n + ' 个域名',
  fail: (n) => n + ' 个域名失败过',
  slow: (n) => n + ' 个域名有耗时记录',
};

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

  const fresh = latestOnly('domains');
  try {
    const d = await api('/api/domains?' + params.toString());
    if (!fresh()) return;
    state.domPages = d.pages || 1;
    $('#domCount').textContent = DOM_COUNT_LABEL[state.domMetric](fmtNum(d.total || 0));
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
        ? html`<span class="node-geo">${label || '位置未知'}</span><span class="node-ip mono">${n.ip}</span>`
        : raw('<span class="node-geo dim">—</span>')}</td>
      <td class="mono">${fmtNum(x.occurrence_count)}</td>
      <td class="mono" style="color:${x.fail_count > 0 ? 'var(--err)' : 'var(--text-dim)'}">${fmtNum(x.fail_count)}</td>
      <td class="mono">${dash(x.last_rcode_name)}</td>
      <td class="mono dim">${fmtTime(x.last_seen_at)}</td>
    </tr>`;
    })}`);
  } catch (e) {
    if (!fresh()) return;
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
    ? html`<th>域名</th><th style="width:90px">平均</th><th style="width:90px">最慢</th>
           <th style="width:70px">次数</th><th colspan="3">最后请求</th>`
    : html`<th>域名</th><th style="width:170px">解析到</th>
           <th style="width:80px">请求</th><th style="width:70px">失败</th>
           <th style="width:96px">最近结果</th><th style="width:130px">最后请求</th>`);
}

async function loadDomainSummary() {
  const fresh = latestOnly('domain-summary');
  try {
    const d = await api('/api/domains/summary');
    if (!fresh()) return;
    const byExit = {};
    (d.by_exit || []).forEach((x) => { byExit[x.path] = x.count; });
    const exitCount = (k) => byExit[k] || 0;
    setHtml($('#domSummary'), html`${[
      statCard(fmtNum(exitCount('cache')), '缓存回答', '24 小时', 'ok'),
      statCard(fmtNum(exitCount('recursive')), '本机递归', '24 小时 · 香港 ' + fmtNum(exitCount('hongkong')) + ' 次', ''),
      statCard(fmtNum(d.new_24h || 0), '新域名', '24 小时 · 1 小时内活跃 ' + fmtNum(d.active_1h || 0)),
      statCard(fmtNum(d.failing || 0), '失败的域名', '24 小时 · 累计 ' + fmtNum(d.failed_ever || 0) + ' 个',
        d.failing > 0 ? 'warn' : 'ok'),
    ]}`);

    const barList = (items, el) => {
      setHtml($(el), (items && items.length) ? barRows(items) : EMPTY());
    };
    barList(d.by_qtype, '#domQtype');
    barList(d.by_rcode, '#domRcode');
  } catch (e) {
    if (!fresh()) return;
    setHtml($('#domSummary'), errState(e));
  }
}



function loadEntry() {
  loadDohInfo();
  loadCert();
}

function loadData() {
  loadCacheInfo();
  loadCollected();
  loadRulesInfo();
}

async function loadCert() {
  const box = $('#certInfo');
  try {
    const c = await apiCached('/api/cert');
    if (!c.exists) { setHtml(box, html`${stateTag('err', '找不到')}${c.error || ''}`); return; }
    const days = c.days_left;
    const cls = days === null || days === undefined ? 'idle' : (days <= 2 ? 'err' : (days <= 4 ? 'warn' : 'ok'));
    setHtml(box, html`${stateTag(cls, days === undefined ? '有效期未知' : '还剩 ' + days + ' 天')}${
      c.expires_at ? fmtTime(c.expires_at).slice(0, 5) + ' 到期 · ' : ''}<span class="mono">${c.san || '—'}</span>
      <span class="dim" title="${c.issuer || ''}"> · 每 6 小时自动续签</span>`);
  } catch (e) {
    setHtml(box, errState(e));
  }
}

async function loadRulesInfo() {
  try {
    const d = await apiCached('/api/rules');
    setHtml($('#rulesInfo'), kvList([
      ['CDN', fmtNum(d.cdn_providers) + ' 家 · ' + fmtNum(d.cdn_prefixes) + ' 段，国内 ' + fmtNum(d.cdn_mainland) + ' 段'],
      ['更新于', d.cdn_generated_at ? ago(d.cdn_generated_at) : '—'],
      ['污染 IP', fmtNum(d.polluted_cidr_count) + ' 段'],
      ['香港解析', fmtNum(d.manual_gfw_count) + ' 个域名'],
    ]));
  } catch (e) {
    setHtml($('#rulesInfo'), errState(e));
  }
}

function fmtTtl(sec) {
  if (sec === null || sec === undefined) return '—';
  if (sec === 0) return '关闭';
  if (sec % 86400 === 0) return (sec / 86400) + ' 天';
  if (sec % 3600 === 0) return (sec / 3600) + ' 小时';
  return sec + ' 秒';
}

function syncSelect(id, value) {
  const sel = $(id);
  if (!sel || value === null || value === undefined) return;
  const cur = String(value);
  if (!Array.from(sel.options).some((o) => o.value === cur)) {
    sel.add(new Option((sel.dataset.custom || '{n}').replace('{n}', cur), cur));
  }
  sel.value = cur;
  sel.dataset.applied = cur;
  sel.dispatchEvent(new Event('change', { bubbles: true }));
}

async function loadCacheInfo() {
  try {
    const d = await api('/api/cache');
    const mp = d.mosproxy || {}, ub = d.unbound || {}, hit = d.hit;
    setHtml($('#cacheInfo'), hit && hit.queries
      ? html`Unbound 命中 ${hit.rate.toFixed(1)}%（${fmtNum(hit.hits)} / ${fmtNum(hit.queries)}）`
      : raw('只清本机缓存，下次查询会重新递归'));
    state.syncingSelects = true;
    syncSelect('#cacheTtl', mp.optimistic_ttl);
    syncSelect('#minTtl', ub['cache-min-ttl']);
    state.syncingSelects = false;
  } catch (e) {
    setHtml($('#cacheInfo'), errState(e));
  }
}

async function applySetting(sel, op, label, args, note) {
  if (state.syncingSelects || sel.value === sel.dataset.applied) return;
  const text = sel.selectedOptions[0].textContent.trim();
  if (!confirm(label + '改为「' + text + '」？' + (note ? '\n\n' + note : ''))) {
    sel.value = sel.dataset.applied || sel.value;
    sel.dispatchEvent(new Event('change', { bubbles: true }));
    return;
  }
  sel.dataset.applied = sel.value;
  await runOp(op, label, args(), false);
}

const CDN_VERDICT = {
  mainland: 'ok',
  no_steering: 'idle',
  no_node: 'idle',
  no_echo: 'warn',
  not_delivered: 'err',
  unresolved: 'err',
};

async function loadCdnHit(mode) {
  const box = $('#cdnHitResult');
  const fresh = mode === 'fresh';
  setHtml(box, fresh
    ? html`<div class="state"><span class="spinner"></span> 正在清缓存重查…</div>` : LOADING);
  const current = latestOnly('cdn-hit');
  try {
    const q = '?all=1' + (mode === 'refresh' ? '&refresh=1' : '') + (fresh ? '&fresh=1' : '');
    const d = await api('/api/cdn-hit' + q, fresh ? { method: 'POST' } : undefined);
    if (!current()) return;
    const reports = d.reports || [];
    const vantages = d.vantages || [];
    if (!reports.length) { setHtml(box, EMPTY()); return; }
    let hits = 0, total = 0, pending = 0, missed = 0;
    reports.forEach((r) => {
      hits += r.mainland; total += r.probes.length; pending += r.undecided - countUnresolved(r); missed += r.not_delivered;
    });
    const rows = reports[0].probes.map((p, i) => html`<tr>
      <th class="site" title="${p.domain}"><b>${p.label}</b><span class="mono dim">${p.domain}</span></th>
      ${reports.map((r) => cdnCell(r.probes[i]))}
    </tr>`);
    setHtml(box, html`
      <div class="cdn-summary">
        <div class="cdn-score"><b>${hits}</b><span>/ ${total}</span></div>
        <div>
          <div>拿到国内节点</div>
          <div class="dim">${fmtTime(d.generated_at)}${d.fresh ? ' · 已清缓存' : ''}${pending > 0
            ? html` · <span class="text-warn">${pending} 项来自缓存，点「复核」可确认</span>` : raw('')}</div>
        </div>
      </div>
      ${missed ? html`<div class="callout err">${missed} 项清了缓存仍没收到子网，可能是 ECS 白名单漏了，用 <code>dns-stack ecs-audit</code> 查</div>` : raw('')}
      <div class="table-wrap"><table class="cdn-matrix">
        <thead><tr><th></th>${vantages.map((v) => html`<th>${v.label}</th>`)}</tr></thead>
        <tbody>${rows}</tbody>
      </table></div>
      <div class="legend cdn-legend">
        <span><i class="dot ok"></i>国内节点</span>
        <span><i class="dot idle"></i>不分地区 / 无国内节点</span>
        <span><i class="dot warn"></i>待复核</span>
        <span><i class="dot err"></i>子网没送到 / 解析失败</span>
      </div>`);
  } catch (e) {
    if (!current()) return;
    setHtml(box, errState(e));
  }
}

function countUnresolved(report) {
  return report.probes.filter((p) => p.verdict === 'unresolved').length;
}

function cdnCell(p) {
  if (!p) return html`<td></td>`;
  const cls = CDN_VERDICT[p.verdict] || 'idle';
  const where = (p.geo || '').replace(/^中国\s*/, '') || (p.addrs || [])[0] || p.error || '—';
  const tip = p.verdict_text + '\n' + (p.addrs || []).join(' ') +
    (p.ecs_echoed ? '\n子网作用范围 /' + p.ecs_scope : '') + (p.provider ? '\n' + p.provider : '');
  return html`<td><span class="cdn-cell is-${cls}" title="${tip}">
    <span class="dot ${cls}"></span><span class="cdn-where">${where}</span>
    ${p.verdict === 'mainland' ? raw('') : html`<span class="cdn-why">${p.verdict_short}</span>`}
  </span></td>`;
}

const splitEntries = (text) => String(text || '').split(/[\s,;]+/).filter(Boolean);

const LIST_ACTIONS = {
  route_cn: { add: 'route_add', remove: 'route_remove', list: 'cn', label: '国内解析' },
  route_hk: { add: 'route_add', remove: 'route_remove', list: 'hk', label: '香港解析' },
  blocklist: { add: 'blocklist_add', remove: 'blocklist_remove', label: '拦截名单' },
  acl: { add: 'acl_add', remove: 'acl_remove', label: '访问控制' },
};

function chipList(items, kind, empty) {
  if (!items.length) return html`<span class="note-xs">${empty}</span>`;
  return html`${items.map((item) => html`<span class="chip">
      <span class="mono">${item}</span>
      <button type="button" data-list-remove="${kind}" data-value="${item}" aria-label="移除 ${item}" title="移除">${ICON_X}</button>
    </span>`)}`;
}

function renderAccess(d) {
  const lists = [
    ['route_cn', '#routeCnList', '#routeCnCount', '还没有'],
    ['route_hk', '#routeHkList', '#routeHkCount', '还没有'],
    ['blocklist', '#blList', '#blCount', '没有拦截任何域名'],
  ];
  if (d.note) {
    lists.forEach(([, box]) => setHtml($(box), stateHtml(d.note)));
    setHtml($('#aclList'), stateHtml(d.note));
    return;
  }
  lists.forEach(([key, box, count, empty]) => {
    const items = d[key] || [];
    setHtml($(count), items.length ? html`<span class="badge unknown sm">${items.length}</span>` : raw(''));
    setHtml($(box), d[key + '_error'] ? stateHtml(d[key + '_error'], 'error') : chipList(items, key, empty));
  });
  const acl = d.acl || [];
  setHtml($('#aclBadge'), acl.length
    ? html`<span class="badge ${d.acl_installed ? 'ok' : 'warn'} sm">${d.acl_installed ? '生效中' : '未下发'}</span>`
    : html`<span class="badge unknown sm">未启用</span>`);
  $('#aclActions').hidden = !acl.length;
  setHtml($('#aclList'), html`${d.acl_error ? stateHtml(d.acl_error, 'error') : chipList(acl, 'acl', '不限制，所有人都能用')}${
    acl.length && !d.acl_installed ? html`<div class="callout">改动还没下发，点「重新下发」生效</div>` : raw('')}${
    acl.length && !d.client_loopback && !d.client_covered
      ? html`<div class="callout err">你现在的地址 <span class="mono">${d.client_ip}</span> 不在里面，下发后会把自己挡在外面</div>`
      : raw('')}`);
}

async function loadAccess() {
  ['#routeCnList', '#routeHkList', '#blList', '#aclList'].forEach((id) => setHtml($(id), LOADING));
  try {
    renderAccess(await api('/api/access'));
  } catch (e) {
    ['#routeCnList', '#routeHkList', '#blList', '#aclList'].forEach((id) => setHtml($(id), errState(e)));
  }
}

async function accessAction(action, label, payload, confirmed) {
  const body = Object.assign({ action: action }, payload || {});
  if (confirmed) body.confirm = true;
  try {
    const d = await api('/api/access', { method: 'POST', body: JSON.stringify(body) });
    toast(label + (d.ok ? '' : '失败'), (d.message || '').slice(0, 800), d.ok ? 'ok' : 'err');
    if (state.page === 'settings') await loadAccess();
    return d.ok;
  } catch (e) {
    if (e.status === 428 && e.body && e.body.need_confirm) {
      if (confirm(e.body.message + '\n\n确认继续？')) return accessAction(action, label, payload, true);
      return false;
    }
    toast(label + '失败', e.message, 'err');
    return false;
  }
}

async function listAdd(form) {
  const kind = form.dataset.listForm || 'acl';
  const meta = LIST_ACTIONS[kind];
  const input = $('input', form);
  const items = splitEntries(input.value);
  if (!items.length) { input.focus(); return; }
  const payload = kind === 'acl' ? { prefixes: items } : { domains: items };
  if (meta.list) payload.list = meta.list;
  const ok = await withBusy($('button[type="submit"]', form), () => accessAction(meta.add, '已加入' + meta.label, payload));
  if (ok) input.value = '';
}

async function listRemove(btn) {
  const kind = btn.dataset.listRemove;
  const meta = LIST_ACTIONS[kind];
  const value = btn.dataset.value;
  const payload = kind === 'acl' ? { prefixes: [value] } : { domains: [value] };
  if (meta.list) payload.list = meta.list;
  await withBusy(btn, () => accessAction(meta.remove, '已移出' + meta.label, payload));
}

const TYPE_HINT = { PTR: '反查', TXT: 'TXT', SRV: 'SRV' };

async function runDnsTest() {
  if ($('#btnTest').disabled) return;
  const domain = $('#testDomain').value.trim();
  if (!domain) { $('#testDomain').focus(); return; }
  const subnet = $('#testSubnet').value.trim();
  if (subnet && !/^\d{1,3}\.\d{1,3}\.\d{1,3}\.0\/24$/.test(subnet)) {
    toast('子网格式不对', '写成 a.b.c.0/24', 'err');
    return;
  }
  const btn = $('#btnTest');
  btn.disabled = true;
  btn.classList.add('busy');
  setHtml($('#testResult'), html`<div class="card">${LOADING}</div>`);
  try {
    const body = { domain: domain, qtype: $('#testQtype').value, servers: ['local-unbound', 'foreign-hk'] };
    if (subnet) body.subnet = subnet;
    const d = await api('/api/dns-test', { method: 'POST', body: JSON.stringify(body) });
    const types = (d.qtypes || []).join(' + ');
    const cards = ['local-unbound', 'foreign-hk'].filter((k) => d.results[k]).map((server) => {
      const r = d.results[server];
      const ok = r.status === 'NOERROR';
      return html`<div class="card">
        <h3>${SERVER_LABEL[server]}
          <span class="row"><span class="dim fs-12">${dash(r.query_time_ms, ' ms')}</span>
          <span class="badge ${ok ? 'ok' : 'err'}">${r.status || (r.error ? '出错' : '—')}</span></span></h3>
        ${r.error && !r.status ? stateHtml(r.error, 'error') : recordList(r.records, r.ips_geo)}
      </div>`;
    });
    setHtml($('#testResult'), html`
      ${d.routing ? html`<div class="card"><h3><span class="mono">${d.domain}</span>
        <span class="dim fs-12">${types}</span></h3>${routingSummary(d.routing, d.domain)}</div>`
        : html`<div class="card"><h3><span class="mono">${d.domain}</span><span class="dim fs-12">${TYPE_HINT[types] || types}</span></h3></div>`}
      <div class="grid c2">${cards}</div>`);
  } catch (e) {
    setHtml($('#testResult'), html`<div class="card">${stateHtml('测试失败：' + e.message, 'error')}</div>`);
  } finally {
    btn.disabled = false;
    btn.classList.remove('busy');
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
  const fresh = latestOnly('logs');
  try {
    const d = await api('/api/logs?' + params.toString());
    if (!fresh()) return;
    state.logLines = d.lines || [];
    renderLogs();
    view.scrollTop = view.scrollHeight;
  } catch (e) {
    if (!fresh()) return;
    setHtml(view, stateHtml('日志加载失败：' + e.message, 'error'));
  }
}

function startLogFollow() {
  if (state.logES) return;
  state.logFollow = true;
  $('#btnLogFollow').textContent = '停止跟随';
  $('#btnLogFollow').classList.add('active');

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
  es.onerror = () => {
    if (state.logES === es) $('#btnLogFollow').textContent = '重连中…';
  };
  es.onopen = () => {
    if (state.logES === es) $('#btnLogFollow').textContent = '停止跟随';
  };
}

function stopLogFollow() {
  if (state.logES) { state.logES.close(); state.logES = null; }
  state.logFollow = false;
  $('#btnLogFollow').textContent = '跟随';
  $('#btnLogFollow').classList.remove('active');
}

let _collected = null;
let _dataSet = 'cn_zones';

const DATA_SETS = {
  cn_zones: { unit: '个', hint: '权威在国内，查询直连' },
  polluted: { unit: '个', hint: '实测抓到的伪造应答地址' },
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
    <div class="hint mb-8">
      ${meta.hint || ''} · 共 ${fmtNum(serverTruncated ? dmeta.total : all.length)} ${meta.unit || ''}
      ${kw ? html`· 匹配 ${fmtNum(items.length)}` : ''}
      ${items.length > LIMIT ? html`· 只显示前 ${LIMIT} 条` : ''}
      ${serverTruncated ? html`· <span class="text-warn">只载入了 ${fmtNum(dmeta.returned)} 条，完整数据请导出</span>` : ''}
    </div>
    ${shown.length
      ? html`<div class="data-grid">${shown.map((x) => html`<span class="data-item">${x}</span>`)}</div>`
      : EMPTY(kw ? '没有匹配项' : '暂无数据')}`);
}

function bindCollected() {
  $('#dataTabs').addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-set]');
    if (!btn) return;
    $$('#dataTabs button').forEach((x) => x.classList.toggle('active', x === btn));
    _dataSet = btn.dataset.set;
    renderDataList();
  });
  $('#dataSearch').addEventListener('input', debounce(renderDataList, 120));
  $('#btnExportDataset').addEventListener('click', () => downloadBundle(
    '/api/export?dataset=' + _dataSet + '&format=txt', 'dns-stack-' + _dataSet + '.txt'));
}

async function loadCollected() {
  try {
    const d = await apiCached('/api/collected');
    _collected = d;
    const ip = d.ip || {};

    setHtml($('#collectStats'), html`${[
      statCard(fmtNum(d.domains_total), '域名', '7 天 · 24 小时活跃 ' + fmtNum(d.domains_active_24h)),
      statCard(fmtNum(d.queries_24h), '查询', '24 小时'),
      statCard(fmtNum(ip.cn_zones), '直连域名', '权威在国内', 'ok'),
      statCard(fmtNum(ip.polluted), '污染 IP', fmtNum(ip.polluted_cidr) + ' 段', ip.polluted > 0 ? 'warn' : ''),
    ]}`);

    renderDataList();

    const rows = d.failing_domains || [];
    setHtml($('#failingDomains'), rows.length
      ? html`<div class="table-wrap"><table>
          <thead><tr><th>域名</th><th style="text-align:right">子域</th>
            <th style="text-align:right">失败</th></tr></thead>
          <tbody>${rows.map((x) => html`<tr>
            <td><a href="#" class="dom-link" data-domain="${x.domain}">${x.domain}</a></td>
            <td style="text-align:right" class="mono">${fmtNum(x.subdomains)}</td>
            <td style="text-align:right" class="mono">${fmtNum(x.count)}</td></tr>`)}</tbody>
        </table></div>`
      : EMPTY('24 小时内没有失败'));
    $$('#failingDomains .dom-link').forEach((a) => a.addEventListener('click', (ev) => {
      ev.preventDefault(); showDomain(a.dataset.domain);
    }));
  } catch (e) {
    setHtml($('#collectStats'), errState(e));
  }
}

const secState = { auth: null };

const ICON_X = raw('<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><line x1="7" y1="7" x2="17" y2="17"/><line x1="17" y1="7" x2="7" y2="17"/></svg>');

const nowSec = () => Math.floor(Date.now() / 1000);

const stateTag = (cls, text) => html`<span class="set-state is-${cls}">${text}</span>`;

const oauthState = () => (secState.auth && secState.auth.oauth) || {};

async function withBusy(btn, fn) {
  if (!btn) return fn();
  if (btn.classList.contains('busy')) return undefined;
  btn.disabled = true;
  btn.classList.add('busy');
  try { return await fn(); } finally {
    btn.disabled = false;
    btn.classList.remove('busy');
  }
}

function showPasswords(on) {
  $('#pwShow').checked = on;
  $$('#pwEdit .pw-input').forEach((el) => { el.type = on ? 'text' : 'password'; });
}

function resetEdit(box) {
  if (box.tagName === 'FORM') box.reset();
  $$('.login-msg', box).forEach((m) => { m.className = 'login-msg'; m.textContent = ''; });
  if (box.id === 'pwEdit') { showPasswords(false); renderPwChecks(); }
  if (box.id === 'oaEdit') $('#oaClientId').value = oauthState().client_id || '';
  if (box.id === 'totpEdit') {
    $('#totpSecret').textContent = '';
    delete $('#totpSecret').dataset.copy;
    $('#totpUri').textContent = '';
    $('#totpCode').value = '';
    $('#totpOffPw').value = '';
  }
}

function openEdit(id) {
  $$('#page-account .set-edit').forEach((box) => {
    const open = box.id === id;
    if (!open && !box.hidden) resetEdit(box);
    box.hidden = !open;
  });
  $$('#page-account button[data-edit]').forEach((b) => {
    const open = b.dataset.edit === id;
    b.setAttribute('aria-expanded', open ? 'true' : 'false');
    b.textContent = open ? '取消' : b.dataset.label;
  });
  const first = id && $$('#' + id + ' input:not([type="checkbox"])').find((el) => el.offsetParent !== null);
  if (first) first.focus();
}

function setEditLabel(btn, label) {
  btn.dataset.label = label;
  if (btn.getAttribute('aria-expanded') !== 'true') btn.textContent = label;
}

let _accountBound = false;
function bindAccount() {
  if (_accountBound) return;
  _accountBound = true;
  $('#page-account').addEventListener('click', (e) => {
    const b = e.target.closest('button[data-edit]');
    if (!b) return;
    if (b.getAttribute('aria-expanded') === 'true') openEdit(null);
    else if (b.id === 'btnTotp') totpAction();
    else openEdit(b.dataset.edit);
  });
  $('#userEdit').addEventListener('submit', changeUsername);
  $('#pwEdit').addEventListener('submit', changePassword);
  $('#pwEdit').addEventListener('input', renderPwChecks);
  $('#pwShow').addEventListener('change', (e) => showPasswords(e.target.checked));
  $('#btnTogglePwd').addEventListener('click', togglePassword);
  $('#btnTotpEnable').addEventListener('click', totpEnable);
  $('#totpCode').addEventListener('input', (e) => { e.target.value = e.target.value.replace(/\D/g, '').slice(0, 6); });
  $('#totpCode').addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); totpEnable(); } });
  $('#totpOff').addEventListener('submit', totpDisable);
  $('#oaEdit').addEventListener('submit', saveOAuth);
  $('#oaUserForm').addEventListener('submit', addOAuthUser);
  $('#oaUsers').addEventListener('click', (e) => {
    const b = e.target.closest('button[data-user]');
    if (b) removeOAuthUser(b);
  });
  $('#btnAcctLogout').addEventListener('click', logout);
  $('#btnRevokeOthers').addEventListener('click', revokeOtherSessions);
}

function loadAccount() {
  bindAccount();
  if (secState.auth) renderAccount();
  loadAuthConfig();
}

async function loadAuthConfig() {
  const fresh = latestOnly('auth-config');
  try {
    const d = await api('/api/auth/config');
    if (!fresh()) return;
    secState.auth = d;
    renderAccount();
  } catch (e) {
    if (fresh()) toast('读取账号信息失败', e.message, 'err');
  }
}

function renderAccount() {
  const d = secState.auth;
  const managed = !!d.auth_enabled;
  const t = transport();
  $('#acctNoAuth').hidden = managed;
  $('#acctHero').hidden = !managed;
  $('#acctPlain').hidden = t.cls !== 'err';
  $('#acctManaged').hidden = !managed;
  $('#btnAcctLogout').hidden = !managed;
  $('#revokeRow').hidden = !managed;
  renderSession(d, t);
  if (!managed) return;
  renderHero(d, t);
  renderLogin(d);
  renderOAuth(d.oauth || {}, d.password_disabled);
}

function renderHero(d, t) {
  const name = d.username || '';
  const left = d.session_expires_at ? d.session_expires_at - nowSec() : 0;
  const way = d.password_disabled ? '只能用 GitHub 登录'
    : (d.totp_enabled ? '密码 + 验证码登录' : '密码登录') + ((d.oauth || {}).verified_once ? '，也可用 GitHub' : '');
  $('#acctAvatar').textContent = name ? name[0].toUpperCase() : '?';
  $('#acctName').textContent = name || '未设置用户名';
  $('#acctName').classList.toggle('dim', !name);
  setHtml($('#acctMeta'), html`<span>${way}</span>${
    left > 0 ? html`<span>登录还剩 ${fmtDuration(left)}</span>` : raw('')}${
    t.cls === 'err' ? html`<span class="is-err">${t.label}</span>` : raw('')}`);
}

function renderSession(d, t) {
  const left = d.session_expires_at ? d.session_expires_at - nowSec() : 0;
  setHtml($('#sessionValue'), html`<div><span class="mono">${location.host}</span> · ${t.detail}</div>
    <div>${!d.auth_enabled ? '没设密码，不需要登录'
      : left > 0 ? fmtTime(d.session_expires_at) + ' 到期，还剩 ' + fmtDuration(left) : '—'}</div>`);
}

function renderLogin(d) {
  const o = d.oauth || {};
  const userBtn = $('#btnUserEdit');
  setHtml($('#userValue'), d.username
    ? html`<span class="mono">${d.username}</span>`
    : html`${stateTag('warn', '未设置')}现在登录只要密码`);
  setEditLabel(userBtn, d.username ? '修改' : '设置');
  userBtn.classList.toggle('primary', !d.username);
  $$('.pw-user').forEach((el) => { el.value = d.username || ''; });

  setHtml($('#pwValue'), d.password_set_at ? ago(d.password_set_at) + '改过' : '改密码会让其它设备退出');

  setHtml($('#totpValue'), d.totp_enabled
    ? html`${stateTag('ok', '已启用')}登录要再填 6 位验证码`
    : html`${stateTag('idle', '未启用')}启用后登录要再填 6 位验证码`);
  setEditLabel($('#btnTotp'), d.totp_enabled ? '停用' : '启用');

  const blocked = !d.password_disabled && !o.verified_once;
  setHtml($('#pwLoginValue'), d.password_disabled
    ? html`${stateTag('idle', '已关闭')}只能用 GitHub 登录`
    : html`${stateTag('ok', '开启')}${blocked ? '先用 GitHub 登录成功一次才能关闭' : '关闭后只能用 GitHub 登录'}`);
  const btn = $('#btnTogglePwd');
  btn.textContent = d.password_disabled ? '重新启用' : '关闭';
  btn.className = d.password_disabled ? 'primary sm' : 'danger sm';
  btn.dataset.disable = d.password_disabled ? '0' : '1';
  btn.disabled = blocked;
}

function renderOAuth(o, passwordDisabled) {
  const users = o.allowed_users || [];
  setHtml($('#oauthValue'), o.verified_once
    ? html`${stateTag('ok', '已验证')}Client ID <span class="mono">${o.client_id}</span>`
    : o.ready ? html`${stateTag('warn', '待验证')}用 GitHub 登录成功一次即可`
    : o.client_id && o.secret_set ? html`${stateTag('warn', '未完成')}还要添加允许的账号`
    : html`${stateTag('idle', '未配置')}在 GitHub 建一个 OAuth App 后填进来`);
  setEditLabel($('#btnOaEdit'), o.client_id ? '修改' : '配置');

  const pinned = passwordDisabled && users.length === 1;
  setHtml($('#oaUsers'), users.length ? html`${users.map((u) => html`<span class="chip">
      <span class="mono">${u}</span>
      <button type="button" data-user="${u}" aria-label="移除 ${u}"
        title="${pinned ? '密码登录已关闭，至少要留一个能登录的账号' : '移除'}"${pinned ? raw(' disabled') : raw('')}>${ICON_X}</button>
    </span>`)}`
    : html`<span class="note-xs">还没有</span>`);
  if (document.activeElement !== $('#oaClientId')) $('#oaClientId').value = o.client_id || '';
  $('#oaCallback').textContent = new URL(
    (window.dnsStackApiUrl || ((p) => p))('/api/oauth/github/callback'), location.href).href;
}

function pwChecks() {
  const oldPw = $('#pwOld').value, newPw = $('#pwNew').value;
  return {
    len: Array.from(newPw).length >= 12,
    diff: newPw !== '' && newPw !== oldPw,
    match: newPw !== '' && newPw === $('#pwNew2').value,
  };
}

function renderPwChecks() {
  const c = pwChecks();
  $$('#pwChecks [data-check]').forEach((el) => el.classList.toggle('ok', c[el.dataset.check]));
  $('#btnPw').disabled = !$('#pwOld').value || !(c.len && c.diff && c.match);
}

function failIn(id, text) {
  const msg = $('#' + id);
  msg.textContent = text;
  msg.className = 'login-msg show';
}

async function changeUsername(e) {
  e.preventDefault();
  $('#userMsg').className = 'login-msg';
  if (!$('#userNew').value.trim()) { $('#userNew').focus(); return failIn('userMsg', '请填写新用户名'); }
  if (!$('#userPw').value) { $('#userPw').focus(); return failIn('userMsg', '请输入当前密码'); }
  await withBusy($('#btnUser'), async () => {
    try {
      const d = await api('/api/auth/username', {
        method: 'POST',
        body: JSON.stringify({ username: $('#userNew').value, password: $('#userPw').value }),
      });
      openEdit(null);
      toast('用户名已更新', d.message || '', 'ok');
      loadAuthConfig();
    } catch (err) { failIn('userMsg', err.message); }
  });
}

async function changePassword(e) {
  e.preventDefault();
  const c = pwChecks();
  if (!$('#pwOld').value || !(c.len && c.diff && c.match)) return;
  if (!confirm('修改密码？\n\n其它设备会立即退出，这台不受影响。')) return;
  $('#pwMsg').className = 'login-msg';
  await withBusy($('#btnPw'), async () => {
    try {
      const d = await api('/api/password', {
        method: 'POST',
        body: JSON.stringify({ old_password: $('#pwOld').value, new_password: $('#pwNew').value }),
      });
      openEdit(null);
      toast('密码已更新', d.message || '', 'ok');
      loadAuthConfig();
    } catch (err) { failIn('pwMsg', err.message); }
  });
  renderPwChecks();
}

async function togglePassword() {
  const btn = $('#btnTogglePwd');
  const want = btn.dataset.disable === '1';
  if (want && !confirm('关闭密码登录？\n\n之后只能用 GitHub 登录。GitHub 连不上时，在服务器执行 sudo dns-stack panel-password 恢复。')) return;
  await withBusy(btn, async () => {
    try {
      const r = await api('/api/auth/password-toggle', {
        method: 'POST', body: JSON.stringify({ disabled: want }),
      });
      toast('登录方式', r.message || '已更新', 'ok');
    } catch (e) { toast('操作失败', e.message, 'err'); }
  });
  loadAuthConfig();
}

async function totpAction() {
  if (secState.auth && secState.auth.totp_enabled) {
    $('#totpSetup').hidden = true;
    $('#totpOff').hidden = false;
    openEdit('totpEdit');
    return;
  }
  await withBusy($('#btnTotp'), async () => {
    try {
      const d = await api('/api/auth/totp/setup', { method: 'POST' });
      $('#totpSecret').textContent = d.secret.replace(/(.{4})(?=.)/g, '$1 ');
      $('#totpSecret').dataset.copy = d.secret;
      $('#totpUri').textContent = d.uri;
      $('#totpSetup').hidden = false;
      $('#totpOff').hidden = true;
    } catch (e) { toast('生成失败', e.message, 'err'); }
  });
  if ($('#totpSecret').dataset.copy) openEdit('totpEdit');
}

async function totpEnable() {
  const code = $('#totpCode').value.trim();
  if (!/^\d{6}$/.test(code)) {
    toast('验证码格式不对', '请输入验证器上显示的 6 位数字', 'err');
    $('#totpCode').focus();
    return;
  }
  await withBusy($('#btnTotpEnable'), async () => {
    try {
      const r = await api('/api/auth/totp/enable', {
        method: 'POST', body: JSON.stringify({ code: code }),
      });
      openEdit(null);
      toast('二次认证', r.message || '已启用', 'ok');
      loadAuthConfig();
    } catch (e) {
      toast('启用失败', e.message, 'err');
      $('#totpCode').select();
    }
  });
}

async function totpDisable(e) {
  e.preventDefault();
  const pw = $('#totpOffPw').value;
  if (!pw) { $('#totpOffPw').focus(); return; }
  await withBusy($('#btnTotpOffConfirm'), async () => {
    try {
      const r = await api('/api/auth/totp/disable', {
        method: 'POST', body: JSON.stringify({ password: pw }),
      });
      openEdit(null);
      toast('二次认证', r.message || '已停用', 'ok');
      loadAuthConfig();
    } catch (err) {
      toast('停用失败', err.message, 'err');
      $('#totpOffPw').select();
    }
  });
}

async function postOAuth(users, extra, btn) {
  const body = Object.assign({ client_id: oauthState().client_id || '', client_secret: '', allowed_users: users }, extra);
  return withBusy(btn, async () => {
    try {
      const r = await api('/api/auth/oauth', { method: 'POST', body: JSON.stringify(body) });
      toast('GitHub 登录', r.message || '已保存', 'ok');
      await loadAuthConfig();
      return true;
    } catch (e) {
      toast('保存失败', e.message, 'err');
      return false;
    }
  });
}

async function addOAuthUser(e) {
  e.preventDefault();
  const input = $('#oaUserAdd');
  const name = input.value.trim().replace(/^@/, '').toLowerCase();
  if (!/^[a-z\d](?:[a-z\d]|-(?=[a-z\d])){0,38}$/.test(name)) {
    toast('用户名不对', 'GitHub 用户名只有字母、数字和单个连字符，最长 39 位', 'err');
    input.focus();
    return;
  }
  const users = oauthState().allowed_users || [];
  if (users.indexOf(name) >= 0) { toast('已经在列表里了', name, 'warn'); input.select(); return; }
  if (await postOAuth(users.concat(name), {}, $('#btnOaUserAdd'))) input.value = '';
}

async function removeOAuthUser(btn) {
  const name = btn.dataset.user;
  if (!confirm('不再允许 ' + name + ' 登录？\n\n它已登录的设备不会马上退出，需要的话再点「其它设备 → 全部退出」。')) return;
  await postOAuth((oauthState().allowed_users || []).filter((u) => u !== name), {}, btn);
}

async function saveOAuth(e) {
  e.preventDefault();
  const ok = await postOAuth(oauthState().allowed_users || [], {
    client_id: $('#oaClientId').value.trim(), client_secret: $('#oaSecret').value,
  }, $('#btnSaveOAuth'));
  if (ok) openEdit(null);
}

async function revokeOtherSessions() {
  if (!confirm('让其它所有设备立即退出？\n\n这台设备保持登录。')) return;
  await withBusy($('#btnRevokeOthers'), async () => {
    try {
      const r = await api('/api/auth/sessions/revoke', { method: 'POST' });
      toast('其它设备已退出', r.message || '', 'ok');
      loadAuthConfig();
    } catch (e) { toast('操作失败', e.message, 'err'); }
  });
}

function loadOps() {
  $('#opsRoleExtra').hidden = window.PANEL_ROLE !== 'cn-resolver';
  loadModules();
  loadBackups();
}

async function loadDohInfo() {
  const box = $('#dohBox');
  try {
    const d = await api('/api/doh');
    const endpoints = [
      ['DoH / DoH3', 'dohUrl', d.doh_url],
      ['DoT', 'dotUrl', d.dot_url],
      ['DoQ', 'doqUrl', d.doq_url],
    ].filter((x) => x[2]);
    setHtml(box, html`${endpoints.map(([k, id, url]) => html`<div class="set-row">
        <div class="set-main">
          <div class="set-k">${k}</div>
          <div class="set-v mono" id="${id}">${url}</div>
        </div>
        <button class="sm" data-copy-target="${id}" data-copy-what="${k} 地址">复制</button>
      </div>`)}
      <div class="set-row">
        <div class="set-main">
          <div class="set-k">DoH 私密路径</div>
          <div class="set-v">${d.is_default
            ? html`${stateTag('warn', '未启用')}还在用默认路径，谁都能把这台服务器当公共 DNS`
            : html`${stateTag('ok', '已启用')}轮换后旧地址立刻失效`}</div>
        </div>
        <button class="danger sm" data-op="rotate_doh_path">轮换</button>
      </div>`);
  } catch (e) {
    setHtml(box, errState(e));
  }
}

function copyFrom(el, what) {
  if (!el) return;
  const text = el.dataset.copy || el.textContent;
  const select = () => {
    const r = document.createRange();
    r.selectNodeContents(el);
    const sel = window.getSelection(); sel.removeAllRanges(); sel.addRange(r);
    toast('已选中' + what, '按 Ctrl+C / ⌘C 复制', 'ok');
  };
  const done = '已复制' + (/^[\x21-\x7e]/.test(what) ? ' ' : '') + what;
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(() => toast(done, '', 'ok')).catch(select);
  } else select();
}

const MOD_STATE = {
  ok: { dot: 'ok', text: '正常' },
  warn: { dot: 'warn', text: '需关注' },
  down: { dot: 'err', text: '已中断' },
  unknown: { dot: 'idle', text: '未知' },
};

const IMPL_LABEL = { go: 'Go', shell: 'Shell', external: '外部' };

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

  return html`<div class="mod ${m.state}" title="${m.purpose}">
    <span class="dot ${st.dot}"></span>
    <div class="mod-main">
      <div class="mod-title">
        <b>${m.name}</b>
        ${m.critical ? html`<span class="badge warn">关键</span>` : ''}
        <span class="mod-unit mono dim">${m.unit}</span>
      </div>
    </div>
    <div class="mod-side">
      <span class="mod-state ${m.state}">${m.note || st.text}</span>
      ${facts.length ? html`<span class="mod-facts dim">${facts.join(' · ')}</span>` : ''}
    </div>
  </div>`;
}

async function loadModules() {
  const box = $('#moduleGroups');
  try {
    const d = await apiCached('/api/modules');
    state.sysModules = d;
    renderAlert();
    const impl = d.impl || {};
    setHtml($('#moduleImpl'), html`${d.total} 个：${
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
  }
}

async function loadBackups() {
  try {
    const d = await api('/api/backups');
    const backups = d.backups || [], exports = d.exports || [];
    const size = backups.reduce((n, x) => n + x.size, 0);
    setHtml($('#backupSummary'), backups.length
      ? html`${backups.length} 份，共 ${fmtBytes(size)}，最新 ${ago(backups[0].mtime)}`
      : raw(d.error ? esc(d.error) : '还没有备份'));
    setHtml($('#backupList'), backups.length ? html`<table class="mini"><tbody>${backups.slice(0, 8).map((x) => html`<tr>
        <td class="mono wrap">${x.name}</td><td class="mono dim">${fmtBytes(x.size)}</td>
        <td class="mono dim">${fmtTime(x.mtime)}</td></tr>`)}</tbody></table>` : raw(''));
    setHtml($('#exportSummary'), exports.length
      ? html`导出包 ${exports.length} 个，最新 ${ago(exports[0].mtime)}；迁移包不含任何密钥`
      : raw('迁移包不含任何密钥'));
    const policy = d.policy || {};
    state.syncingSelects = true;
    syncSelect('#bkInterval', policy.interval_hours);
    syncSelect('#bkDaily', policy.keep_daily);
    syncSelect('#bkWeekly', policy.keep_weekly);
    state.syncingSelects = false;
  } catch (e) {
    setHtml($('#backupSummary'), errState(e));
  }
}

function backupPolicyArgs() {
  return {
    interval_hours: Number($('#bkInterval').value),
    keep_daily: Number($('#bkDaily').value),
    keep_weekly: Number($('#bkWeekly').value),
  };
}

async function loadAudit() {
  const body = $('#auditBody');
  try {
    const d = await api('/api/audit?limit=200');
    if (!d.items.length) { setHtml(body, rowSpan(6, EMPTY('没有记录'))); return; }
    setHtml(body, html`${d.items.map((x) => {
      const msg = /^(.*：)?执行(成功|失败)$/.test(x.message || '') ? '' : (x.message || '').slice(0, 200);
      return html`<tr>
      <td class="mono dim">${fmtTime(x.ts)}</td>
      <td title="${x.operation}">${x.label || x.operation}</td>
      <td><span class="badge ${x.ok ? 'ok' : 'err'}">${x.ok ? '成功' : '失败'}</span></td>
      <td class="mono dim audit-args" title="${x.args || ''}">${auditArgs(x.args)}</td>
      <td class="wrap audit-msg">${msg}</td>
      <td>${x.id === null || x.id === undefined ? ''
          : html`<button class="row-del" data-aid="${x.id}" title="删除这条记录" aria-label="删除">${ICON_DEL}</button>`}</td>
    </tr>`;
    })}`);
  } catch (e) {
    setHtml(body, rowSpan(6, errState(e)));
  }
}

function auditArgs(text) {
  if (!text) return '';
  try {
    const args = JSON.parse(text);
    return Object.keys(args).filter((k) => k !== 'list')
      .map((k) => (Array.isArray(args[k]) ? args[k].join(' ') : String(args[k]))).join(' · ');
  } catch (e) {
    return text;
  }
}

function deleteAudit(id, btn) {
  return deleteRecord('delete_audit', { id: Number(id) }, {
    confirm: '删除这条审计记录？', btn, done: '已删除', after: loadAudit,
  });
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
  rotate_doh_path: '换一个新的 DoH 路径，旧地址立刻失效，所有客户端都要改成新地址。'
    + '\n会重启 mosproxy 并自动验证，失败会自动退回。',
  prune_backups: '按保留份数删除多出来的旧备份，删了找不回来。',
  drop_stale_logs: '删除不再属于任何模块、14 天没人写过的日志文件。',
  restart_mosproxy: 'DoH / DoT 入口会断几秒，这期间所有客户端都解析不了。',
  restart_unbound: '递归会断几秒并清空缓存，之后一段时间解析会变慢。',
  flush_cache: '清掉的名字下次都要重新递归，短时间会变慢。',
  cert_renew: '证书剩不到 3 天或 IP 对不上时才真的续签，否则什么也不做。'
    + '\n续签后面板会重启，这个页面会断开几秒。',
  clear_domains: '删除 7 天没出现过的域名，以及 7 天前的请求记录，删了找不回来。',
  clear_domains_all: '清空所有域名统计和请求记录，面板上的历史数字全部归零，删了找不回来。',
  purge_legacy: '删除统计起点之前的所有请求记录和域名，删了找不回来。',
  set_arch_epoch: '「近 24 小时」的数字会从现在重新累计，旧数据不删。',
  vacuum_logs: '删除 7 天前的全部系统日志，包括其它服务的，删了找不回来。',
  clear_audit: '清空后就查不到以前做过哪些操作了。',
};

const _runningOps = new Set();

function markOpBusy(op, busy) {
  $$('button[data-op="' + op + '"]').forEach((b) => {
    b.disabled = busy;
    b.classList.toggle('busy', busy);
  });
}

async function runOp(op, label, args, isDangerous) {
  args = args || {};
  if (_runningOps.has(op)) { toast('「' + label + '」正在执行', '等它结束再试', 'warn'); return; }
  if (isDangerous) {
    const note = CONFIRM_NOTE[op] || '这是危险操作，可能中断服务或覆盖数据。';
    if (!confirm('确认执行「' + label + '」？\n\n' + note)) return;
    args.confirm = true;
  }
  _runningOps.add(op);
  markOpBusy(op, true);
  toast('执行中：' + label, '');
  try {
    const d = await api('/api/action/' + op, { method: 'POST', body: JSON.stringify(args) });
    if (d.ok) toast(label + '：完成', (d.message || d.stdout || '').slice(0, 800), 'ok');
    else toast(label + '：失败', (d.message || d.stderr || '').slice(0, 800), 'err');

    invalidateCache();
    if (['cert_check', 'cert_renew'].indexOf(op) >= 0) loadCert();
    if (['restart_mosproxy', 'restart_unbound'].indexOf(op) >= 0) setTimeout(loadModules, 1500);
    if (['backup', 'export', 'prune_backups', 'set_backup_policy'].indexOf(op) >= 0) loadBackups();
    if (['set_cache_ttl', 'set_min_ttl', 'flush_cache'].indexOf(op) >= 0 && state.page === 'settings') loadCacheInfo();
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
        _runningOps.delete(op);
        markOpBusy(op, false);
        return runOp(op, label, args, false);
      }
      return;
    }
    toast(label + '：出错', e.message, 'err');
  } finally {
    _runningOps.delete(op);
    markOpBusy(op, false);
  }
}

function jumpTo(page, tab, metric) {
  switchPage(page);
  if (tab) {
    const btn = $$('#page-' + page + ' .main-tabs button').find((b) =>
      Object.values(b.dataset).indexOf(tab) >= 0);
    if (btn && !btn.classList.contains('active')) btn.click();
  }
  if (metric) {
    const m = $('#domTabs button[data-metric="' + metric + '"]');
    if (m) m.click();
  }
}

function bindEvents() {
  $('#nav').addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-page]');
    if (btn) switchPage(btn.dataset.page);
  });

  document.addEventListener('click', (e) => {
    const btn = e.target.closest('[data-page-jump]');
    if (btn) { e.preventDefault(); jumpTo(btn.dataset.pageJump, btn.dataset.tab, btn.dataset.metric); }
  });

  document.addEventListener('click', (e) => {
    const rm = e.target.closest('button[data-list-remove]');
    if (rm) { listRemove(rm); return; }
    const route = e.target.closest('button[data-route-add], button[data-route-remove]');
    if (route) { routeChange(route); return; }
    const flush = e.target.closest('button[data-flush]');
    if (flush) {
      runOp('flush_cache', '清缓存 ' + flush.dataset.flush, { domain: flush.dataset.flush, confirm: true }, false);
    }
  });
  document.addEventListener('submit', (e) => {
    const form = e.target.closest('form[data-list-form], #aclForm');
    if (!form) return;
    e.preventDefault();
    listAdd(form);
  });
  $('#testForm').addEventListener('submit', (e) => { e.preventDefault(); runDnsTest(); });
  $('#flushForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const domain = $('#flushDomain').value.trim();
    if (!confirm('清理' + (domain ? '「' + domain + '」及子域' : '全部') + '的缓存？\n\n'
      + CONFIRM_NOTE.flush_cache)) return;
    const args = { confirm: true };
    if (domain) args.domain = domain;
    await runOp('flush_cache', '清缓存', args, false);
    $('#flushDomain').value = '';
  });
  $('#cacheTtl').addEventListener('change', (e) => applySetting(e.target, 'set_cache_ttl', '过期后继续使用',
    () => ({ ttl: Number(e.target.value) }), 'Unbound 马上生效，mosproxy 要重启后生效。'));
  $('#minTtl').addEventListener('change', (e) => applySetting(e.target, 'set_min_ttl', '最短缓存',
    () => ({ ttl: Number(e.target.value) }), '调高会让 CDN 换节点变慢。'));
  ['#bkInterval', '#bkDaily', '#bkWeekly'].forEach((id) => $(id).addEventListener('change', (e) =>
    applySetting(e.target, 'set_backup_policy', '备份策略', backupPolicyArgs, '')));
  $('#btnReloadModules').addEventListener('click', () => { invalidateCache(); loadModules(); });
  $('#btnReloadAudit').addEventListener('click', () => { invalidateCache(); loadAudit(); });
  $('#btnReloadCollected').addEventListener('click', () => { invalidateCache(); loadCollected(); });
  bindCollected();

  const bindTabs = (tabsSel, attr, onSwitch) => {
    const tabs = $(tabsSel);
    if (!tabs) return;
    const show = (btn) => {
      $$(tabsSel + ' button').forEach((b) => b.classList.toggle('active', b === btn));
      const name = btn.getAttribute(attr);
      $$('.tab-panel', tabs.closest('.page')).forEach((p) =>
        p.classList.toggle('active', p.id === attr.replace('data-', '') + '-' + name));
      return name;
    };
    let saved = null;
    try { saved = localStorage.getItem('dns-stack-tab' + tabsSel); } catch (e) {  }
    const restore = saved && tabs.querySelector('button[' + attr + '="' + saved + '"]');
    if (restore) show(restore);
    tabs.addEventListener('click', (e) => {
      const btn = e.target.closest('button[' + attr + ']');
      if (!btn) return;
      const name = show(btn);
      try { localStorage.setItem('dns-stack-tab' + tabsSel, name); } catch (err) {  }
      if (onSwitch) onSwitch(name);
    });
  };
  bindTabs('#queryTabs', 'data-qtab', (name) => {
    if (name === 'live') initLivePage();
    else { if (state.liveOn) stopLive(); loadDomains(1); }
  });
  bindTabs('#toolTabs', 'data-ttab', openToolTab);

  $('#btnCdnHit').addEventListener('click', (e) => withBusy(e.currentTarget, () => loadCdnHit('refresh')));
  $('#btnCdnFresh').addEventListener('click', (e) => withBusy(e.currentTarget, () => loadCdnHit('fresh')));

  $('#btnAclApply').addEventListener('click', () => accessAction('acl_apply', '已下发访问控制', {}));
  $('#btnAclDisable').addEventListener('click', () => {
    if (!confirm('停用后所有人都能使用这台 DNS。\n\n确认停用？')) return;
    accessAction('acl_disable', '已停用访问控制', {}, true);
  });
  bindTabs('#settingTabs', 'data-stab', (name) => loadSettingTab(name));

  $('#btnIpLookup').addEventListener('click', loadIpLookup);
  $('#ipQuery').addEventListener('keydown', (e) => { if (e.key === 'Enter') loadIpLookup(); });
  $('#tsSpan').addEventListener('change', loadTimeseries);

  $('#btnSearch').addEventListener('click', () => loadQueries(1));
  $('#fDomain').addEventListener('keydown', (e) => { if (e.key === 'Enter') loadQueries(1); });
  $('#btnReset').addEventListener('click', () => {
    ['#fDomain', '#fQtype', '#fRoute', '#fRcode'].forEach((s) => { $(s).value = ''; });
    $('#fSince').value = '0';
    syncFilterCount();
    loadQueries(1);
  });
  EXTRA_FILTERS.forEach((s) => {
    const el = $(s);
    if (el) el.addEventListener('change', () => { syncFilterCount(); loadQueries(1); });
  });
  const more = $('#btnFilterMore');
  if (more) more.addEventListener('click', () => setFilterMore($('#filterMore').hidden));
  syncFilterCount(true);
  $('#btnPrev').addEventListener('click', () => {
    if (state.queryPage > 1) loadQueries(state.queryPage - 1);
  });
  $('#btnNext').addEventListener('click', () => {
    if (state.queryPage < state.queryPages) loadQueries(state.queryPage + 1);
  });
  $('#btnLiveToggle').addEventListener('click', () => {
    if (state.liveOn) { stopLive(true); return; }
    if (state.queryPage !== 1) loadQueries(1);
    startLive();
  });
  const bindExport = (id, dataset, format) => {
    const el = $(id);
    if (el) el.addEventListener('click', () => downloadExport(dataset, format));
  };
  bindExport('#btnExportQueriesJson', 'queries', 'json');
  bindExport('#btnExportQueriesCsv', 'queries', 'csv');
  bindExport('#btnExportDomainsJson', 'domains', 'json');
  bindExport('#btnExportDomainsCsv', 'domains', 'csv');
  document.addEventListener('click', (e) => {
    const inMenu = e.target.closest('details.menu');
    $$('details.menu[open]').forEach((m) => { if (m !== inMenu || e.target.closest('.menu-list button')) m.open = false; });
  });
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

    const cp = e.target.closest('button[data-copy-target]');
    if (cp) { copyFrom($('#' + cp.dataset.copyTarget), cp.dataset.copyWhat || ''); return; }

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
    loadDomains(1);
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

  document.addEventListener('click', (e) => {
    const ex = e.target.closest('button[data-example]');
    if (!ex) return;
    $('#testDomain').value = ex.dataset.example;
    runDnsTest();
  });

  $('#btnLogRefresh').addEventListener('click', loadLogs);
  $('#btnLogFollow').addEventListener('click', () => {
    state.logFollow ? stopLogFollow() : startLogFollow();
  });
  $('#btnLogClear').addEventListener('click', () => { state.logLines = []; renderLogs(); });
  $('#logSearch').addEventListener('input', debounce(renderLogs, 120));
  $('#logUnit').addEventListener('change', () => {
    try { localStorage.setItem('dns-stack-log-unit', $('#logUnit').value); } catch (e) {  }
    state.logLines = [];
    if (state.logFollow) { stopLogFollow(); startLogFollow(); }
    loadLogs();
  });
  $('#logPriority').addEventListener('change', () => {
    if (state.logFollow) { stopLogFollow(); startLogFollow(); }
    loadLogs();
  });

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
  ['#fDomain', '#fQtype', '#fRoute', '#fRcode', '#domSearch', '#domRoute', '#logSearch']
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
    let saved = null;
    try { saved = localStorage.getItem('dns-stack-log-unit'); } catch (e) {  }
    if (saved && d.log_units.indexOf(saved) >= 0) sel.value = saved;
  }
}

(async function init() {
  initTheme();
  initSidebarFold();
  initSession();
  resetFilterControls();
  bindEvents();
  await Promise.all([loadBootstrap(), loadOpsMeta()]);
  initSelects();
  const hash = location.hash.replace('#', '');
  switchPage(PAGE_TITLES[hash] ? hash : 'overview');
})();

const SELECT_SHEET_BREAKPOINT = 860;
const SELECT_SHEET_TOUCH_MAX = 1180;

function preferSheet() {
  if (window.innerWidth <= SELECT_SHEET_BREAKPOINT) return true;
  if (window.innerWidth > SELECT_SHEET_TOUCH_MAX) return false;
  return window.matchMedia('(pointer: coarse)').matches;
}

function selectOptions(sel) {
  return Array.from(sel.options).map((o) => ({
    value: o.value, label: o.textContent.trim(),
    disabled: o.disabled, selected: o.selected,
  }));
}

function closeAllSelects(except) {
  $$('.xsel.open').forEach((el) => {
    if (el === except) return;
    el.classList.remove('open');
    const list = el._list;
    if (list) list.remove();
    el._list = null;
    const mask = el._mask;
    if (mask) mask.remove();
    el._mask = null;
    const btn = el.querySelector('.xsel-btn');
    if (btn) btn.setAttribute('aria-expanded', 'false');
  });
}

function renderSelectLabel(wrap) {
  const sel = wrap._select;
  const btn = wrap.querySelector('.xsel-btn');
  const picked = sel.options[sel.selectedIndex];
  btn.querySelector('.xsel-text').textContent = picked ? picked.textContent.trim() : '';
  btn.disabled = sel.disabled;
  wrap.classList.toggle('disabled', sel.disabled);
}

function commitSelect(wrap, value) {
  const sel = wrap._select;
  if (sel.value !== value) {
    sel.value = value;
    sel.dispatchEvent(new Event('input', { bubbles: true }));
    sel.dispatchEvent(new Event('change', { bubbles: true }));
  }
  renderSelectLabel(wrap);
  closeAllSelects();
}

function moveSelectCursor(list, delta) {
  const items = Array.from(list.querySelectorAll('.xsel-opt:not([aria-disabled="true"])'));
  if (!items.length) return;
  const current = list.querySelector('.xsel-opt.cursor');
  let index = current ? items.indexOf(current) : -1;
  index = (index + delta + items.length) % items.length;
  items.forEach((el) => el.classList.remove('cursor'));
  const next = items[index];
  next.classList.add('cursor');
  next.scrollIntoView({ block: 'nearest' });
}

function openSelect(wrap) {
  const sel = wrap._select;
  if (sel.disabled) return;
  closeAllSelects(wrap);
  const sheet = preferSheet();
  const options = selectOptions(sel);

  const list = document.createElement('div');
  list.className = 'xsel-list' + (sheet ? ' sheet' : '');
  list.setAttribute('role', 'listbox');
  if (sheet && wrap._label) {
    const head = document.createElement('div');
    head.className = 'xsel-sheet-head';
    head.textContent = wrap._label;
    list.appendChild(head);
  }
  const body = document.createElement('div');
  body.className = 'xsel-scroll';
  options.forEach((opt) => {
    const item = document.createElement('button');
    item.type = 'button';
    item.className = 'xsel-opt' + (opt.selected ? ' selected' : '');
    item.setAttribute('role', 'option');
    item.setAttribute('aria-selected', String(opt.selected));
    if (opt.disabled) item.setAttribute('aria-disabled', 'true');
    item.textContent = opt.label;
    if (opt.selected) item.classList.add('cursor');
    if (!opt.disabled) {
      item.addEventListener('click', (e) => {
        e.stopPropagation();
        commitSelect(wrap, opt.value);
      });
    }
    body.appendChild(item);
  });
  list.appendChild(body);

  if (sheet) {
    const mask = document.createElement('div');
    mask.className = 'xsel-mask';
    mask.addEventListener('click', () => closeAllSelects());
    document.body.appendChild(mask);
    document.body.appendChild(list);
    wrap._mask = mask;
    requestAnimationFrame(() => { mask.classList.add('in'); list.classList.add('in'); });
  } else {
    wrap.appendChild(list);
  }
  wrap._list = list;
  wrap.classList.add('open');
  wrap.querySelector('.xsel-btn').setAttribute('aria-expanded', 'true');
  const active = list.querySelector('.xsel-opt.cursor');
  if (active) active.scrollIntoView({ block: 'nearest' });
}

function enhanceSelect(sel) {
  if (sel._enhanced) return;
  sel._enhanced = true;

  const wrap = document.createElement('div');
  wrap.className = 'xsel' + (sel.classList.contains('sel-sm') ? ' sm' : '');
  wrap._select = sel;
  wrap._label = sel.getAttribute('title') || sel.getAttribute('aria-label') || '';

  const btn = document.createElement('button');
  btn.type = 'button';
  btn.className = 'xsel-btn';
  btn.setAttribute('aria-haspopup', 'listbox');
  btn.setAttribute('aria-expanded', 'false');
  if (wrap._label) btn.setAttribute('aria-label', wrap._label);
  btn.innerHTML = '<span class="xsel-text"></span><span class="xsel-caret" aria-hidden="true"></span>';

  sel.parentNode.insertBefore(wrap, sel);
  wrap.appendChild(btn);
  wrap.appendChild(sel);
  sel.classList.add('xsel-native');
  sel.setAttribute('tabindex', '-1');

  btn.addEventListener('click', (e) => {
    e.stopPropagation();
    if (wrap.classList.contains('open')) { closeAllSelects(); return; }
    openSelect(wrap);
  });
  btn.addEventListener('keydown', (e) => {
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      if (!wrap.classList.contains('open')) { openSelect(wrap); return; }
      moveSelectCursor(wrap._list, e.key === 'ArrowDown' ? 1 : -1);
      return;
    }
    if (e.key === 'Enter' || e.key === ' ') {
      if (!wrap.classList.contains('open')) return;
      e.preventDefault();
      const cursor = wrap._list.querySelector('.xsel-opt.cursor');
      if (cursor) cursor.click();
      return;
    }
    if (e.key === 'Escape' && wrap.classList.contains('open')) {
      e.preventDefault();
      closeAllSelects();
    }
  });
  sel.addEventListener('change', () => renderSelectLabel(wrap));
  renderSelectLabel(wrap);
}

function refreshEnhancedSelects(root) {
  $$('select', root || document).forEach((sel) => {
    if (sel._enhanced) { renderSelectLabel(sel.parentNode); return; }
    enhanceSelect(sel);
  });
}

function initSelects() {
  refreshEnhancedSelects();
  document.addEventListener('click', () => closeAllSelects());
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeAllSelects();
  });
  window.addEventListener('resize', () => closeAllSelects());
  const observer = new MutationObserver((records) => {
    let touched = false;
    records.forEach((rec) => {
      if (rec.target && rec.target.tagName === 'SELECT') { touched = true; return; }
      rec.addedNodes.forEach((node) => {
        if (node.nodeType !== 1) return;
        if (node.tagName === 'SELECT' || node.querySelector('select')) touched = true;
      });
    });
    if (touched) refreshEnhancedSelects();
  });
  observer.observe(document.body, { childList: true, subtree: true });
}
