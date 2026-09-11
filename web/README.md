# DNS Stack 管理面板 · 前端

一份**自包含的静态站点**。没有构建步骤、没有依赖、没有模板语法——四个文件加一个
假后端，双击命令行就能跑起来。

```
web/
├── index.html        主面板（纯 HTML）
├── login.html        登录页（纯 HTML）
├── assets/
│   ├── panel.css
│   └── panel.js      无框架、无打包，原生 ES2020
├── mock-api.js       假后端：拦截 fetch / EventSource，数据全部虚构
├── devserver/        开发服务器（Go），返回 HTML 时动态注入 mock-api.js
└── README.md
```

## 本地开发

```bash
go run ./devserver --root .                     # http://127.0.0.1:8791
go run ./devserver --root . --addr :9000        # 换端口
```

不需要任何后端。`mock-api.js` 会接管所有请求，界面上的每一块都能看到。

改完文件直接刷新——开发服务器一律 `no-store`，不存在"改了没生效"。

> `mock-api.js` **只在开发服务器里被注入**，`index.html` 本身对它零引用。
> 这条要一直成立，验证方式：`grep -c mock-api index.html` 必须是 `0`。
> 假后端一旦被带进生产，面板会安静地显示一整屏虚构数据——解析看着全都正常，
> 只有数字是编的。

## 接后端

前端只依赖 HTTP JSON 接口，把它挂在任何能提供这些接口的服务后面即可：

默认情况下前端与后端同源。若把 `web/` 静态文件单独放在另一台托管机上，编辑
`assets/runtime-config.js` 中的 `apiBase`，例如 `https://dns.example.com`，并在后端
`/etc/dns-stack/config.env` 配置同一个精确来源：

```dotenv
PANEL_CORS_ORIGINS=https://panel.example.com
PANEL_COOKIE_SAMESITE=none
```

跨域模式必须使用 HTTPS；后端拒绝 `*` 通配来源，浏览器请求会携带 HttpOnly 会话
Cookie，SSE 日志流也会带凭据。若只在本机通过 SSH 隧道访问，保持 `apiBase` 与
`PANEL_CORS_ORIGINS` 为空即可。

| 路径 | 说明 |
|---|---|
| `GET /api/bootstrap` | **启动必需**。见下方契约 |
| `GET /api/overview` | 概览指标 |
| `GET /api/queries` `GET /api/queries/stream` | 实时请求（后者是 SSE） |
| `GET /api/domains` `GET /api/domain/{name}` | 域名统计与详情 |
| `GET /api/timeseries` | 趋势图数据 |
| `GET /api/my-location` | 访问者位置与 CDN 调度探测 |
| `POST /api/dns-test` | 解析对比测试 |
| `GET /api/logs` `GET /api/logs/stream` | 日志 |
| `GET /api/modules` | 模块清单与整机结论（分组、状态、上次/下次运行） |
| `GET /api/services` `POST /api/action/{op}` | 服务状态与运维操作 |
| `POST /api/login` `POST /api/logout` | 认证 |

### `/api/bootstrap` 契约

页面骨架所需的一次性上下文。**必须在首屏渲染前拿到**——`panel.js` 有两处直接读
`window.PANEL_ROLE` 做分支，拿不到值会按"不是这个角色"走，表现为整块功能凭空消失，
而且不报错。

```jsonc
// 已登录
{
  "auth_enabled": true,          // false 时隐藏所有 .auth-only 元素（退出按钮）
  "totp_enabled": false,         // 登录页据此决定渲不渲染验证码框
  "role": "cn-resolver",         // 或 "global-builder"
  "role_name": "国内 DNS 服务器",
  "log_units": ["mosproxy", "unbound", "..."]   // 日志页的服务下拉
}

// 未登录（这个端点必须公开——登录页也要读它）
{ "auth_enabled": true, "totp_enabled": false }
```

未登录时**刻意只回两个开关**：角色与服务名对未登录者是多余信息，白送出去没有
任何好处。

### 认证约定

所有接口在会话失效时返回 `401` + `{"need_login": true}`。`panel.js` 的 `api()`
统一捕获这个组合并跳转 `/login`，业务代码不必各自处理。

## 改动时的注意事项

**归属字段是多库合并的结果**，可能整体缺失。`geo` 对象里 `available: false` 表示
"库没装"，而 `available: true` + `label: null` 表示"库里没这条"——两者的处理方式
完全不同，不要合并成一个"未知"。`mock-api.js` 里两种形状都有样例。

**别把「取不到」和「值是 0」混为一谈**。`subnet_queries: null` 是"unbound 没开
扩展统计"，`0` 才是"确实一条都没有"。混起来会让一台工作正常的机器常驻红色告警。

**IP 一律用文档专用段**。示例、注释、mock 数据里出现的地址必须取自
RFC 5737（`192.0.2.0/24`、`198.51.100.0/24`、`203.0.113.0/24`）与 RFC 2606
（`example.com` 等）。仓库里有一道扫描护栏盯着这件事，真实地址提交不进去。

**模块清单只有一处**：`internal/stack/stack.go`。面板的监视列表、helper 的单元
白名单、`dns-stack status` 三者都从它派生，新增模块只改那一处。前端不要再自己
维护单元名数组——`mock-api.js` 里那份是给假后端造数据用的，不参与真实渲染。
