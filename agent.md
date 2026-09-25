# DNS Stack 前后端审计台账

## 目标

核实 Go 后端、面板前端、mock、部署模块目录和项目手册的一致性；移除已证实的旧架构残留，降低重复事实源，补足关键边界测试。保留 DNS 分类、ECS、角色权限和生产操作的现行契约。

## 审计计划

- [x] 盘点代码树、服务入口、前端 API 调用、mock 和现有测试。
- [x] 执行 Go 测试、`go vet` 与前端 JavaScript 语法基线。
- [x] 对比实际角色、服务注册表和历史手册，定位可验证的旧实现残留。
- [x] 清理面板对旧 `classifier.db` 的隐式回退。
- [x] 让备份按现行模块与角色选择 systemd 文件；停止导出已退役 classifier/publish 状态。
- [x] 移除 `db-migrate` 在 `offshore` 角色下调用旧 classifier/verify 服务和 CLI 的路径。
- [x] 移除迁移资源清单中已不存在的 `rules/`，避免迁移在打包前必然失败。
- [x] 修正 offshore CLI 日志默认目标、角色契约文档与过时的服务测试夹具。
- [x] 精简项目记忆，分离长期事实与本轮任务进度。
- [x] 运行全部变更后测试、vet、格式/差异检查，并复核变更范围。

## 已确认发现

1. `internal/panel` 在配置的 `collector.db` 缺失时改读 `classifier.db`。这是已退役数据模型，可能让面板静默读取错误数据库。
2. `internal/backup` 仍包含 `dns-stack-classify`、`dns-stack-verify`、`dns-stack-reference-data`、`dns-stack-publish` unit，以及 classifier 数据库和旧发布目录；备份单元清单还独立于 `internal/stack`。
3. `cmd/dns-stack/dbmigratecmd.go` 对任何非 CN 角色都按旧 classifier 架构停服务并执行 `classify status`。现行角色只有 `cn-resolver` 和 `offshore`。
4. `internal/opsctl.shippedItems` 还要求迁移传输已删除的 `rules/` 目录，导致迁移必然提前失败。
5. `internal/opsctl.Logs` 在 offshore 默认查找已退役的 `dns-stack-classify`；面板 mock README 仍称另一角色为 `global-builder`。
6. Go 基线测试与 vet 均通过，但 `internal/backup`、`internal/opsctl` 原先没有测试；已为这些新边界补测试。
7. `memory.md` 原有约 58 KB，代码地图包含不存在的包和不再适用的绝对化旧约束；本轮已压缩并按现状重写。

## 改动范围

- 后端：面板数据库路径、备份内容、数据库迁移角色门禁和 CLI 日志默认模块。
- 测试：面板旧库回退、角色化备份内容、迁移命令角色拒绝、当前角色日志默认值。
- 文档：`memory.md` 改为短版现状手册；本文件记录任务状态；`web/README.md` 使用现行 `offshore` 角色名。

## 当前验证

- 基线和变更后：Go 1.26 `go test -count=1 ./...`、`go vet ./...` 均通过。
- 变更后：`panel.js`、`mock-api.js`、`runtime-config.js`、`layout-scan.js` 均通过 `node --check`；`gofmt -l` 无输出；`git diff --check` 通过。
- 仅完成本机代码验证；未执行 Debian/systemd/Unbound/生产 SQLite/真实 CDN 与 ECS 验证。

## 后续审计提示

- 逐项确认 API 及操作按钮的服务端实现、helper 白名单、角色门禁和 mock 响应保持一致；不要仅凭字符串搜索删除功能。
- 对历史迁移代码保留与否，依据实际支持的源版本和可重复测试判断；不要为删代码破坏有效的迁移/回滚路径。
- 任何真实服务、数据库、WireGuard、防火墙或远程节点验证均另行报告，不以本机测试冒充。

## 优化回合 2

### 目标

提高面板数据可信度和 SQLite 查询的资源效率；实际走查前后端功能，确认 mock 不会进入生产；评估不必要功能时以没有有效消费者/后端的证据为准。

### 状态

- [x] 检查当前浏览器和已打开窗口；本次会话未发现可用窗口。
- [x] 跑静态资源基准，确认资源缓存查找约 11 ns、0 B/0 alloc；不动已有热路径。
- [x] 定位会吞掉 SQLite 错误并返回空值/零值的面板 API。
- [x] 请求内 SQLite 查询传入 HTTP context；取消或读取错误不再包装成有效的空数据。
- [x] 增加 domain summary/timeseries 固定样本校验、取消请求、审计错误、双向 API 路由和生产 mock 隔离测试。
- [ ] 用浏览器进行页面/布局交互走查。阻塞：CUA 没有可用窗口；Playwright 返回其 Chrome profile 被另一实例占用。
- [x] 全量 Go 测试、vet、前端语法、gofmt 与差异检查；本地 HTTP 确认开发服务器注入 mock。
- [x] 核对 `.github/workflows/build.yml`：推送 main 会由 Actions 编译并发布 `binaries-latest`；安装脚本检查明确禁止生产编译 Go。
- [ ] 主人审阅后再推送 GitHub、等 Actions 完成，再按本文件后续部署步骤同步生产。

### 已处理的数据准确性风险

- `/api/audit` 之前在数据库/表缺失时返回 HTTP 200 空数组；现在区分数据库查询失败与真实空表。
- overview、查询、域名、趋势、汇总和导出查询现在传递请求 context、检查 Scan/Rows 错误，并用 503 表达不完整或失败结果。
- 本地 mock 页面 HTTP 200 且含有开发 mock 注入；生产嵌入页测试断言不包含 mock 或布局扫描脚本。
- 固定 SQLite 样本核对了近 24h/1h 域名计数、失败数、出口计数和趋势桶计数。
- CUA 没有打开窗口；Playwright 返回其 Chrome profile 正被其他实例使用。未抢占或关闭用户浏览器，页面逐项交互/布局未验证。

### 当前交付状态

- 本地工作区包含上轮旧架构清理和本轮数据准确性/请求效率改动；没有创建 commit、没有 push、没有操作生产。
- `memory.md` 是个人忽略文件，不纳入 Git；`agent.md` 与测试文件可随代码一起审阅。
- 生产同步必须等 Actions 在 push 后生成 `binaries-latest`，再从 Release 安装；生产节点不编译 Go。

### GitHub 与生产发布准备

- `.github/workflows/build.yml` 对 main 推送运行 gofmt/vet/test/规模门禁，交叉构建 linux/amd64、linux/arm64 与 windows/amd64，并更新 rolling `binaries-latest` Release。
- `install.sh` 从 Release 获取校验过 SHA256 的二进制；不在生产机编译 Go。
- 当前代码与上轮审计修复仍在工作区，尚未 commit/push；生产服务、二进制、数据库和配置均未改动。
- 发布顺序：主人审阅本地差异并最终确认 → commit/push main → 等 GitHub Actions 全部通过并确认 Release 资产 → 再确认生产目标与部署窗口 → 备份/核验远端当前二进制 → 通过 `binaries-latest` 更新二进制并按现有安装/回滚流程验证。
