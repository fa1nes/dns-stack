<template>
  <figure class="arch" aria-label="dns-stack 架构：设备经国内节点的四层处理，境外查询经隧道从香港出网">
    <div class="arch-client">设备 · DoH / DoH3 / DoT / DoQ</div>
    <div class="arch-arrow">↓</div>

    <section class="arch-node">
      <header>国内节点 <code>cn-resolver</code></header>
      <div class="arch-layer">
        <span class="arch-tag">入口层</span>
        <div><b>mosproxy</b>：加密入口 · 缓存 · 黑名单 · 访问控制 · 限流</div>
      </div>
      <div class="arch-layer">
        <span class="arch-tag">递归层</span>
        <div>
          <b>Unbound :5335</b> 从根区完整递归，每一跳按权威 IP 分流
          <div class="arch-split">
            <div class="arch-path cn">权威在大陆<br><small>直连出网</small></div>
            <div class="arch-path tunnel">权威在境外<br><small>打标 → WireGuard 隧道</small></div>
          </div>
        </div>
      </div>
      <div class="arch-layer">
        <span class="arch-tag">数据层</span>
        <div>分流数据流水线：大陆网段 · 国内权威 · ECS 白名单 · 分片表</div>
      </div>
      <div class="arch-layer">
        <span class="arch-tag">运维层</span>
        <div>采集器 · 面板 · 特权助手 · 看门狗 · 例行维护</div>
      </div>
    </section>

    <div class="arch-link">
      <span>⇅</span>
      <code>wg0</code> 10.100.0.2 ⇄ 10.100.0.3
      <small>境外权威的查询 · mosproxy 的降级上游</small>
    </div>

    <section class="arch-node offshore">
      <header>香港节点 <code>offshore</code></header>
      <div class="arch-layer">
        <span class="arch-tag">出口</span>
        <div>WireGuard 出口 + <b>Unbound :5335</b>（mosproxy 的降级上游）</div>
      </div>
    </section>
  </figure>
</template>

<style scoped>
.arch {
  margin: 24px 0;
  display: flex;
  flex-direction: column;
  align-items: stretch;
  gap: 8px;
  font-size: 14px;
  line-height: 1.6;
}
.arch-client,
.arch-link {
  text-align: center;
  color: var(--vp-c-text-2);
}
.arch-client {
  align-self: center;
  padding: 6px 16px;
  border: 1px solid var(--vp-c-divider);
  border-radius: 999px;
  background: var(--vp-c-bg-soft);
  color: var(--vp-c-text-1);
}
.arch-arrow {
  text-align: center;
  color: var(--vp-c-text-3);
}
.arch-node {
  border: 1px solid var(--vp-c-brand-soft);
  border-radius: 12px;
  overflow: hidden;
  background: var(--vp-c-bg-soft);
}
.arch-node.offshore {
  border-color: var(--vp-c-divider);
}
.arch-node header {
  padding: 8px 16px;
  font-weight: 600;
  background: var(--vp-c-brand-soft);
  color: var(--vp-c-brand-1);
}
.arch-node.offshore header {
  background: var(--vp-c-default-soft);
  color: var(--vp-c-text-1);
}
.arch-layer {
  display: grid;
  grid-template-columns: 4.5em 1fr;
  gap: 12px;
  padding: 10px 16px;
  border-top: 1px solid var(--vp-c-divider);
}
.arch-tag {
  font-weight: 600;
  color: var(--vp-c-text-2);
}
.arch-split {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 8px;
  margin-top: 8px;
}
.arch-path {
  padding: 6px 10px;
  border-radius: 8px;
  text-align: center;
  border: 1px solid var(--vp-c-divider);
  background: var(--vp-c-bg);
}
.arch-path small {
  color: var(--vp-c-text-2);
}
.arch-path.cn {
  border-color: var(--vp-c-green-2);
}
.arch-path.tunnel {
  border-color: var(--vp-c-indigo-2);
}
.arch-link small {
  display: block;
  color: var(--vp-c-text-3);
}
@media (max-width: 480px) {
  .arch-layer {
    grid-template-columns: 1fr;
    gap: 2px;
  }
}
</style>
