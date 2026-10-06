import { defineConfig } from 'vitepress'

const base = process.env.SITE_BASE || '/'

export default defineConfig({
  lang: 'zh-CN',
  title: 'dns-stack 文档',
  description: '两台机器上的抗污染递归解析：本地完整递归 + 递归出口按权威位置分流',
  base,
  cleanUrls: true,
  lastUpdated: true,
  head: [
    ['link', { rel: 'icon', type: 'image/svg+xml', href: `${base}favicon.svg` }],
    ['meta', { name: 'theme-color', content: '#3451b2' }]
  ],
  markdown: { lineNumbers: false },
  themeConfig: {
    siteTitle: 'dns-stack 文档',
    logo: '/favicon.svg',
    nav: [
      { text: '技术详解', link: '/', activeMatch: '^/$' },
      { text: '使用', link: '/guide/quick-start', activeMatch: '^/guide/' },
      { text: '运维', link: '/ops/nodes', activeMatch: '^/ops/' },
      { text: '参考', link: '/reference/cli', activeMatch: '^/reference/' }
    ],
    sidebar: [
      {
        text: '系统介绍',
        items: [
          { text: '技术详解', link: '/' },
          { text: '系统概述', link: '/intro/overview' },
          { text: '设计取舍', link: '/intro/tradeoffs' }
        ]
      },
      {
        text: '上手',
        collapsed: false,
        items: [
          { text: '快速开始', link: '/guide/quick-start' },
          { text: '客户端接入', link: '/guide/clients' },
          { text: '管理面板', link: '/guide/panel' }
        ]
      },
      {
        text: '递归管理',
        collapsed: false,
        items: [
          { text: '加密入口', link: '/guide/entry' },
          { text: '出口分流', link: '/guide/routing' },
          { text: 'ECS 就近调度', link: '/guide/ecs' },
          { text: '缓存', link: '/guide/cache' },
          { text: '域名黑名单', link: '/guide/blocklist' },
          { text: '访问控制', link: '/guide/acl' },
          { text: '查询日志与统计', link: '/guide/query-log' }
        ]
      },
      {
        text: '运维与可靠性',
        collapsed: true,
        items: [
          { text: '两台节点', link: '/ops/nodes' },
          { text: '分流数据流水线', link: '/ops/pipeline' },
          { text: '健康检查与告警', link: '/ops/health' },
          { text: '证书', link: '/ops/certificates' },
          { text: '备份与迁移', link: '/ops/backup' },
          { text: '故障排查', link: '/ops/troubleshooting' }
        ]
      },
      {
        text: '参考',
        collapsed: true,
        items: [
          { text: '命令参考', link: '/reference/cli' },
          { text: '配置项', link: '/reference/config' },
          { text: '故障模式', link: '/reference/failure-modes' }
        ]
      }
    ],
    socialLinks: [{ icon: 'github', link: 'https://github.com/fa1nes/dns-stack' }],
    outline: { level: [2, 3], label: '页面导航' },
    docFooter: { prev: '上一页', next: '下一页' },
    lastUpdated: { text: '最后更新' },
    returnToTopLabel: '回到顶部',
    sidebarMenuLabel: '菜单',
    darkModeSwitchLabel: '外观',
    lightModeSwitchTitle: '切换到浅色',
    darkModeSwitchTitle: '切换到深色',
    notFound: { title: '页面不存在', quote: '这个地址没有内容，可能已经改名或删除。', linkText: '回到首页' },
    search: {
      provider: 'local',
      options: {
        translations: {
          button: { buttonText: '搜索文档', buttonAriaLabel: '搜索文档' },
          modal: {
            noResultsText: '没有找到',
            resetButtonTitle: '清除',
            displayDetails: '显示详情',
            footer: { selectText: '选择', navigateText: '切换', closeText: '关闭' }
          }
        }
      }
    },
    footer: { message: '只有两台机器：一台国内，一台香港。', copyright: 'dns-stack' }
  }
})
