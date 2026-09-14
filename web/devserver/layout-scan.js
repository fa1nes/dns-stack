'use strict';

window.__layoutScan = function () {
  const de = document.documentElement;
  const issues = [];
  const visible = (el) => el.offsetParent !== null;

  const pageOver = de.scrollWidth - de.clientWidth;
  if (pageOver > 1) issues.push('页面横向溢出 ' + pageOver + 'px');

  const spills = new Map();
  document.querySelectorAll('.page.active td, .page.active th').forEach((cell) => {
    if (!visible(cell) || getComputedStyle(cell).display === 'none') return;
    const box = cell.getBoundingClientRect();
    if (box.width <= 0) return;
    Array.from(cell.children).forEach((el) => {
      const r = el.getBoundingClientRect();
      const over = Math.round(Math.max(r.right - box.right, box.left - r.left));
      if (over <= 1) return;
      const key = '第' + (cell.cellIndex + 1) + '列 ' + (el.className || el.tagName);
      if (!spills.has(key) || spills.get(key) < over) spills.set(key, over);
    });
  });
  spills.forEach((over, key) => issues.push('单元格溢出 ' + key + ' ' + over + 'px'));

  document.querySelectorAll('.page.active .filters').forEach((row) => {
    if (!visible(row)) return;
    const sizes = new Set();
    row.querySelectorAll('input[type="text"], input[type="search"], .xsel-btn,' +
                         ' button:not(.xsel-btn):not(.icon)').forEach((el) => {
      if (visible(el)) sizes.add(getComputedStyle(el).fontSize);
    });
    if (sizes.size > 1) {
      issues.push('同一筛选行里出现 ' + sizes.size + ' 种字号: ' + Array.from(sizes).join('/'));
    }
  });

  document.querySelectorAll('.page.active .callout, .page.active .state').forEach((el) => {
    if (!visible(el)) return;
    const over = Math.round(el.scrollWidth - el.clientWidth);
    if (over > 1) issues.push('提示块溢出 ' + (el.className || '').split(' ')[0] + ' ' + over + 'px');
  });

  return issues;
};

window.__layoutSweep = async function () {
  const wait = (ms) => new Promise((r) => setTimeout(r, ms));
  const out = [];
  for (const page of ['overview', 'queries', 'tools', 'settings']) {
    const nav = document.querySelector('[data-page="' + page + '"]');
    if (!nav) continue;
    nav.click();
    await wait(450);
    const first = window.__layoutScan();
    if (first.length) out.push(page + ': ' + first.join(' | '));
    const tabs = Array.from(document.querySelectorAll('.page.active .main-tabs button'));
    for (const tab of tabs) {
      tab.click();
      await wait(650);
      const found = window.__layoutScan();
      if (found.length) out.push(page + '/' + tab.textContent.trim() + ': ' + found.join(' | '));
    }
  }
  return { viewport: window.innerWidth + 'x' + window.innerHeight, issues: out };
};
