
(function (global) {
  'use strict';

  var configured = global.DNS_STACK_CONFIG || {};
  var raw = typeof configured.apiBase === 'string' ? configured.apiBase.trim() : '';
  var base = '';

  if (raw) {
    try {
      var parsed = new URL(raw, global.location.href);
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        throw new Error('API base must use HTTP(S)');
      }
      parsed.hash = '';
      parsed.search = '';
      base = parsed.href.replace(/\/$/, '');
    } catch (err) {
      global.console && console.error('[dns-stack] invalid apiBase', err);
    }
  }

  global.DNS_STACK_API_BASE = base;
  global.dnsStackApiUrl = function (path) {
    var value = String(path || '');
    if (/^https?:\/\//i.test(value)) return value;
    if (value.charAt(0) !== '/') value = '/' + value;
    return base + value;
  };
})(window);
