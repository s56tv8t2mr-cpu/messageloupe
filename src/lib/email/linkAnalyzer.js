// URL extraction + heuristic flagging for the message body.
// Used to surface phishing destinations during takedown triage.

const SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd',
  'buff.ly', 'rebrand.ly', 'cli.gs', 'short.io', 'shorturl.at',
  'tiny.cc', 'lnkd.in', 'rb.gy', 'cutt.ly', 'tr.im', 'bl.ink',
  'shorturl.com', 'snip.ly', 'soo.gd', 'clk.im'
]);

const REGISTRABLE_SUFFIXES = [
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk',
  'com.au', 'net.au', 'org.au',
  'com.br', 'com.cn', 'com.hk', 'com.mx', 'com.my', 'com.ng', 'com.sg', 'com.tr', 'com.vn',
  'co.jp', 'co.nz', 'co.za'
];

const registrableDomain = (host) => {
  if (!host) return '';
  const lower = host.toLowerCase().replace(/^\[|\]$/g, '');
  const suffix = REGISTRABLE_SUFFIXES.find((s) => lower.endsWith(`.${s}`));
  if (suffix) {
    const before = lower.slice(0, -suffix.length - 1).split('.');
    const label = before.pop();
    return label ? `${label}.${suffix}` : lower;
  }
  return lower.split('.').slice(-2).join('.');
};

const isIpHost = (host) => {
  if (!host) return false;
  const stripped = host.replace(/^\[|\]$/g, '');
  return /^\d+\.\d+\.\d+\.\d+$/.test(stripped) || /^[0-9a-f:]+$/i.test(stripped);
};

const URL_RE = /https?:\/\/[^\s<>"'`)\]]+/gi;
const HREF_RE = /<a\b[^>]*?href\s*=\s*["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;

const stripHtmlTags = (s) => s
  .replace(/<[^>]+>/g, '')
  .replace(/&nbsp;/g, ' ')
  .replace(/&amp;/g, '&')
  .replace(/\s+/g, ' ')
  .trim();

// Trim trailing punctuation that often follows URLs in prose
const cleanUrl = (url) => url.replace(/[.,;:!?)\]'"]+$/, '');

const decodeHtmlEntities = (s) => s
  .replace(/&amp;/gi, '&')
  .replace(/&lt;/gi, '<')
  .replace(/&gt;/gi, '>')
  .replace(/&quot;/gi, '"')
  .replace(/&#39;/gi, "'");

const hostOf = (url) => {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    const m = url.match(/^https?:\/\/([^/?#]+)/i);
    return (m?.[1] || '').toLowerCase();
  }
};

export const extractLinks = (result) => {
  if (!result) return [];

  const found = new Map(); // key: lowercase URL → { url, displayText }

  const add = (rawUrl, displayText) => {
    const url = cleanUrl((rawUrl || '').trim());
    if (!/^https?:\/\//i.test(url)) return;
    const key = url.toLowerCase();
    const existing = found.get(key);
    if (!existing) {
      found.set(key, { url, displayText: displayText || null });
    } else if (displayText && !existing.displayText) {
      existing.displayText = displayText;
    }
  };

  // Plain text URLs
  const text = result.bodyText || '';
  (text.match(URL_RE) || []).forEach((m) => add(m));

  // HTML href URLs (with anchor text for mismatch detection)
  const html = decodeHtmlEntities(result.bodyHtml || '');
  let hrefMatch;
  HREF_RE.lastIndex = 0;
  while ((hrefMatch = HREF_RE.exec(html)) !== null) {
    add(hrefMatch[1], stripHtmlTags(hrefMatch[2]));
  }
  // Catch any bare URLs in HTML that aren't wrapped in anchors
  (html.match(URL_RE) || []).forEach((m) => add(m));

  const sendingRegistrable = registrableDomain(result.sendingDomain || '');

  return Array.from(found.values()).map(({ url, displayText }) => {
    const host = hostOf(url);
    const hostRegistrable = registrableDomain(host);
    const flags = [];

    // Mismatch: anchor text shows a URL that doesn't match the actual href
    if (displayText && /https?:\/\//i.test(displayText)) {
      const displayUrlMatch = displayText.match(URL_RE);
      if (displayUrlMatch) {
        const displayHost = hostOf(cleanUrl(displayUrlMatch[0]));
        if (displayHost && registrableDomain(displayHost) !== hostRegistrable) {
          flags.push('mismatch');
        }
      }
    }

    if (isIpHost(host)) flags.push('ipHost');
    if (host.includes('xn--')) flags.push('punycode');
    if (host.endsWith('.cm') || host.includes('.cm.')) flags.push('cmTld');
    if (SHORTENERS.has(host) || SHORTENERS.has(hostRegistrable)) flags.push('shortener');
    if (sendingRegistrable && hostRegistrable && hostRegistrable !== sendingRegistrable) {
      flags.push('thirdParty');
    }

    return { url, host, displayText: displayText || null, flags };
  }).sort((a, b) => {
    // High-severity flags first
    const score = (f) => (
      (f.flags.includes('mismatch') ? 100 : 0)
      + (f.flags.includes('ipHost') ? 50 : 0)
      + (f.flags.includes('punycode') ? 50 : 0)
      + (f.flags.includes('cmTld') ? 30 : 0)
      + (f.flags.includes('shortener') ? 20 : 0)
      + (f.flags.includes('thirdParty') ? 5 : 0)
    );
    return score(b) - score(a);
  });
};

export const FLAG_LABELS = {
  mismatch:   { text: 'Display ≠ Link',  severity: 'high' },
  ipHost:     { text: 'IP as host',       severity: 'high' },
  punycode:   { text: 'Punycode (xn--)',  severity: 'high' },
  cmTld:      { text: '.cm typosquat',    severity: 'medium' },
  shortener:  { text: 'URL shortener',    severity: 'medium' },
  thirdParty: { text: 'Third-party host', severity: 'info' }
};
