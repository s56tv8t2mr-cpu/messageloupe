export const isGoogleIp = (ip = '') => {
  const lower = ip.toLowerCase();
  return lower.startsWith('2001:4860')
    || lower.startsWith('2607:f8b0')
    || lower.startsWith('209.85')
    || lower.startsWith('74.125');
};

export const isMicrosoftIp = (ip = '') => {
  const lower = ip.toLowerCase();
  return lower.startsWith('2a01:111')
    || lower.startsWith('40.107')
    || lower.startsWith('40.92')
    || lower.startsWith('52.100');
};

export const isPrivateIp = (ip) => {
  if (!ip) return true;
  const lowerIp = ip.toLowerCase();

  let checkIp = ip;
  if (lowerIp.startsWith('2002:')) {
    const parts = lowerIp.split(':');
    if (parts.length >= 3) {
      const group2 = parseInt(parts[1], 16) || 0;
      const group3 = parseInt(parts[2], 16) || 0;
      checkIp = `${(group2 >> 8) & 0xFF}.${group2 & 0xFF}.${(group3 >> 8) & 0xFF}.${group3 & 0xFF}`;
    }
  }

  if (lowerIp.startsWith('::ffff:')) {
    checkIp = ip.split(':').pop();
  }

  if (checkIp.includes('.')) {
    return /^(10\.|127\.|169\.254\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)/.test(checkIp);
  }

  // IPv6 private/local ranges:
  //   ::1            loopback
  //   ::             unspecified
  //   fc00::/7       unique local addresses (fc00–fdff)
  //   fe80::/10      link-local (fe80–febf)
  //   ff00::/8       multicast (not a public unicast source)
  return /^(::1$|::$|f[cd][0-9a-f]{2}:|fe[89ab][0-9a-f]:|ff[0-9a-f]{2}:)/i.test(checkIp);
};

// Strict validator — catches false positives like timestamps ("09:52:35")
// being mistaken for IPv6 by loose regexes.
export const isValidPublicIp = (ip) => {
  if (!ip) return false;
  const stripped = ip.replace(/^\[|\]$/g, '');

  // IPv4 dotted-quad with valid octets
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(stripped)) {
    const octetsValid = stripped.split('.').every((o) => {
      const n = parseInt(o, 10);
      return n >= 0 && n <= 255;
    });
    return octetsValid && !isPrivateIp(stripped);
  }

  // IPv6 — must be hex+colons only, and either contain :: or have exactly
  // 8 hex groups. This rejects shapes like "09:52:35" (only 3 groups, no ::).
  if (!/^[0-9a-f:]+$/i.test(stripped)) return false;
  const hexGroup = /^[0-9a-f]{1,4}$/i;

  if (stripped.includes('::')) {
    const groups = stripped.split(/::?/).filter(Boolean);
    if (groups.length > 7) return false;
    if (!groups.every((g) => hexGroup.test(g))) return false;
  } else {
    const groups = stripped.split(':');
    if (groups.length !== 8) return false;
    if (!groups.every((g) => hexGroup.test(g))) return false;
  }
  return !isPrivateIp(stripped);
};
