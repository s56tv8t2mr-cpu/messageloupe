// Recipient-side email security gateways (SEGs). When one of these appears
// as the "from" host of a Received hop, the real sender is one or more hops
// upstream. Used by the parser to bypass the gateway and surface the actual
// origin IP for abuse reporting.
//
// Patterns match anywhere in the "from <...>" portion of the Received header.

export const SECURITY_GATEWAY_PATTERNS = [
  // AppRiver / Zix
  /\bappriver\.com\b/i,
  /\bzixmail\.net\b/i,

  // Proofpoint family
  /\bpphosted\.com\b/i,
  /\bppops\.net\b/i,
  /\bproofpoint\.com\b/i,

  // Mimecast
  /\bmimecast(?:\.com|\.co\.uk|\.net)\b/i,

  // Symantec.cloud (formerly MessageLabs)
  /\bmessagelabs\.com\b/i,

  // Barracuda Email Security
  /\bbarracudanetworks\.com\b/i,
  /\bess\.barracuda\.com\b/i,

  // Sophos / Reflexion
  /\bsophos(?:email)?\.com\b/i,
  /\breflexion\.net\b/i,

  // Trend Micro Email Security
  /\btrendmicro\.com\b/i,
  /\btmes\.trendmicro\.com\b/i,

  // Cisco IronPort / Email Security
  /\bironport\.com\b/i,
  /\bciscoiron(?:port)?\.com\b/i,

  // FireEye / Trellix
  /\bfireeyecloud\.com\b/i,
  /\btrellix\.com\b/i,

  // Avanan (Check Point)
  /\bavanan\.net\b/i,

  // Perimeter Email Security
  /\bperimeter[-_]?email\.com\b/i,

  // MailRoute
  /\bmailroute\.net\b/i,

  // Forcepoint Email Security
  /\bmailcontrol\.com\b/i,
  /\bforcepoint\.com\b/i,

  // McAfee SaaS Email Protection / MX Logic
  /\bmxlogic\.net\b/i,

  // N-able Mail Assure (formerly SolarWinds SpamExperts)
  /\bmailassure\.com\b/i,
  /\bspamexperts\.com\b/i,

  // Hornetsecurity (and acquired brands)
  /\bhornetsecurity\.com\b/i,
  /\bantispameurope\.com\b/i,
  /\bsecuremx\.com\b/i,
  /\bmailspamprotection\.com\b/i,

  // Vade Secure
  /\bvadesecure\.(?:com|net)\b/i,

  // Spambrella
  /\bspambrella\.(?:com|net)\b/i,

  // Trustwave SEG / MailMarshal
  /\btrustwave\.com\b/i,
  /\bmailmarshal\.com\b/i,

  // SpamHero
  /\bspamhero\.com\b/i,

  // Modern API-based / inline platforms
  /\babnormalsecurity\.com\b/i,
  /\bironscales\.com\b/i,
  /\binky\.com\b/i,
  /\begress\.com\b/i,

  // GFI MailEssentials Online
  /\bgfi(?:cloud)?\.com\b/i
];

// Only check the "from <host>" portion — a hop where the gateway is the
// RECEIVER ("by gateway") shouldn't cause us to bypass the legitimate sender.
export const isSecurityGateway = (header) => {
  if (!header) return false;
  const fromPart = header.split(/\sby\s/i)[0];
  return SECURITY_GATEWAY_PATTERNS.some((p) => p.test(fromPart));
};
