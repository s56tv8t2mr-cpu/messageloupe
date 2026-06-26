import { isValidPublicIp } from './ipClassifiers.js';
import { matchProvider } from './providers.js';
import { isSecurityGateway } from './securityGateways.js';
import { decodeEncodedWords } from './encodedWords.js';

export { isGoogleIp } from './ipClassifiers.js';

const extractEmailAddress = (value) => {
  if (!value) return null;
  const bracketMatch = value.match(/<([^>]+)>/);
  if (bracketMatch?.[1]) return bracketMatch[1].trim();

  const emailMatch = value.match(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i);
  return emailMatch ? emailMatch[0].trim() : null;
};

const extractDomain = (value) => {
  if (!value) return null;
  const candidate = (extractEmailAddress(value) || value)
    .replace(/[<>]/g, '')
    .trim()
    .toLowerCase();
  const domainPart = candidate.includes('@') ? candidate.split('@').pop() : candidate.split(/[;\s]/)[0];
  const match = domainPart.match(/[a-z0-9.-]+\.[a-z]{2,}$/i);
  return match ? match[0].toLowerCase() : null;
};

const REGISTRABLE_SUFFIXES = [
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk',
  'com.au', 'net.au', 'org.au',
  'com.br', 'com.cn', 'com.hk', 'com.mx', 'com.my', 'com.ng', 'com.sg', 'com.tr', 'com.vn',
  'co.jp', 'co.nz', 'co.za'
];

const registrableDomain = (host) => {
  if (!host) return null;
  const lower = host.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
  const suffix = REGISTRABLE_SUFFIXES.find((s) => lower.endsWith(`.${s}`));
  if (suffix) {
    const label = lower.slice(0, -suffix.length - 1).split('.').pop();
    return label ? `${label}.${suffix}` : lower;
  }
  const parts = lower.split('.').filter(Boolean);
  return parts.length >= 2 ? parts.slice(-2).join('.') : lower;
};

const sameRegistrableDomain = (a, b) => {
  const left = registrableDomain(a);
  const right = registrableDomain(b);
  return Boolean(left && right && left === right);
};

const hostFromAuthservId = (value) => {
  const firstToken = value
    ?.split(';')[0]
    ?.replace(/\([^)]*\)/g, ' ')
    ?.trim()
    ?.split(/\s+/)[0]
    ?.replace(/\.$/, '');
  return extractDomain(firstToken);
};

const receivedByHosts = (entry) => {
  const pattern = /\bby\s+([a-z0-9.-]+\.[a-z]{2,})/gi;
  const match = pattern.exec(entry.value);
  return match?.[1] ? [match[1].toLowerCase().replace(/\.$/, '')] : [];
};

const receivedFromHosts = (entry) => {
  const pattern = /\bfrom\s+([a-z0-9.-]+\.[a-z]{2,})/gi;
  const match = pattern.exec(entry.value);
  return match?.[1] ? [match[1].toLowerCase().replace(/\.$/, '')] : [];
};

const topReceivedByHosts = (receivedEntries) => {
  const firstReceived = receivedEntries[0];
  if (!firstReceived) return [];
  return receivedByHosts(firstReceived);
};

const MICROSOFT_RECIPIENT_HOST_RE =
  /(?:^|\.)(?:(?:mail\.)?protection\.outlook\.com|prod\.outlook\.com|outlook\.office365\.com)$/i;
const MICROSOFT_EOP_FRONTEND_LABEL_RE = /P(?:E)?PF/i;

const isMicrosoftRecipientHost = (host) => (
  Boolean(host && MICROSOFT_RECIPIENT_HOST_RE.test(host))
);

const firstHostLabel = (host) => host?.split('.')[0]?.toLowerCase() || null;

const isMicrosoftEopFrontendHost = (host) => (
  isMicrosoftRecipientHost(host) &&
  MICROSOFT_EOP_FRONTEND_LABEL_RE.test(firstHostLabel(host) || '')
);

const sameHostOrLabel = (left, right) => (
  Boolean(left && right && (
    left === right ||
    firstHostLabel(left) === firstHostLabel(right)
  ))
);

const receivedEntriesAreAdjacent = (newerEntry, olderEntry) => {
  const newerFromHosts = receivedFromHosts(newerEntry);
  const olderByHosts = receivedByHosts(olderEntry);
  return newerFromHosts.some((fromHost) => (
    olderByHosts.some((byHost) => sameHostOrLabel(fromHost, byHost))
  ));
};

const trustedReceivedPrefix = (receivedEntries) => {
  const trusted = [];
  for (const entry of receivedEntries) {
    const previous = trusted.at(-1);
    if (!previous || receivedEntriesAreAdjacent(previous, entry)) {
      trusted.push(entry);
      continue;
    }
    break;
  }
  return trusted;
};

const hasTrustedAuthservHost = (authservHost, byHosts) => (
  byHosts.some((host) => (
    authservHost === host ||
    authservHost.endsWith(`.${host}`) ||
    host.endsWith(`.${authservHost}`) ||
    sameRegistrableDomain(authservHost, host)
  ))
);

const isMicrosoftAnonymousAuthResults = (entry) => (
  !hostFromAuthservId(entry.value) &&
  /\bcompauth=(?:pass|fail|none|softpass|temperror|permerror)\b/i.test(entry.value) &&
  /\breason=\d+\b/i.test(entry.value)
);

const findFirstMicrosoftInboundBoundary = (receivedEntries) => (
  trustedReceivedPrefix(receivedEntries).find((entry) => {
    const hasMicrosoftByHost = receivedByHosts(entry).some(isMicrosoftEopFrontendHost);
    if (!hasMicrosoftByHost) return false;

    const fromHosts = receivedFromHosts(entry);
    return fromHosts.some((host) => !isMicrosoftRecipientHost(host));
  }) || null
);

const hasMicrosoftReceivedSpfEvidence = (receivedSpfEntries, authResultsEntry, boundaryEntry) => (
  receivedSpfEntries.some((entry) => (
    entry.index > authResultsEntry.index &&
    entry.index < boundaryEntry.index &&
    /\breceiver=protection\.outlook\.com\b/i.test(entry.value) &&
    /\bclient-ip=/i.test(entry.value)
  ))
);

const isRecognizedMicrosoftAnonymousAuthResults = (
  entry,
  receivedEntries,
  receivedSpfEntries,
  microsoftAuthSourceHeaders
) => {
  if (!isMicrosoftAnonymousAuthResults(entry)) return false;
  if (!topReceivedByHosts(receivedEntries).some(isMicrosoftRecipientHost)) return false;

  const authSourceHosts = microsoftAuthSourceHeaders
    .map((header) => extractDomain(header))
    .filter(isMicrosoftEopFrontendHost);
  const authSourceLabels = new Set(authSourceHosts.map(firstHostLabel).filter(Boolean));
  if (authSourceLabels.size === 0) return false;

  const boundaryEntry = findFirstMicrosoftInboundBoundary(receivedEntries);
  if (!boundaryEntry || entry.index >= boundaryEntry.index) return false;

  const boundaryByLabels = new Set(
    receivedByHosts(boundaryEntry)
      .filter(isMicrosoftEopFrontendHost)
      .map(firstHostLabel)
      .filter(Boolean)
  );
  if (![...boundaryByLabels].some((label) => authSourceLabels.has(label))) return false;

  return hasMicrosoftReceivedSpfEvidence(receivedSpfEntries, entry, boundaryEntry);
};

const selectTrustedAuthResults = (entries, receivedEntries) => {
  const byHosts = topReceivedByHosts(receivedEntries);
  return entries.find((entry) => {
    const authservHost = hostFromAuthservId(entry.value);
    return authservHost && hasTrustedAuthservHost(authservHost, byHosts);
  }) || null;
};

const selectRecognizedAuthResults = (
  entries,
  receivedEntries,
  receivedSpfEntries,
  microsoftAuthSourceHeaders
) => (
  entries.find((entry) => (
    isRecognizedMicrosoftAnonymousAuthResults(
      entry,
      receivedEntries,
      receivedSpfEntries,
      microsoftAuthSourceHeaders
    )
  )) || null
);

const parseAuthResult = (value, token) => (
  value?.match(new RegExp(`${token}=([a-z]+)`, 'i'))?.[1]?.toLowerCase() || null
);

const parseHeaderMatch = (value, patterns) => {
  for (const pattern of patterns) {
    const match = value?.match(pattern);
    if (match?.[1]) return match[1];
  }
  return null;
};

const decodeHtmlCodePoint = (value, radix) => {
  const codePoint = parseInt(value, radix);
  if (!Number.isInteger(codePoint) || codePoint < 0 || codePoint > 0x10FFFF) return '';
  try {
    return String.fromCodePoint(codePoint);
  } catch {
    return '';
  }
};

const stripHtmlToText = (html) => (
  (html || '')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'")
    .replace(/&#x([0-9a-f]+);/gi, (_m, hex) => decodeHtmlCodePoint(hex, 16))
    .replace(/&#(\d+);/g, (_m, code) => decodeHtmlCodePoint(code, 10))
    .replace(/\s+/g, ' ')
    .trim()
);

const looksLikeHtml = (content, contentType = '') => (
  /text\/html/i.test(contentType) ||
  /<(?:html|body|table|div|p|br|a|img|span|strong|em|i|b)\b/i.test(content || '')
);

const appendDecodedPart = (existing, content) => {
  if (!content) return existing;
  return existing ? `${existing}\n${content}` : content;
};

export const parseEmlLocally = (text) => {
  const [headersPart, ...bodyParts] = text.split(/\r?\n\r?\n/);
  const rawBody = bodyParts.join('\n\n');
  const headerLines = headersPart.split(/\r?\n/);

  const getHeaderEntries = (name) => {
    const results = [];
    const prefix = `${name.toLowerCase()}:`;
    for (let i = 0; i < headerLines.length; i++) {
      if (headerLines[i].toLowerCase().startsWith(prefix)) {
        let result = headerLines[i].substring(name.length + 1).trim();
        let j = i + 1;
        while (j < headerLines.length && /^\s/.test(headerLines[j])) {
          result += ` ${headerLines[j].trim()}`;
          j++;
        }
        results.push({ value: result, index: i });
      }
    }
    return results;
  };

  const getHeader = (name) => {
    const first = getHeaderEntries(name)[0];
    if (first) return first.value;
    return null;
  };

  const getHeaders = (name) => {
    return getHeaderEntries(name).map((entry) => entry.value);
  };

  const decodeBody = (content, encoding) => {
    if (!content) return "";
    try {
      const lowerEncoding = encoding?.toLowerCase();
      if (lowerEncoding === 'base64') {
        const cleaned = content.replace(/\s/g, '');
        return new TextDecoder().decode(Uint8Array.from(atob(cleaned), (char) => char.charCodeAt(0)));
      }
      if (lowerEncoding === 'quoted-printable') {
        return content
          .replace(/=\r?\n/g, '')
          .replace(/=\n/g, '')
          .replace(/=[0-9A-F]{2}/gi, (match) => String.fromCharCode(parseInt(match.slice(1), 16)));
      }
    } catch {
      // Fall through to the raw content if decode fails — better to show
      // the encoded text than to crash the parser.
    }
    return content;
  };

  const receivedEntries = getHeaderEntries('Received');
  const allReceived = receivedEntries.map((entry) => entry.value);
  const receivedSpfEntries = getHeaderEntries('Received-SPF');
  const spfHeader = receivedSpfEntries[0]?.value || null;
  const authResultsEntries = getHeaderEntries('Authentication-Results');
  const fromHeader = decodeEncodedWords(getHeader('From') || '');
  const toHeader = decodeEncodedWords(getHeader('To') || '');
  const microsoftAuthSourceHeaders = [
    ...getHeaders('X-MS-Exchange-Organization-AuthSource'),
    ...getHeaders('X-MS-Exchange-CrossTenant-AuthSource')
  ].filter(Boolean);
  const duplicateCriticalHeaders = ['From', 'Subject', 'Return-Path'].filter((name) => (
    getHeaderEntries(name).length > 1
  ));
  const returnPath = decodeEncodedWords(getHeader('Return-Path') || '')?.replace(/[<>]/g, '') || null;
  const replyToHeader = decodeEncodedWords(getHeader('Reply-To') || '') || null;
  const listIdHeader = getHeader('List-Id') || null;
  const hasThreadReferences = Boolean(getHeader('In-Reply-To') || getHeader('References'));
  const sendingEmail = extractEmailAddress(fromHeader) || fromHeader || null;
  const sendingDomain = extractDomain(fromHeader);
  const recipientEmail = extractEmailAddress(toHeader);
  const recipientDomain = extractDomain(toHeader);
  const trustedAuthResultsEntry = selectTrustedAuthResults(authResultsEntries, receivedEntries);
  const recognizedAuthResultsEntry = trustedAuthResultsEntry
    ? null
    : selectRecognizedAuthResults(
      authResultsEntries,
      receivedEntries,
      receivedSpfEntries,
      microsoftAuthSourceHeaders
    );
  const authResults = trustedAuthResultsEntry?.value || null;
  const ignoredAuthResultsCount =
    authResultsEntries.length -
    (trustedAuthResultsEntry ? 1 : 0) -
    (recognizedAuthResultsEntry ? 1 : 0);
  const authResultsTrusted = Boolean(trustedAuthResultsEntry);
  // Outlook/M365 marks rights-protected (RMS-encrypted) messages with
  // Content-Class: rpmsg.message. The body of such a message is opaque
  // to any analyzer — combined with other signals it's a strong tell.
  const contentClass = getHeader('Content-Class')?.toLowerCase() || null;
  const returnPathDomain = extractDomain(returnPath);
  const replyTo = replyToHeader ? (extractEmailAddress(replyToHeader) || replyToHeader.replace(/[<>]/g, '').trim()) : null;
  const replyToDomain = extractDomain(replyToHeader);
  const dkimSignature = getHeader('DKIM-Signature') || '';
  const msgId = getHeader('Message-ID') || '';
  const lowerMsgId = msgId.toLowerCase();

  const xSpam = getHeader('X-Spam')?.trim().toLowerCase() || null;
  const xSpamFlag = getHeader('X-Spam-Flag')?.trim().toLowerCase() || null;
  const xSpamdResult = getHeader('X-Spamd-Result') || null;
  const xRspamdServer = getHeader('X-Rspamd-Server') || null;
  const xPmSpamAction = getHeader('X-Pm-Spam-Action') || null;
  const xMsScl = getHeader('X-MS-Exchange-Organization-SCL') || null;
  const xForefrontReport = getHeader('X-Forefront-Antispam-Report') || '';
  const xSpamStatus = getHeader('X-Spam-Status') || null;
  const xSpamCheckerVersion = getHeader('X-Spam-Checker-Version') || null;
  const hasTrustedRecipientSpamContext = Boolean(
    xSpamdResult &&
    (xPmSpamAction || /(?:rspamd|mailin|proton|recipient|mx[0-9.-]*\.)/i.test(xRspamdServer || ''))
  );
  const spamScore = xSpamdResult?.match(/\[([+-]?\d+(?:\.\d+)?)\s*\//)?.[1] || null;
  const microsoftScl = xMsScl?.match(/-?\d+/)?.[0] ?? null;
  const recipientByHosts = topReceivedByHosts(receivedEntries).join(' ');
  const hasMicrosoftRecipientContext =
    /\b(?:outlook|protection\.outlook|prod\.outlook|microsoft|office365)\.com\b/i.test(recipientByHosts);
  const spamAssassinHost = xSpamCheckerVersion
    ?.match(/\bon\s+([a-z0-9.-]+\.[a-z]{2,})/i)?.[1]
    ?.toLowerCase()
    ?.replace(/\.$/, '') || null;
  const hasSpamAssassinContext = Boolean(
    xSpamStatus &&
    spamAssassinHost &&
    topReceivedByHosts(receivedEntries).some((host) => (
      spamAssassinHost === host ||
      spamAssassinHost.endsWith(`.${host}`) ||
      host.endsWith(`.${spamAssassinHost}`) ||
      sameRegistrableDomain(spamAssassinHost, host)
    ))
  );
  const microsoftSpamVerdict = Boolean(
    hasMicrosoftRecipientContext &&
    (
      (microsoftScl && Number(microsoftScl) >= 5) ||
      /\bSFV:(?:SPM|PHSH)\b/i.test(xForefrontReport)
    )
  );
  const spamAssassinVerdict = xSpamFlag === 'yes' && hasSpamAssassinContext;
  const rspamdSpamVerdict = xSpam === 'yes' && hasTrustedRecipientSpamContext;
  const recipientSpamVerdict = rspamdSpamVerdict || microsoftSpamVerdict || spamAssassinVerdict ? 'spam' : null;
  let recipientSpamSource = null;
  if (recipientSpamVerdict) {
    if (microsoftSpamVerdict) {
      recipientSpamSource = 'Microsoft / Forefront';
    } else if (spamAssassinVerdict) {
      recipientSpamSource = 'SpamAssassin';
    } else if (xRspamdServer) {
      recipientSpamSource = xRspamdServer;
    } else if (xPmSpamAction) {
      recipientSpamSource = 'Proton Mail / Rspamd';
    } else {
      recipientSpamSource = 'recipient spam filter';
    }
  }

  const spfResult = parseAuthResult(authResults, 'spf')
    || spfHeader?.match(/^(pass|fail|softfail|neutral|none|temperror|permerror)/i)?.[1]?.toLowerCase()
    || null;
  const dkimResult = parseAuthResult(authResults, 'dkim') || (dkimSignature ? 'present' : null);
  const dmarcResult = parseAuthResult(authResults, 'dmarc') || null;
  const spfMailFromDomain = extractDomain(parseHeaderMatch(authResults, [/smtp\.mailfrom=([^\s;]+)/i]));
  const dkimHeaderDomain = extractDomain(parseHeaderMatch(authResults, [/header\.i=@?([^\s;]+)/i]))
    || extractDomain(parseHeaderMatch(dkimSignature, [/\bd=([^;\s]+)/i]));
  const authHeaderFromDomain = extractDomain(parseHeaderMatch(authResults, [/header\.from=([^\s;]+)/i])) || sendingDomain;

  const publicIpInHeader = (header) => {
    const ipBody = /((?:\d{1,3}\.){3}\d{1,3}|(?:[a-fA-F0-9]{1,4}:|:){1,7}[a-fA-F0-9]{1,4})/.source;
    const patterns = [
      new RegExp(`(?:\\[|\\()${ipBody}(?:\\]|\\))`, 'g'),
      new RegExp(`(?:^|[^a-z0-9.-])${ipBody}(?![a-z0-9.-])`, 'gi')
    ];
    for (const pattern of patterns) {
      const matches = header.matchAll(pattern);
      for (const match of matches) {
        if (isValidPublicIp(match[1])) return match[1];
      }
    }
    return null;
  };

  let sourceIp = null;
  let sourceIpEvidence = null;
  let sourceHostname = "Unknown";
  let heloIdentity = null;
  let sourceReceivedHeader = null;

  const sourceIpCandidates = [
    {
      ip: parseHeaderMatch(authResults, [/sender IP is ([a-fA-F0-9.:]+)/i]),
      evidence: "Authentication-Results sender IP"
    },
    {
      ip: parseHeaderMatch(authResults, [/client-ip=([a-fA-F0-9.:]+)/i]),
      evidence: "Authentication-Results client-ip"
    },
    {
      ip: parseHeaderMatch(spfHeader, [/client-ip=([a-fA-F0-9.:]+)/i]),
      evidence: "Received-SPF client-ip"
    },
    {
      ip: parseHeaderMatch(spfHeader, [/designates\s+([a-fA-F0-9.:]+)/i]),
      evidence: "Received-SPF authorized sender IP"
    },
    {
      ip: parseHeaderMatch(spfHeader, [/use of\s+([a-fA-F0-9.:]+)/i]),
      evidence: "Received-SPF sender IP"
    }
  ];

  const extractedSourceIp = sourceIpCandidates.find((candidate) => isValidPublicIp(candidate.ip));

  if (extractedSourceIp) {
    sourceIp = extractedSourceIp.ip;
    sourceIpEvidence = extractedSourceIp.evidence;
  }

  const applySourceHeader = (header, ip, evidence = null) => {
    sourceReceivedHeader = header;
    sourceIp = ip;
    if (evidence) sourceIpEvidence = evidence;
    // Hostname extraction. Tries, in order:
    //   1. "from <hostname>"                    — RFC standard form
    //   2. "(reverse-dns.example [ip])"          — common with IP-literal HELO
    //   3. "(HELO hostname)" / "(EHLO hostname)" — parenthesised SMTP greeting
    //   4. "helo=hostname"                       — Exim / ecelerity etc. style
    sourceHostname = header.match(/from\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/i)?.[1]
      || header.match(/\(([^()\s]+\.[a-zA-Z]{2,})\s+\[[a-fA-F0-9.:]+\]\)/i)?.[1]
      || header.match(/\((?:HELO|EHLO)\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/i)?.[1]
      || header.match(/\bhelo=([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/i)?.[1]
      || "Unknown";
    heloIdentity = header.match(/\((?:HELO|EHLO)\s+([^)]+)\)/i)?.[1]?.trim() || null;
  };

  // Locate the Received header that corresponds to the auth-derived IP
  let matchedHeaderIndex = -1;
  if (sourceIp) {
    for (let i = allReceived.length - 1; i >= 0; i--) {
      if (allReceived[i].includes(sourceIp)) {
        matchedHeaderIndex = i;
        break;
      }
    }
  }

  // If the matched header is a recipient-side security gateway, walk older
  // (more upstream) Received headers to find the real origin sender.
  let bypassedGateway = false;
  if (matchedHeaderIndex >= 0 && isSecurityGateway(allReceived[matchedHeaderIndex])) {
    for (let i = matchedHeaderIndex + 1; i < allReceived.length; i++) {
      const header = allReceived[i];
      if (isSecurityGateway(header)) continue;
      const fromMatch = header.match(/from\s+[^;]*?(?:\[|\()([a-fA-F0-9.:]{7,})(?:\]|\))/i);
      if (fromMatch && isValidPublicIp(fromMatch[1])) {
        sourceIp = fromMatch[1];
        sourceIpEvidence = "Real sender behind recipient-side security gateway";
        matchedHeaderIndex = i;
        bypassedGateway = true;
        break;
      }
      const publicIp = publicIpInHeader(header);
      if (publicIp) {
        sourceIp = publicIp;
        sourceIpEvidence = "Real sender behind recipient-side security gateway";
        matchedHeaderIndex = i;
        bypassedGateway = true;
        break;
      }
    }
  }

  if (matchedHeaderIndex >= 0) {
    applySourceHeader(allReceived[matchedHeaderIndex], sourceIp, sourceIpEvidence);
  }

  // Final fallback: walk Received headers oldest-first, skipping gateways
  if (!sourceReceivedHeader) {
    for (let i = allReceived.length - 1; i >= 0; i--) {
      const header = allReceived[i];
      if (isSecurityGateway(header)) continue;
      const fromMatch = header.match(/from\s+[^;]*?(?:\[|\()([a-fA-F0-9.:]{7,})(?:\]|\))/i);
      if (fromMatch && isValidPublicIp(fromMatch[1])) {
        applySourceHeader(header, fromMatch[1], "Oldest external Received header");
        break;
      }

      const publicIp = publicIpInHeader(header);
      if (publicIp) {
        applySourceHeader(header, publicIp, "Received header public IP fallback");
        break;
      }
    }
  }

  const receivedChain = allReceived.slice().reverse().map((header, index) => ({
    hop: index + 1,
    header,
    selected: Boolean(sourceReceivedHeader && header === sourceReceivedHeader)
  }));

  const collectNamedHeaders = (names) => names.flatMap((name) => (
    getHeaders(name).map((value) => ({ name, value }))
  ));

  const relayIndicators = [];
  const addRelayIndicator = (label, headers, detail) => {
    if (!headers.length) return;
    relayIndicators.push({
      label,
      detail: detail || `${headers.length} matching header${headers.length === 1 ? '' : 's'} detected.`,
      headers
    });
  };

  const arcHeaders = collectNamedHeaders(['ARC-Seal', 'ARC-Message-Signature', 'ARC-Authentication-Results']);
  addRelayIndicator(
    "ARC authentication chain present",
    arcHeaders,
    "ARC can preserve authentication results across forwarding or relay paths."
  );

  const listHeaders = collectNamedHeaders(['List-Id', 'List-Unsubscribe', 'List-Post', 'List-Help', 'List-Subscribe', 'List-Archive']);
  addRelayIndicator(
    "Mailing list headers present",
    listHeaders,
    "List headers can indicate legitimate bulk/list handling that changes the delivery path."
  );

  const resentHeaders = collectNamedHeaders(['Resent-From', 'Resent-Sender', 'Resent-To', 'Resent-Date', 'Resent-Message-ID']);
  addRelayIndicator(
    "Resent headers present",
    resentHeaders,
    "Resent headers can indicate a message was re-sent by an intermediary."
  );

  const forwardingHeaders = collectNamedHeaders([
    'X-Forwarded-For',
    'X-Forwarded-To',
    'X-Forwarded-Message-Id',
    'X-MS-Exchange-ForwardingLoop',
    'X-MS-Exchange-Inbox-Rules-Loop'
  ]);
  addRelayIndicator(
    "Forwarding headers present",
    forwardingHeaders,
    "Forwarding headers can explain authentication changes between the original sender and final mailbox."
  );

  const gatewayReceivedHeaders = allReceived.filter((h) => isSecurityGateway(h));
  if (gatewayReceivedHeaders.length) {
    relayIndicators.push({
      label: bypassedGateway
        ? "Recipient-side security gateway bypassed"
        : "Recipient-side security gateway present",
      detail: bypassedGateway
        ? "A known security gateway (AppRiver, Proofpoint, Mimecast, etc.) appeared between the original sender and the recipient. The source IP shown is the upstream sender, not the gateway."
        : "A known security gateway appears in the chain. If the source IP looks like the gateway, the real sender is one or more hops upstream.",
      headers: gatewayReceivedHeaders.map((value) => ({ name: 'Received', value }))
    });
  }

  const autoSubmitted = getHeader('Auto-Submitted');
  if (autoSubmitted && autoSubmitted.toLowerCase() !== 'no') {
    relayIndicators.push({
      label: "Automated submission header present",
      detail: "Auto-Submitted can indicate an automated responder, notification, or system-generated message.",
      headers: [{ name: 'Auto-Submitted', value: autoSubmitted }]
    });
  }

  const precedence = getHeader('Precedence');
  if (precedence && /^(list|bulk|junk)$/i.test(precedence.trim())) {
    relayIndicators.push({
      label: "Bulk/list precedence header present",
      detail: "Precedence can identify bulk or list traffic that may have different delivery handling.",
      headers: [{ name: 'Precedence', value: precedence }]
    });
  }

  const lowerSourceHeader = (sourceReceivedHeader || '').toLowerCase();
  const lowerSourceHostname = sourceHostname.toLowerCase();
  const senderEvidence = [
    lowerSourceHeader,
    lowerMsgId,
    dkimSignature.toLowerCase(),
    (returnPath || '').toLowerCase()
  ].join('\n');

  const provider = matchProvider({
    senderEvidence,
    lowerMsgId,
    lowerSourceHeader,
    lowerSourceHostname,
    sourceIp,
    sendingDomain,
    returnPathDomain
  });

  const sendingService = provider?.name || null;
  const abuseReport = provider?.abuse || null;

  const spfFailish = ['fail', 'softfail', 'permerror'].includes(spfResult || '');
  const dkimAbsentish = !dkimResult || ['none', 'fail'].includes(dkimResult);
  const spoofingLikely = Boolean(
    sendingDomain && (
      dmarcResult === 'fail'
      || (spfFailish && dkimAbsentish && (!authHeaderFromDomain || authHeaderFromDomain === sendingDomain))
    )
  );

  const authSummary = [
    `SPF: ${spfResult || 'unknown'}`,
    `DKIM: ${dkimResult || 'unknown'}`,
    `DMARC: ${dmarcResult || 'unknown'}`
  ].join(' | ');

  const senderDomainNote = spoofingLikely
    ? `${sendingDomain || 'Visible sender domain'} looks plausible by spelling, but this message does not authenticate it as an authorized sender. Treat it as spoofed or unauthorized.`
    : sendingDomain
      ? `${sendingDomain} does not look like an obvious lookalike from the headers alone.`
      : 'No sender domain extracted.';

  let bodyText = "";
  let bodyHtml = "";
  const processMimeParts = (content, boundary, depth = 0) => {
    if (!boundary || depth > 10) return;
    const parts = content.split(`--${boundary}`);

    for (let i = 1; i < parts.length; i++) {
      const part = parts[i];
      if (!part.trim() || part.trim() === "--") continue;

      const split = part.match(/\r?\n\r?\n/);
      if (!split) continue;

      const partHeaders = part.substring(0, split.index);
      const partBody = part.substring(split.index + split[0].length).replace(/\r?\n--\s*$/, '').trim();

      const contentTypeMatch = partHeaders.match(/Content-Type:\s*([^;\s]+)/i);
      const innerType = contentTypeMatch?.[1]?.toLowerCase() || "";
      const encodingMatch = partHeaders.match(/Content-Transfer-Encoding:\s*(\S+)/i);
      const encoding = encodingMatch?.[1];

      if (innerType.includes('multipart/')) {
        const innerBoundaryMatch = partHeaders.match(/boundary=(?:"([^"]+)"|([^;\s]+))/i);
        const innerBoundary = innerBoundaryMatch?.[1] || innerBoundaryMatch?.[2];
        if (innerBoundary && innerBoundary !== boundary) {
          processMimeParts(partBody, innerBoundary, depth + 1);
        }
      } else if (innerType.includes('text/plain')) {
        bodyText = appendDecodedPart(bodyText, decodeBody(partBody, encoding));
      } else if (innerType.includes('text/html')) {
        const decodedHtml = decodeBody(partBody, encoding);
        bodyHtml = appendDecodedPart(bodyHtml, decodedHtml);
        bodyText = appendDecodedPart(bodyText, stripHtmlToText(decodedHtml));
      }
    }
  };

  const rootContentType = getHeader('Content-Type') || '';
  const mainBoundaryMatch = rootContentType.match(/boundary=(?:"([^"]+)"|([^;\s]+))/i);
  const boundary = mainBoundaryMatch?.[1] || mainBoundaryMatch?.[2];
  if (boundary) processMimeParts(rawBody, boundary);
  else {
    const decodedBody = decodeBody(rawBody, getHeader('Content-Transfer-Encoding'));
    if (looksLikeHtml(decodedBody, rootContentType)) {
      bodyHtml = decodedBody;
      bodyText = stripHtmlToText(decodedBody);
    } else {
      bodyText = decodedBody;
    }
  }

  const hasImageContent = /<img\b|Content-Type:\s*image\//i.test(`${bodyHtml}\n${text}`);
  const hasBodyContent = Boolean(bodyText || bodyHtml || rawBody.trim());

  return {
    subject: decodeEncodedWords(getHeader('Subject') || '') || null,
    sendingEmail,
    sendingName: fromHeader.split('<')[0]?.replace(/"/g, '')?.trim() || 'Unknown',
    sendingDomain,
    recipientEmail,
    recipientDomain,
    contentClass,
    returnPath,
    returnPathDomain,
    replyTo,
    replyToDomain,
    listId: listIdHeader,
    messageId: msgId,
    hasThreadReferences,
    bodyText,
    bodyHtml,
    hasImageContent,
    hasBodyContent,
    duplicateCriticalHeaders,
    allHeaders: headersPart,
    sendingService: sendingService || 'No clear email service identified',
    serviceIdentified: Boolean(sendingService),
    abuseReport,
    sourceHostname,
    sourceIp,
    sourceIpEvidence,
    sourceReceivedHeader,
    receivedChain,
    relayIndicators,
    heloIdentity,
    spfResult,
    spfMailFromDomain,
    dkimResult,
    dkimHeaderDomain,
    dmarcResult,
    authSummary,
    authResultsTrusted,
    ignoredAuthResultsCount,
    recipientSpamVerdict,
    recipientSpamScore: spamScore ? Number(spamScore) : null,
    recipientSpamSource,
    spoofingLikely,
    senderDomainNote,
    authHeaderFromDomain,
    version: "1.0.8"
  };
};
