import { isValidPublicIp } from './ipClassifiers.js';
import { matchProvider } from './providers.js';
import { isSecurityGateway } from './securityGateways.js';

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

export const parseEmlLocally = (text) => {
  const [headersPart, ...bodyParts] = text.split(/\r?\n\r?\n/);
  const rawBody = bodyParts.join('\n\n');
  const headerLines = headersPart.split(/\r?\n/);

  const getHeader = (name) => {
    const prefix = `${name.toLowerCase()}:`;
    for (let i = 0; i < headerLines.length; i++) {
      if (headerLines[i].toLowerCase().startsWith(prefix)) {
        let result = headerLines[i].substring(name.length + 1).trim();
        let j = i + 1;
        while (j < headerLines.length && /^\s/.test(headerLines[j])) {
          result += ` ${headerLines[j].trim()}`;
          j++;
        }
        return result;
      }
    }
    return null;
  };

  const getHeaders = (name) => {
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
        results.push(result);
      }
    }
    return results;
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

  const allReceived = getHeaders('Received');
  const spfHeader = getHeader('Received-SPF');
  const authResults = getHeader('Authentication-Results');
  const fromHeader = getHeader('From') || '';
  const toHeader = getHeader('To') || '';
  const returnPath = getHeader('Return-Path')?.replace(/[<>]/g, '') || null;
  const replyToHeader = getHeader('Reply-To') || null;
  const listIdHeader = getHeader('List-Id') || null;
  const sendingEmail = extractEmailAddress(fromHeader) || fromHeader || null;
  const sendingDomain = extractDomain(fromHeader);
  const recipientEmail = extractEmailAddress(toHeader);
  const recipientDomain = extractDomain(toHeader);
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
  const xSpamdResult = getHeader('X-Spamd-Result') || null;
  const xRspamdServer = getHeader('X-Rspamd-Server') || null;
  const xPmSpamAction = getHeader('X-Pm-Spam-Action') || null;
  const hasTrustedRecipientSpamContext = Boolean(
    xSpamdResult &&
    (xPmSpamAction || /(?:rspamd|mailin|proton|recipient|mx[0-9.-]*\.)/i.test(xRspamdServer || ''))
  );
  const spamScore = xSpamdResult?.match(/\[([+-]?\d+(?:\.\d+)?)\s*\//)?.[1] || null;
  const recipientSpamVerdict = xSpam === 'yes' && hasTrustedRecipientSpamContext ? 'spam' : null;
  let recipientSpamSource = null;
  if (recipientSpamVerdict) {
    if (xRspamdServer) {
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

  const ipRegex = /(?:\[|(?:\b))((?:\d{1,3}\.){3}\d{1,3}|(?:[a-fA-F0-9]{1,4}:|:){1,7}[a-fA-F0-9]{1,4})(?:\]|(?:\b))/;

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
    //   2. "(HELO hostname)" / "(EHLO hostname)" — parenthesised SMTP greeting
    //   3. "helo=hostname"                       — Exim / ecelerity etc. style
    sourceHostname = header.match(/from\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/i)?.[1]
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
      const m = header.match(ipRegex);
      if (m && isValidPublicIp(m[1])) {
        sourceIp = m[1];
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

      const match = header.match(ipRegex);
      if (match && isValidPublicIp(match[1])) {
        applySourceHeader(header, match[1], "Received header public IP fallback");
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
      } else if (innerType.includes('text/plain') && !bodyText) {
        bodyText = decodeBody(partBody, encoding);
      } else if (innerType.includes('text/html') && !bodyHtml) {
        bodyHtml = decodeBody(partBody, encoding);
      }
    }
  };

  const mainBoundaryMatch = (getHeader('Content-Type') || '').match(/boundary=(?:"([^"]+)"|([^;\s]+))/i);
  const boundary = mainBoundaryMatch?.[1] || mainBoundaryMatch?.[2];
  if (boundary) processMimeParts(rawBody, boundary);
  else bodyText = decodeBody(rawBody, getHeader('Content-Transfer-Encoding'));

  return {
    subject: getHeader('Subject'),
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
    bodyText,
    bodyHtml,
    hasBodyContent: Boolean(bodyText || bodyHtml),
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
    recipientSpamVerdict,
    recipientSpamScore: spamScore ? Number(spamScore) : null,
    recipientSpamSource,
    spoofingLikely,
    senderDomainNote,
    authHeaderFromDomain,
    version: "1.0.8"
  };
};
