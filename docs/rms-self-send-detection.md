# RMS Self-Send Detection

Detection rule that catches compromised-mailbox phishing where an attacker
uses a real Microsoft 365 account to send rights-protected email to itself.

## Problem

A real-world phishing email arrived from `epowers@raleighcountyfcu.com` to
`epowers@raleighcountyfcu.com` — same address on both sides — with the
body encrypted via Microsoft Rights Management (`Content-Class:
rpmsg.message`). Message Loupe rated it **Safe / "Looks legitimate"** with
zero reasons in the verdict.

The email was a known compromised-account phish. The attacker had popped
the real Raleigh County FCU M365 mailbox and was using RMS encryption to
hide a fake "click to read message" Microsoft login form from any content
scanner downstream.

Why every existing signal stayed silent:

| Check | Result | Why it didn't fire |
| --- | --- | --- |
| SPF | `pass` | Email genuinely came from the real Microsoft 365 tenant |
| DKIM | `none` | Org has no DKIM; not a `fail`, so no signal |
| DMARC | `none` | Org has no DMARC policy; not a `fail`, so no signal |
| Reply-To mismatch | — | No `Reply-To` header at all |
| Brand impersonation | — | Display name matches the actual From domain |
| Suspicious links | — | Body is RMS-encrypted; analyzer can't see it |
| Money/credentials cap | — | Body is RMS-encrypted; classifier can't see it |
| Forward heuristics | — | Headers look like a normal direct send |

Authentication-based detection cannot catch this class on its own:
authentication is passing because the message **really is** from the
domain's real tenant. The user has been compromised, not the domain.

## Solution

A new high-weight verdict reason, `rms-self-send`, fires when **both** of
the following hold:

1. `From` mailbox (normalized, case-insensitive) equals `To` mailbox.
2. `Content-Class: rpmsg.message` is present (Outlook RMS marker).

Either condition alone is benign — people email themselves notes; orgs
use RMS for legitimate internal traffic. The combination is the tell.
Legitimate users do not send themselves rights-protected mail as a
workflow. Encrypted self-send is, in practice, an attacker workflow: it
puts the malicious payload (a credential-harvesting page rendered when
the recipient unlocks the message) into a container the analyzer cannot
read while routing it through a real tenant whose auth passes cleanly.

When both conditions are met, the verdict escalates to **danger** with
the explanation surfaced to the user.

## Why the false-positive rate is acceptable

- **Sysadmin RMS template testing** — rare, low-volume, and unlikely to
  be pasted into a phishing analyzer.
- **"Backup to self" automation** — would not typically use RMS
  encryption; unencrypted self-send remains unflagged.
- **Legitimate intra-org RMS to other recipients** — unaffected; the
  rule requires the recipient mailbox to match the sender.

## Implementation

- `src/lib/email/parser.js` — extracts `recipientEmail`, `recipientDomain`,
  and `contentClass` from headers.
- `src/lib/email/types.ts` — adds the three fields to `ParserResult`.
- `src/lib/email/verdict.ts` — emits the `rms-self-send` reason and
  escalates the tier.
- `src/lib/email/__tests__/fixtures/raleighcountyfcu-rms-self-send.eml`
  — the real-world fixture, kept as a permanent regression case.
- `src/lib/email/__tests__/verdict.test.ts` — covers the positive case,
  both negative cases (each condition alone), and case-insensitive
  mailbox matching.

## Future work

- Broaden the encrypted-payload check to other RMS containers (e.g. MIME
  type `application/x-microsoft-rpmsg-message`, S/MIME, PGP-self-send).
- Surface a lower-severity "cannot inspect" caveat when RMS is present
  but the rest of the message looks clean, so users know the verdict
  didn't see the body.
- When a real DMARC pass + matching DKIM signature is present, consider
  softening the verdict from danger to caution — the encryption is still
  unusual, but the auth attestation raises the cost of impersonation.
