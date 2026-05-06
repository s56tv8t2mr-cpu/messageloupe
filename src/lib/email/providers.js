// Consumer-facing build of the provider knowledge base for Message Loupe.
//
// Detection logic lifted from the SecOps Toolkit, with the analyst-grade
// abuse-routing fields removed: the consumer verdict only needs to identify
// *which* email service likely sent the message, not where to file an abuse
// report. Stripped fields include:
//   - GOOGLE_ABUSE_DOC_URL (internal reference)
//   - per-provider `abuse: { ... }` payloads (analyst tooling)
//
// If you ever need to surface "report this to <abuse@…>" in a future build,
// re-import the full providers module from the toolkit; do not re-introduce
// internal URLs here.

import { isGoogleIp, isMicrosoftIp } from './ipClassifiers.js';

export const PROVIDERS = [
  { name: 'MailerLite',                signatures: ['mlsend.com'] },
  { name: 'SendGrid',                  signatures: ['sendgrid.net'] },
  { name: 'Amazon SES',                signatures: ['amazonses.com'] },
  { name: 'ZeptoMail',                 signatures: ['zeptomail.com'] },
  { name: 'Zoho Mail',                 signatures: ['zoho.com'] },
  { name: 'Mailgun',                   signatures: ['mailgun.org', 'mailgun.net'] },
  { name: 'SparkPost',                 signatures: ['sparkpostmail.com'] },
  { name: 'Mailchimp',                 signatures: ['mandrillapp.com', 'mcsv.net', 'mcdlv.net', 'mailchimp.com'] },
  { name: 'HubSpot',                   signatures: ['hubspotemail.net', 'hubspot.com'] },
  { name: 'Constant Contact',          signatures: ['constantcontact.com', 'ccsend.com', 'confirmedcc.com', 'rs6.net'] },
  { name: 'Campaign Monitor',          signatures: ['createsend.com', 'cmail1.com'] },
  { name: 'Brevo (Sendinblue)',        signatures: ['sendinblue.com', 'brevo.com'] },
  { name: 'Klaviyo',                   signatures: ['klaviyomail.com', 'klaviyo.com'] },
  { name: 'Postmark',                  signatures: ['postmarkapp.com'] },
  { name: 'Mailjet',                   signatures: ['mailjet.com'] },
  { name: 'Elastic Email',             signatures: ['elasticemail.com'] },
  { name: 'Salesforce / ExactTarget',  signatures: ['exacttarget.com', 'salesforce.com'] },
  { name: 'Marketo',                   signatures: ['mktomail.com', 'marketo.com'] },
  {
    detect: (parts) => (
      parts.lowerMsgId.includes('mail.gmail.com')
      || parts.lowerSourceHeader.includes('gmailapi.google.com')
      || isGoogleIp(parts.sourceIp || '')
    ),
    nameFor: (parts) => (
      parts.sendingDomain === 'gmail.com' || parts.returnPathDomain === 'gmail.com'
        ? 'Gmail (Consumer)'
        : 'Google Workspace'
    )
  },
  {
    name: 'Microsoft 365 / Outlook',
    detect: (parts) => (
      parts.lowerSourceHostname.includes('outlook.com')
      || parts.lowerSourceHostname.includes('office365.com')
      || parts.lowerSourceHostname.includes('protection.outlook.com')
      || isMicrosoftIp(parts.sourceIp || '')
    )
  }
];

export const matchProvider = (parts) => {
  for (const provider of PROVIDERS) {
    const matched = provider.signatures
      ? provider.signatures.some((sig) => parts.senderEvidence.includes(sig))
      : Boolean(provider.detect && provider.detect(parts));
    if (matched) {
      const name = provider.nameFor ? provider.nameFor(parts) : provider.name;
      return { name };
    }
  }
  return null;
};
