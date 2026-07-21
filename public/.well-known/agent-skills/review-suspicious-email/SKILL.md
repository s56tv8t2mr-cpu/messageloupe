---
name: review-suspicious-email
description: Guide a user to privately check a suspicious email with Message Loupe, preserve original headers, and interpret the result. Use when the user asks whether an email may be phishing, spoofed, or business email compromise.
---

# Review a suspicious email with Message Loupe

## Protect the user's privacy

- Do not ask the user to paste the email into the conversation or send it to another service.
- Direct the user to [Message Loupe](https://messageloupe.com/), where parsing and verdict analysis run in their browser.
- The optional DNS and RDAP checks may send only the visible sender domain. They do not send the message, headers, links, or verdict.

## Obtain the original message

A regular forward is not sufficient because it replaces the original delivery headers. Ask the user to save the original message as an `.eml` file by following [How to save an email](https://messageloupe.com/how-to-save-an-email/).

## Run the private check

1. Ask the user to open [Message Loupe](https://messageloupe.com/).
2. Have the user drop the saved `.eml` file onto the page, or paste the original raw message directly into the page.
3. Wait for Message Loupe to finish its local analysis.
4. Ask the user to share only the displayed verdict level if they want help understanding what it means.

## Interpret the result

- **No warning signs:** Message Loupe did not detect a warning sign, but the message is not guaranteed safe.
- **Caution:** The user should independently verify the request, especially before sending money, changing payment details, entering credentials, or opening a link.
- **Likely fake:** The message shows strong evidence of impersonation, spoofing, or another deceptive pattern. The user should not act on it through the message.

Never describe a verdict as a guarantee. A real, authenticated account can still be compromised, so Message Loupe may not detect every business email compromise. Refer to the [methodology](https://messageloupe.com/methodology/) for the checked signals and deliberate limitations.

## Escalate consequential requests

For money, payment-detail, payroll, gift-card, or credential requests, tell the user to verify through an independently sourced phone number or another trusted channel. Do not use contact details supplied by the suspicious message.
