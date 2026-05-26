# Message Loupe team product roadmap

## Positioning

Message Loupe should stay free for individual checks and become paid when it saves a business workflow: suspicious-email intake, inbox add-ins, admin visibility, and repeatable payment-risk policy.

Primary buyers:

- Bookkeepers and outsourced finance teams
- Realtors and title-adjacent offices
- Small law firms
- Agencies with client billing access
- Family offices and executive assistants

## Product wedge

The first paid product should not be a consumer subscription. It should be a small-team protection workflow:

1. A branded "send suspicious emails here" address for each customer.
2. Gmail and Outlook add-ins so employees can check the open message from the inbox.
3. A team dashboard that stores verdict metadata only: timestamp, reporter, verdict tier, reason codes, sender domain, and follow-up status.
4. Policy prompts for the expensive mistakes: wire transfers, bank-detail changes, payroll changes, credential requests, and shared-document links.

## Add-in reality check

Google Workspace:

- Google Workspace add-ons can request Gmail-specific scopes for the currently open message.
- Prefer the narrow current-message scopes over broad Gmail read access.
- Marketplace publication will involve OAuth review and least-privilege scrutiny.

Microsoft 365:

- Outlook add-ins can live in read and compose surfaces.
- Event-based activation exists, but automatic/background behavior has platform and admin-deployment constraints.
- The first Outlook version should be a user-invoked task pane button. Smart Alerts and event activation come later.

References:

- Google Workspace add-on scopes: https://developers.google.com/workspace/add-ons/concepts/workspace-scopes
- Gmail add-on manifest docs: https://developers.google.com/apps-script/manifest/gmail-addons
- Outlook event-based activation: https://learn.microsoft.com/en-us/office/dev/add-ins/develop/event-based-activation

## Build order

### Phase 1: Team landing and manual workflow

- Add `/business` to explain the team use case.
- Keep the public scanner free.
- Offer a manual pilot: customer forwards suspicious emails to a branded inbox, and Message Loupe returns or records verdicts.
- Validate who pays before building admin-heavy features.

### Phase 2: Shared verdict backend

- Store only metadata, not email contents.
- Add tenants, users, reports, verdict summaries, and follow-up states.
- Keep raw-email analysis client-side where possible; if server processing becomes necessary for forwarded mail, make retention explicit and short-lived.

### Phase 3: Gmail add-on

- Start with a Workspace add-on that reads only the open message after user action.
- Render a compact card: tier, top reasons, and "verify outside email" instruction.
- Send only verdict metadata to the dashboard after the user chooses to report or save it.
- Prototype scaffold: `integrations/gmail-workspace-addon/`.

### Phase 4: Outlook add-in

- Start with an Outlook task pane command for the selected message.
- Use admin deployment for pilots.
- Add compose/send-time checks later for risky outbound replies, payment changes, and external recipients.
- Prototype scaffold: `integrations/outlook-add-in/`.

## Pricing hypothesis

- Free: public scanner.
- Team: $12 per user per month for add-in, branded report address, verdict history, and export.
- Office: $299 per month for up to 25 users, onboarding help, policy templates, and quarterly scam-pattern review.

The likely buyer cares less about "AI phishing detection" and more about preventing one bad payment. Price against avoided loss and workflow confidence, not against consumer security apps.
