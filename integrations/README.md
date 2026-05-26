# Message Loupe integrations

This folder holds prototype add-in work for the team product. Nothing here is shipped to production by the Next.js static export unless a later milestone explicitly wires it into `src/` or `public/`.

## Current direction

- Gmail: Google Workspace add-on built with Apps Script, starting with user-invoked current-message review.
- Outlook: Microsoft 365 Outlook task pane add-in, starting with a ribbon command in message-read mode.
- Dashboard: later milestone; store verdict metadata only, not email contents.

## Guardrails

- Do not claim these add-ins are available until they have been installed and tested in real Google Workspace and Microsoft 365 tenants.
- Prefer narrow current-message permissions.
- Do not store raw email bodies or headers in any shared dashboard without an explicit retention policy.
- Treat automated send-time or event-based checks as later work after the manual add-in surfaces are proven.
