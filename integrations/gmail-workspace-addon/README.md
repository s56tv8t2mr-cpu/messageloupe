# Gmail Workspace add-on prototype

This is a starter Google Workspace add-on for Gmail. It is not published and is not connected to the production scanner yet.

## Why this path

Google Workspace add-ons can run inside Gmail and request temporary access to the currently open message. The production version should use the least permissive current-message scopes possible and avoid broad Gmail access.

## Files

- `appsscript.json`: Apps Script manifest with Gmail contextual trigger and current-message scopes.
- `Code.js`: Card-based prototype that reads the currently open message after Gmail grants a short-lived access token.

## Local setup

1. Create a new Apps Script project.
2. Enable "Show appsscript.json manifest file" in Project Settings.
3. Paste `appsscript.json` and `Code.js` into the project.
4. Test as a Google Workspace add-on in Gmail.

## Next implementation step

Replace the placeholder card with a compact Message Loupe verdict. The hard part is converting Gmail message access into the same RFC-822-like input expected by the existing analyzer without widening scopes or sending message contents to a server.

References:

- https://developers.google.com/workspace/add-ons/concepts/workspace-scopes
- https://developers.google.com/apps-script/manifest/gmail-addons
