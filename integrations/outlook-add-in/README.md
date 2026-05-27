# Outlook add-in prototype

This is a starter Outlook task pane add-in. It is not published, not admin-deployed, and not part of the production static site yet.

## Why this path

The first Outlook version should be user-invoked from the message-read surface. That avoids overpromising automatic protection and keeps the initial install/testing path straightforward for Microsoft 365 pilots.

## Files

- `manifest.sample.xml`: add-in-only manifest with a Message Read command.
- `taskpane.html`: minimal task pane UI.
- `taskpane.js`: Office.js prototype that reads basic selected-message fields.
- `public/add-in-icons/`: PNG icons referenced by the Outlook manifest.

The sample HTML intentionally does not load the hosted Office.js script directly.
When this moves from scaffold to a real sideloaded add-in, serve the task pane from
the app and follow Microsoft's current Office.js loading guidance for that host.

## Next implementation step

Serve `taskpane.html` over HTTPS, update the manifest URLs, sideload in Outlook, and verify it can read the selected message in Outlook on the web, new Outlook for Windows, and classic Outlook where available.

References:

- https://learn.microsoft.com/en-us/outlook/add-ins/quick-start
- https://learn.microsoft.com/en-us/office/dev/add-ins/develop/event-based-activation
