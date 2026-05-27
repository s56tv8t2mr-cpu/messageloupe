const officeHost = globalThis.Office;

if (officeHost) {
  officeHost.onReady(function () {
    const item = officeHost.context?.mailbox?.item;

    if (!item) {
      setText("status", "No selected message is available.");
      return;
    }

    setText("status", "Selected message loaded.");
    setText("subject", item.subject || "(no subject)");

    if (item.from?.displayName) {
      setText("from", item.from.displayName + " <" + item.from.emailAddress + ">");
    } else {
      setText("from", "(sender unavailable)");
    }
  });
} else {
  setText("status", "Office.js is not loaded. Add the hosted Office.js script when sideloading this prototype.");
}

function setText(id, value) {
  const element = document.getElementById(id);
  if (element) {
    element.textContent = value;
  }
}
