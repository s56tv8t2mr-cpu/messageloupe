Office.onReady(function () {
  var item = Office.context && Office.context.mailbox && Office.context.mailbox.item;

  if (!item) {
    setText("status", "No selected message is available.");
    return;
  }

  setText("status", "Selected message loaded.");
  setText("subject", item.subject || "(no subject)");

  if (item.from && item.from.displayName) {
    setText("from", item.from.displayName + " <" + item.from.emailAddress + ">");
  } else {
    setText("from", "(sender unavailable)");
  }
});

function setText(id, value) {
  var element = document.getElementById(id);
  if (element) {
    element.textContent = value;
  }
}
