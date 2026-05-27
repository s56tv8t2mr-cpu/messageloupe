/* eslint-disable @typescript-eslint/no-unused-vars */
/* global CardService, GmailApp */

function buildHomepage() {
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle("Message Loupe"))
    .addSection(
      CardService.newCardSection()
        .addWidget(CardService.newTextParagraph().setText("Open an email to review it with Message Loupe."))
        .addWidget(CardService.newTextParagraph().setText("Prototype status: add-in surface only. Verdict logic is not wired in yet."))
    )
    .build();
}

function onGmailMessageOpen(e) {
  const message = getCurrentMessage_(e);

  if (!message) {
    return CardService.newCardBuilder()
      .setHeader(CardService.newCardHeader().setTitle("Message Loupe"))
      .addSection(
        CardService.newCardSection().addWidget(
          CardService.newTextParagraph().setText("Gmail did not provide current-message access for this item.")
        )
      )
      .build();
  }

  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle("Message Loupe").setSubtitle("Current message prototype"))
    .addSection(
      CardService.newCardSection()
        .addWidget(keyValue_("From", message.getFrom()))
        .addWidget(keyValue_("Subject", message.getSubject() || "(no subject)"))
        .addWidget(keyValue_("Date", String(message.getDate())))
    )
    .addSection(
      CardService.newCardSection()
        .addWidget(CardService.newTextParagraph().setText("Next step: pass this message through the Message Loupe analyzer and show Safe / Caution / Likely Fake here."))
    )
    .build();
}

function getCurrentMessage_(e) {
  const gmailEvent = (e && (e.gmail || e.messageMetadata)) || {};
  const accessToken = gmailEvent.accessToken;
  const messageId = gmailEvent.messageId;

  if (!accessToken || !messageId) {
    return null;
  }

  GmailApp.setCurrentMessageAccessToken(accessToken);
  return GmailApp.getMessageById(messageId);
}

function keyValue_(topLabel, content) {
  return CardService.newKeyValue()
    .setTopLabel(topLabel)
    .setContent(String(content || ""));
}
