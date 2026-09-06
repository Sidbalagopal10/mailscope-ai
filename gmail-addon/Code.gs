const APP = {
  NAME: "AI Email Security",
  ACTIVE_KEY: "protection_active"
};


function onHomepage(e) {
  return buildHomepageCard();
}


function buildHomepageCard() {
  const active = isProtectionActive();

  const header = CardService
    .newCardHeader()
    .setTitle(APP.NAME)
    .setSubtitle(
      "Gmail security and phishing protection"
    );

  const statusSection = CardService
    .newCardSection()
    .setHeader("Protection");

  statusSection.addWidget(
    CardService
      .newDecoratedText()
      .setTopLabel("Current status")
      .setText(
        active
          ? "ACTIVE"
          : "PAUSED"
      )
  );

  statusSection.addWidget(
    CardService
      .newTextParagraph()
      .setText(
        active
          ? "Protection is active. Email analysis will be added in the next module."
          : "Protection is paused. Activate it to prepare the add-on for email analysis."
      )
  );

  const toggleAction = CardService
    .newAction()
    .setFunctionName(
      active
        ? "pauseProtection"
        : "activateProtection"
    );

  statusSection.addWidget(
    CardService
      .newTextButton()
      .setText(
        active
          ? "Pause Protection"
          : "Activate Protection"
      )
      .setTextButtonStyle(
        CardService.TextButtonStyle.FILLED
      )
      .setOnClickAction(
        toggleAction
      )
  );

  const navigationSection = CardService
    .newCardSection()
    .setHeader("Security Center");

  navigationSection.addWidget(
    createNavigationButton(
      "Dashboard",
      "openDashboard"
    )
  );

  navigationSection.addWidget(
    createNavigationButton(
      "Recent Scans",
      "openRecentScans"
    )
  );

  navigationSection.addWidget(
    createNavigationButton(
      "Trusted Domains",
      "openTrustedDomains"
    )
  );

  navigationSection.addWidget(
    createNavigationButton(
      "Settings",
      "openSettings"
    )
  );

  const informationSection = CardService
    .newCardSection()
    .setHeader("Free local version");

  informationSection.addWidget(
    CardService
      .newTextParagraph()
      .setText(
        "This Gmail add-on uses Google Apps Script and does not require Google Cloud billing. Advanced Python machine-learning features will remain available through the optional local companion application."
      )
  );

  return CardService
    .newCardBuilder()
    .setHeader(header)
    .addSection(statusSection)
    .addSection(navigationSection)
    .addSection(informationSection)
    .build();
}


function createNavigationButton(
  text,
  functionName
) {
  const action = CardService
    .newAction()
    .setFunctionName(
      functionName
    );

  return CardService
    .newTextButton()
    .setText(text)
    .setOnClickAction(action)
    .setTextButtonStyle(
      CardService.TextButtonStyle.TEXT
    );
}


function activateProtection() {
  PropertiesService
    .getUserProperties()
    .setProperty(
      APP.ACTIVE_KEY,
      "true"
    );

  return updateCurrentCard(
    buildHomepageCard()
  );
}


function pauseProtection() {
  PropertiesService
    .getUserProperties()
    .setProperty(
      APP.ACTIVE_KEY,
      "false"
    );

  return updateCurrentCard(
    buildHomepageCard()
  );
}


function isProtectionActive() {
  return (
    PropertiesService
      .getUserProperties()
      .getProperty(
        APP.ACTIVE_KEY
      ) === "true"
  );
}


function updateCurrentCard(card) {
  return CardService
    .newActionResponseBuilder()
    .setNavigation(
      CardService
        .newNavigation()
        .updateCard(card)
    )
    .build();
}


function pushCard(card) {
  return CardService
    .newActionResponseBuilder()
    .setNavigation(
      CardService
        .newNavigation()
        .pushCard(card)
    )
    .build();
}


function buildPlaceholderCard(
  title,
  description
) {
  const section = CardService
    .newCardSection()
    .addWidget(
      CardService
        .newTextParagraph()
        .setText(description)
    );

  return CardService
    .newCardBuilder()
    .setHeader(
      CardService
        .newCardHeader()
        .setTitle(title)
        .setSubtitle(APP.NAME)
    )
    .addSection(section)
    .build();
}


function openDashboard() {
  return pushCard(
    buildPlaceholderCard(
      "Daily Security Dashboard",
      "Daily email totals, risk distribution, phishing detections, suspicious links, and attachment alerts will appear here."
    )
  );
}


function openRecentScans() {
  return pushCard(
    buildPlaceholderCard(
      "Recent Scans",
      "Recent analyzed Gmail messages and their risk verdicts will appear here."
    )
  );
}


function openTrustedDomains() {
  return pushCard(
    buildPlaceholderCard(
      "Trusted Domains",
      "Trusted, neutral, unknown, suspicious, and blocked domain controls will appear here."
    )
  );
}


function openSettings() {
  return pushCard(
    buildPlaceholderCard(
      "Settings",
      "Automatic scanning, Gmail labels, feedback, privacy, and local companion settings will appear here."
    )
  );
}
