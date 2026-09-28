/**
 * Secure & Grow — Workshop & Services Questionnaire
 *
 * Builds the Google Form (with routing) in your Google account.
 *
 * HOW TO RUN (one time, ~2 minutes):
 *   1. Go to https://script.google.com  ->  New project.
 *   2. Delete the sample code, paste this whole file, and save.
 *   3. Put your Eventbrite link in EVENTBRITE_URL below.
 *   4. Pick the function "createSecureAndGrowForm" in the toolbar and click Run.
 *      Approve the permission prompt (Forms + Sheets, for the responses sheet).
 *   5. Open View > Logs (or Execution log) for the form's edit + share links.
 *
 * ROUTING (question "What do you want to learn?"):
 *   Just want to learn anything AI  -> Eventbrite page, then submit
 *   Need a new website              -> Voice & brand + Website prompts, then submit
 *   Need help automating my business -> Automation prompts, then submit
 *
 * Google Forms cannot redirect to an outside site after submit, so the AI
 * branch shows the Eventbrite link on its own page before the form submits.
 */

var EVENTBRITE_URL = 'PASTE_YOUR_EVENTBRITE_URL_HERE';

function createSecureAndGrowForm() {
  var form = FormApp.create('Secure & Grow: Workshop & Services Questionnaire');

  form
    .setDescription(
      'Tell us what you are looking for and we will point you to the right next step.\n\n' +
      'Your answers are used only to follow up with you. Privacy policy: https://www.techinpeace.com/privacy'
    )
    .setConfirmationMessage(
      'Thank you! We have your answers and will follow up by email. ' +
      'Questions? Write to support@cyberprotectionconsultingservices.com.'
    )
    .setProgressBar(true)
    .setShowLinkToRespondAgain(false)
    .setAllowResponseEdits(false)
    .setCollectEmail(false);

  // ---------------------------------------------------------------- Page 1
  var emailValidation = FormApp.createTextValidation()
    .requireTextIsEmail()
    .setHelpText('Please enter a valid email address.')
    .build();

  form.addTextItem()
    .setTitle('Email')
    .setHelpText('Where should we send your follow-up?')
    .setValidation(emailValidation)
    .setRequired(true);

  form.addParagraphTextItem()
    .setTitle('Any regulated or sensitive topics to avoid? (health, financial, legal claims)')
    .setHelpText('For example: no medical claims, no income promises, no legal advice. Leave blank if none.')
    .setRequired(false);

  // Choices are filled in after the pages exist (navigation needs the page objects).
  var learn = form.addMultipleChoiceItem();
  learn.setTitle('What do you want to learn?').setRequired(true);
  learn.setChoices([learn.createChoice('placeholder')]);

  // ------------------------------------------------- Page: AI -> Eventbrite
  var pageAI = form.addPageBreakItem()
    .setTitle('Learn AI with us')
    .setHelpText(
      'Our AI workshops are the best place to start. Reserve your seat here:\n\n' +
      EVENTBRITE_URL + '\n\n' +
      'Open the link above to register. You can submit this form afterwards, or simply close it.'
    );

  // ------------------------------------------- Page: New website branch
  var pageWeb = form.addPageBreakItem()
    .setTitle('A new website')
    .setHelpText('A few questions so your site sounds like you and does its job.');

  // Ends the AI page: when the flow reaches the Website page linearly, submit instead.
  pageWeb.setGoToPage(FormApp.PageNavigationType.SUBMIT);

  form.addSectionHeaderItem()
    .setTitle('Voice and brand');

  form.addTextItem()
    .setTitle('Three words that describe your tone')
    .setHelpText('For example: warm, direct, playful.')
    .setRequired(true);

  form.addParagraphTextItem()
    .setTitle('Words or phrases you always use. Words you never use.')
    .setHelpText('Always use: ...    Never use: ...')
    .setRequired(false);

  form.addParagraphTextItem()
    .setTitle('Paste a short sample of writing that sounds like you')
    .setHelpText('An email, a post, or a paragraph from your current site.')
    .setRequired(false);

  form.addSectionHeaderItem()
    .setTitle('Website prompts');

  form.addCheckboxItem()
    .setTitle('What pages do you need?')
    .setChoiceValues(['Home', 'About', 'Services', 'Pricing', 'Contact', 'FAQ'])
    .showOtherOption(true)
    .setRequired(false);

  form.addParagraphTextItem()
    .setTitle('What is the one action you want a visitor to take?')
    .setHelpText('For example: book a call, buy a product, join a list.')
    .setRequired(true);

  form.addCheckboxItem()
    .setTitle('Any proof to include?')
    .setChoiceValues(['Testimonials', 'Credentials', 'Results', 'Logos'])
    .showOtherOption(true)
    .setRequired(false);

  // -------------------------------------------- Page: Automation branch
  var pageAuto = form.addPageBreakItem()
    .setTitle('Automating your business')
    .setHelpText('Tell us how your work runs today so we can find the quickest wins.');

  // Ends the Website page: when the flow reaches the Automation page linearly, submit.
  pageAuto.setGoToPage(FormApp.PageNavigationType.SUBMIT);

  form.addCheckboxItem()
    .setTitle('Which tools do you use daily?')
    .setChoiceValues(['Email', 'Calendar', 'CRM', 'Invoicing', 'Social', 'Docs'])
    .showOtherOption(true)
    .setRequired(false);

  form.addParagraphTextItem()
    .setTitle('List the three tasks you repeat most often each week')
    .setRequired(true);

  form.addParagraphTextItem()
    .setTitle('What happens when a new lead contacts you? Walk me through it step by step.')
    .setRequired(false);

  form.addParagraphTextItem()
    .setTitle('Where does work fall through the cracks right now?')
    .setRequired(false);
  // The Automation page is the last page, so the form submits after it.

  // ---------------------------------------------------------- Routing
  learn.setChoices([
    learn.createChoice('Just want to learn anything AI', pageAI),
    learn.createChoice('Need a new website', pageWeb),
    learn.createChoice('Need help automating my business', pageAuto)
  ]);

  // ------------------------------------------------ Responses spreadsheet
  var sheet = SpreadsheetApp.create('Secure & Grow Questionnaire: Responses');
  form.setDestination(FormApp.DestinationType.SPREADSHEET, sheet.getId());

  if (EVENTBRITE_URL.indexOf('PASTE_') === 0) {
    Logger.log('REMINDER: EVENTBRITE_URL is still a placeholder. Edit the "Learn AI with us" page text in the form.');
  }
  Logger.log('EDIT the form:    ' + form.getEditUrl());
  Logger.log('SHARE this link:  ' + form.getPublishedUrl());
  Logger.log('RESPONSES sheet:  ' + sheet.getUrl());
}
