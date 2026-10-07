/*
 * demo-emails.js
 * Completely fictional sample emails for learning and testing.
 * They use only reserved / placeholder domains (example.com, .test, .invalid)
 * and NON-WORKING links. None of these addresses or domains are real or
 * malicious - they exist purely to demonstrate the analyser.
 */
(function (root) {
  'use strict';

  var DEMO_EMAILS = [
    {
      id: 'obvious',
      label: 'Obvious phishing',
      hint: 'High Risk',
      text:
'From: "PayPal Security Team" <security@paypal-account-verify.tk>\n' +
'Reply-To: reclaim@mail-paypa1.tk\n' +
'To: victim@example.com\n' +
'Subject: URGENT: Your PayPal account will be suspended within 24 hours!\n' +
'\n' +
'Dear Customer,\n' +
'\n' +
'We have detected unusual activity on your PayPal account. Your account has\n' +
'been temporarily limited and will be permanently suspended within 24 hours\n' +
'unless you confirm your identity immediately.\n' +
'\n' +
'To restore access, click the link below and enter your password and the\n' +
'6-digit verification code we sent to your phone:\n' +
'\n' +
'    http://192.168.4.21/paypal/login.php\n' +
'\n' +
'Failure to act now will result in account closure. This is your final notice.\n' +
'\n' +
'PayPal Security Team'
    },
    {
      id: 'sophisticated',
      label: 'Sophisticated phishing',
      hint: 'Suspicious',
      text:
'From: "Sarah Whitfield" <s.whitfield@acme-corp.com>\n' +
'Reply-To: finance@acme-corp.com\n' +
'To: James Okafor <james.okafor@example.com>\n' +
'Subject: Re: Q3 supplier payment update\n' +
'\n' +
'Hi James,\n' +
'\n' +
'Following our call this morning, please find the revised payment details for\n' +
'the Wexford Supplies account below. Our finance team has changed banks, so the\n' +
'old account number is no longer in use.\n' +
'\n' +
'New account number: 44219803\n' +
'Sort code: 20-41-77\n' +
'\n' +
'Please update our record before processing the invoice due on Friday.\n' +
'\n' +
'Thanks,\n' +
'Sarah'
    },
    {
      id: 'microsoft',
      label: 'Fake Microsoft 365 warning',
      hint: 'High Risk',
      text:
'From: "Microsoft 365" <no-reply@micros0ft-security.com>\n' +
'To: user@example.com\n' +
'Subject: Action required: your Microsoft 365 password expires today\n' +
'\n' +
'Your Microsoft 365 password will expire today. To keep using your account you\n' +
'must verify your account and update your password now.\n' +
'\n' +
'Verify your account here:\n' +
'    https://micros0ft-security.com/owa/auth/login\n' +
'\n' +
'If you do not verify within 2 hours, your mailbox will be locked.\n' +
'\n' +
'Microsoft 365 Security Team'
    },
    {
      id: 'parcel',
      label: 'Fake parcel delivery',
      hint: 'High Risk',
      text:
'From: "DHL Express" <tracking@dhl-express-parcel.test>\n' +
'To: recipient@example.com\n' +
'Subject: Your parcel DHL-8842-XP could not be delivered\n' +
'\n' +
'Hello,\n' +
'\n' +
'We attempted to deliver your parcel today but no one was available. Your\n' +
'parcel will be returned to sender unless you reschedule delivery within\n' +
'24 hours.\n' +
'\n' +
'Track your parcel: https://dhl-express-parcel.test/track/DHL-8842-XP\n' +
'\n' +
'A small redelivery fee of 1.99 GBP is required. Pay here:\n' +
'    http://bit.ly/3xParcelDHL\n' +
'\n' +
'Thank you,\n' +
'DHL Express Delivery Team'
    },
    {
      id: 'invoice',
      label: 'Fake invoice / BEC',
      hint: 'High Risk',
      text:
'From: "Accounts Payable" <billing@secure-invoices-portal.com>\n' +
'Reply-To: payments@secure-invoices-portal.com\n' +
'To: finance@example.com\n' +
'Subject: Overdue invoice #INV-20931 - immediate payment required\n' +
'\n' +
'Dear Sir,\n' +
'\n' +
'Please find attached the overdue invoice for services rendered. Our records\n' +
'show your account balance is outstanding and payment is now overdue.\n' +
'\n' +
'Invoice details are in the attached file: Invoice_INV-20931.pdf.exe\n' +
'\n' +
'Kindly remit payment via wire transfer to the account below and update our\n' +
'bank details for future invoices.\n' +
'\n' +
'Bank: First National\n' +
'Account number: 88392011\n' +
'Sort code: 40-12-99\n' +
'\n' +
'Failure to pay may result in legal action.\n' +
'\n' +
'Regards,\n' +
'Accounts Payable'
    },
    {
      id: 'legitimate',
      label: 'Legitimate email',
      hint: 'Low Risk',
      text:
'From: "Priya Raman" <priya.raman@contoso.com>\n' +
'To: James Okafor <james.okafor@contoso.com>\n' +
'Subject: Notes from Tuesday planning meeting\n' +
'\n' +
'Hi James,\n' +
'\n' +
'Thanks for joining the planning call on Tuesday. I have summarised the key\n' +
'points below so we have a record.\n' +
'\n' +
'1. We will keep the current roadmap for Q3 and revisit staffing in October.\n' +
'2. You will own the client onboarding checklist; I will draft the risk register.\n' +
'3. Next catch-up is provisionally set for the 14th at 10:00.\n' +
'\n' +
'The shared notes are in our usual internal drive (search for "Q3 planning").\n' +
'No action needed right now - just flag anything you would change.\n' +
'\n' +
'Best,\n' +
'Priya'
    }
  ];

  root.DEMO_EMAILS = DEMO_EMAILS;
  if (typeof module !== 'undefined' && module.exports) module.exports = DEMO_EMAILS;
})(typeof globalThis !== 'undefined' ? globalThis : this);
