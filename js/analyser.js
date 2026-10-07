/*
 * analyser.js
 * The detection engine. It scans pasted email text for common phishing and
 * social-engineering warning signs and returns a fully explainable list of
 * findings. Every finding is a named indicator with a fixed point value, a
 * plain-English explanation, and the exact text that triggered it.
 *
 * Nothing here talks to the network. It is pure text processing that runs in
 * the visitor's browser (and can also be loaded in Node for testing).
 */
(function (root) {
  'use strict';

  var Scoring = (typeof module !== 'undefined' && module.exports)
    ? require('./scoring.js')
    : root.PhishingScoring;

  /* ------------------------------------------------------------------ *
   * Data tables
   * ------------------------------------------------------------------ */

  // Well-known link-shortening services. A short link hides its real target.
  var SHORTENERS = [
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
    'rebrand.ly', 'cutt.ly', 'shorturl.at', 'rb.gy', 'tiny.cc', 'lnkd.in',
    't.ly', 'bl.ink', 'short.io', 'adf.ly', 's.id', 'soo.gd', 'shorte.st',
    'bit.do', 'qr.ae', 'v.gd', 'clck.ru', 'u.to'
  ];

  // Top-level domains that are frequently abused because they are cheap or free.
  var SUSPICIOUS_TLDS = [
    '.tk', '.ml', '.ga', '.cf', '.gq', '.zip', '.mov', '.top', '.xyz', '.click',
    '.link', '.country', '.kim', '.work', '.loan', '.men', '.review', '.stream',
    '.gdn', '.icu', '.rest', '.cam', '.surf', '.quest', '.cfd', '.sbs', '.lol',
    '.monster', '.buzz', '.cyou', '.best', '.bar', '.beauty'
  ];

  // Brands commonly impersonated, with the domains they actually use.
  // hostKeys are matched against URL hostnames; textKeys against free text.
  var BRANDS = [
    { name: 'Microsoft', hostKeys: ['microsoft', 'outlook', 'onedrive', 'sharepoint', 'office365'],
      textKeys: ['microsoft', 'office ?365', 'office365', 'outlook', 'onedrive', 'sharepoint', 'windows', 'azure'],
      domains: ['microsoft.com', 'office.com', 'office365.com', 'live.com', 'outlook.com', 'microsoftonline.com', 'windows.com', 'sharepoint.com'] },
    { name: 'Apple', hostKeys: ['apple', 'icloud'],
      textKeys: ['apple', 'icloud', 'apple ?id'],
      domains: ['apple.com', 'icloud.com', 'me.com'] },
    { name: 'Google', hostKeys: ['google', 'gmail'],
      textKeys: ['google', 'gmail'],
      domains: ['google.com', 'gmail.com', 'googlemail.com', 'youtube.com'] },
    { name: 'PayPal', hostKeys: ['paypal'],
      textKeys: ['paypal'],
      domains: ['paypal.com', 'paypal.co.uk', 'paypal.me'] },
    { name: 'Amazon', hostKeys: ['amazon'],
      textKeys: ['amazon'],
      domains: ['amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.ca', 'amazon.in'] },
    { name: 'Netflix', hostKeys: ['netflix'], textKeys: ['netflix'], domains: ['netflix.com'] },
    { name: 'Facebook', hostKeys: ['facebook'], textKeys: ['facebook', 'meta'],
      domains: ['facebook.com', 'meta.com', 'fb.com'] },
    { name: 'Instagram', hostKeys: ['instagram'], textKeys: ['instagram'], domains: ['instagram.com'] },
    { name: 'WhatsApp', hostKeys: ['whatsapp'], textKeys: ['whatsapp'], domains: ['whatsapp.com'] },
    { name: 'Chase', hostKeys: ['chase'], textKeys: ['chase bank', 'jpmorgan'], domains: ['chase.com', 'jpmorgan.com'] },
    { name: 'Bank of America', hostKeys: ['bankofamerica'], textKeys: ['bank of america'], domains: ['bankofamerica.com'] },
    { name: 'Wells Fargo', hostKeys: ['wellsfargo'], textKeys: ['wells fargo'], domains: ['wellsfargo.com'] },
    { name: 'HSBC', hostKeys: ['hsbc'], textKeys: ['hsbc'], domains: ['hsbc.com', 'hsbc.co.uk'] },
    { name: 'Barclays', hostKeys: ['barclays'], textKeys: ['barclays'], domains: ['barclays.co.uk'] },
    { name: 'DHL', hostKeys: ['dhl'], textKeys: ['dhl'], domains: ['dhl.com'] },
    { name: 'FedEx', hostKeys: ['fedex'], textKeys: ['fedex'], domains: ['fedex.com'] },
    { name: 'UPS', hostKeys: ['ups'], textKeys: ['ups parcel', 'ups delivery', 'united parcel'], domains: ['ups.com'] },
    { name: 'USPS', hostKeys: ['usps'], textKeys: ['usps'], domains: ['usps.com'] },
    { name: 'Royal Mail', hostKeys: ['royalmail'], textKeys: ['royal mail'], domains: ['royalmail.com'] },
    { name: 'Dropbox', hostKeys: ['dropbox'], textKeys: ['dropbox'], domains: ['dropbox.com'] },
    { name: 'Adobe', hostKeys: ['adobe'], textKeys: ['adobe'], domains: ['adobe.com'] },
    { name: 'LinkedIn', hostKeys: ['linkedin'], textKeys: ['linkedin'], domains: ['linkedin.com'] },
    { name: 'DocuSign', hostKeys: ['docusign'], textKeys: ['docusign'], domains: ['docusign.com', 'docusign.net'] },
    { name: 'Coinbase', hostKeys: ['coinbase'], textKeys: ['coinbase'], domains: ['coinbase.com'] },
    { name: 'HMRC', hostKeys: ['hmrc'], textKeys: ['hmrc', 'hm revenue'], domains: ['gov.uk', 'hmrc.gov.uk'] },
    { name: 'IRS', hostKeys: ['irs'], textKeys: ['irs tax', 'internal revenue'], domains: ['irs.gov'] }
  ];

  /* ------------------------------------------------------------------ *
   * Reusable patterns
   * ------------------------------------------------------------------ */

  var RE_URGENCY = /\b(urgent(?:ly)?|immediately|act now|act fast|act immediately|right away|as soon as possible|asap|time[- ]sensitive|final (?:notice|warning|reminder)|last (?:warning|chance)|expires? (?:today|soon|in \d+|within \d+)|within (?:the next )?\d+\s?(?:minutes?|hours?|days?)|immediate action|don'?t (?:delay|wait)|limited time|before it'?s too late)\b/gi;
  var RE_THREAT = /\b(suspend(?:ed|ing|sion)?|terminat(?:e|ed|ion|ing)|deactivat(?:e|ed|ion)|permanently (?:clos|delet|remov|suspend|lock)|account (?:will be|has been|is being) (?:clos|suspend|lock|deactivat|terminat|restrict)|will be (?:locked|closed|suspended|terminated|deactivated|restricted)|lock(?:ed)? (?:out|down)|legal action|account closure|permanent closure|disab(?:led|le) your account)\b/gi;
  var RE_PASSWORD = /\b(password|passphrase|login credentials|login details|current password)\b/gi;
  var RE_REQUEST_VERB = /\b(enter|provide|confirm|verify|update|submit|send|reply|reset|re-?enter|type|supply|share|validate)\b/gi;
  var RE_PASSWORD_PAIR = /\b(?:enter|provide|confirm|verify|update|submit|send|reply with|reset|re-?enter|type|supply|share|validate)[^.\n]{0,40}\b(?:password|passphrase|login details|login credentials)\b/gi;
  var RE_MFA = /\b(one[- ]?time (?:code|password|pin)|otp|verification code|security code|authentication code|two[- ]?factor|2fa|mfa|6[- ]?digit code|code (?:we|i) (?:just )?sent|sms code|text message code)\b/gi;
  var RE_PAYMENT = /\b(gift ?cards?|itunes (?:card|voucher)|google play (?:card|voucher)|amazon (?:card|gift)|steam card|prepaid card|wire transfer|bank transfer|western union|moneygram|bitcoin|cryptocurrency|usdt|ethereum|redelivery fee|delivery fee|processing fee|customs fee|clearance fee|pay the (?:invoice|fee|amount|balance)|remit payment|make a payment|purchase .{0,20}cards)\b/gi;
  var RE_BANK = /\b(update (?:your |our |the )?(?:bank|banking|payment|direct deposit|wire|account) (?:details|information|info|record)|change (?:your |our |the )?(?:bank|banking)|changed banks|new (?:bank account|account number|account details|bank details)|updated (?:bank|payment|account) (?:details|information|info)|revised (?:payment|bank|banking) details|new beneficiary|beneficiary account|remittance details|new payment details)\b/gi;
  var RE_IMPERSONATION_ROLE = /\b(?:security|support|account|delivery|billing|customer|service|help|technical|it|fraud|verification|compliance)\s?(?:team|desk|department|support|service|care|center|centre)\b|\bhelp ?desk\b|\bservice desk\b|\bno[- ]?reply\b/gi;
  var RE_GREETING = /\b(dear (?:customer|client|user|member|sir|madam|sir\/madam|valued customer|account holder|friend|winner)|to whom it may concern|hello (?:customer|user|member|friend))\b/gi;
  var RE_REWARD = /\b(you (?:have|'ve) (?:won|been selected|been chosen)|congratulations|claim your (?:prize|reward|refund|gift)|you are a winner|free (?:gift|money|iphone|holiday)|lottery|jackpot|exclusive (?:offer|reward)|gift card (?:reward|bonus))\b/gi;
  var RE_INVOICE = /\b(invoice|payment (?:due|remittance)|outstanding (?:balance|payment|amount)|unpaid|overdue (?:invoice|payment|balance|account)|purchase order|remittance advice|amount due|proforma|accounts payable|billing statement|past due|final demand)\b/gi;
  var RE_CREDENTIALS = /\b(verify your (?:account|identity|information|details|email|login)|confirm your (?:account|identity|details|information|email address|login)|validate your account|re-?activate your account|unlock your account|sign in to (?:confirm|verify|secure|restore|continue)|log ?in (?:here|below|to)|click (?:here|below|the link|this link) to (?:verify|confirm|secure|restore|unlock|update|continue)|update your (?:payment|billing|account) (?:information|info|details)|restore (?:your )?access)\b/gi;
  var RE_EXEC = /\b[\w\-. ]{1,60}\.(?:exe|scr|jse?|vbs|vbe|bat|cmd|pif|jar|ps1|psm1|msi|lnk|hta|reg|wsf|cpl|iso|img|apk|dll|sys|chm|gadget|application|msc)\b/gi;
  var RE_DOUBLE_EXT = /\b[\w\-. ]{1,60}\.(?:pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|rtf|csv|html?|zip|rar|7z)\.(?:exe|scr|jse?|vbs|vbe|bat|cmd|pif|jar|ps1|msi|lnk|hta|reg|wsf|cpl|iso|img|apk)\b/gi;
  var RE_MACROS = /\b(enable (?:macros?|editing|content|active content)|macros? (?:must|need to|have to) be enabled|click (?:enable|allow) (?:content|editing|macros)|enable content to (?:view|see|read)|protected view|disable protected view|turn on macros)\b/gi;
  var RE_SPF = /(spf=(?:fail|softfail|permerror|temperror|neutral))|(received-spf:\s*(?:fail|softfail|neutral))/i;
  var RE_DKIM = /dkim=(?:fail|permerror|temperror)/i;
  var RE_DMARC = /dmarc=(?:fail|permerror|temperror)/i;

  // Headers whose presence tells us the pasted text includes real email headers.
  var STRONG_HEADERS = ['from', 'reply-to', 'return-path', 'authentication-results',
    'received-spf', 'dkim-signature', 'arc-authentication-results', 'message-id',
    'received', 'delivered-to', 'envelope-to'];

  /* ------------------------------------------------------------------ *
   * Small helpers
   * ------------------------------------------------------------------ */

  // Run a global regex over the text and return the unique matches (up to a limit).
  function findMatches(re, text, limit) {
    var out = [];
    var m;
    limit = limit || 8;
    re.lastIndex = 0;
    while ((m = re.exec(text)) !== null) {
      var value = (m[1] !== undefined && m[1] !== null) ? m[1] : m[0];
      value = String(value).trim();
      if (value && out.indexOf(value) === -1) out.push(value);
      if (m.index === re.lastIndex) re.lastIndex++;
      if (out.length >= limit) break;
    }
    return out;
  }

  function stripTags(str) {
    return String(str).replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim();
  }

  function registrableDomain(host) {
    var parts = String(host).split('.');
    if (parts.length <= 2) return host;
    return parts.slice(-2).join('.');
  }

  // Turn characters that are easy to confuse back into plain letters, so that
  // e.g. "micros0ft" becomes "microsoft".
  function normalizeHost(host) {
    return String(host).toLowerCase()
      .replace(/0/g, 'o').replace(/1/g, 'l').replace(/3/g, 'e')
      .replace(/5/g, 's').replace(/\$/g, 's').replace(/rn/g, 'm')
      .replace(/vv/g, 'w');
  }

  // Does the (normalised) host contain the key as a whole token?
  function hostHasKey(norm, key) {
    var idx = 0;
    while ((idx = norm.indexOf(key, idx)) !== -1) {
      var before = idx === 0 ? '' : norm[idx - 1];
      var after = norm[idx + key.length] || '';
      var okBefore = before === '' || before === '.' || before === '-';
      var okAfter = after === '' || after === '.' || after === '-';
      if (okBefore && okAfter) return true;
      idx += 1;
    }
    return false;
  }

  function hostMatchesOfficial(host, domains) {
    for (var i = 0; i < domains.length; i++) {
      var d = domains[i];
      if (host === d || host.slice(-(d.length + 1)) === '.' + d) return true;
    }
    return false;
  }

  function findBrandInHost(host) {
    var norm = normalizeHost(host);
    for (var i = 0; i < BRANDS.length; i++) {
      var b = BRANDS[i];
      for (var j = 0; j < b.hostKeys.length; j++) {
        if (hostHasKey(norm, b.hostKeys[j])) return { brand: b, matchedKey: b.hostKeys[j] };
      }
    }
    return null;
  }

  function findBrandInText(text) {
    for (var i = 0; i < BRANDS.length; i++) {
      var b = BRANDS[i];
      var re = new RegExp('\\b(' + b.textKeys.join('|') + ')\\b', 'i');
      var m = re.exec(text);
      if (m) return { brand: b, matched: m[0] };
    }
    return null;
  }

  function isIp(host) { return /^(\d{1,3}\.){3}\d{1,3}$/.test(host); }
  function isShortener(host) { return SHORTENERS.indexOf(String(host).replace(/^www\./, '')) !== -1; }

  function hasSuspiciousTld(host) {
    for (var i = 0; i < SUSPICIOUS_TLDS.length; i++) {
      var t = SUSPICIOUS_TLDS[i];
      if (host.slice(-t.length) === t) return true;
    }
    return false;
  }

  function isPunycode(host) {
    return host.indexOf('xn--') === 0 || host.indexOf('.xn--') !== -1;
  }

  function hyphenCount(host) { return (host.match(/-/g) || []).length; }
  function labelCount(host) { return host.split('.').length; }

  // Extract every URL from the text (http/https and bare www. links).
  function extractUrls(text) {
    var out = [];
    var seen = {};
    var re = /\bhttps?:\/\/[^\s<>"'\)\]]+/gi;
    var m;
    while ((m = re.exec(text)) !== null) addUrl(out, seen, m[0]);
    var re2 = /(?:^|[\s(<\[])(www\.[^\s<>"'\)\]]+)/gi;
    while ((m = re2.exec(text)) !== null) addUrl(out, seen, m[1]);
    return out;
  }

  function addUrl(out, seen, raw) {
    var clean = raw.replace(/[.,;:!]+$/, '');
    if (seen[clean]) return;
    seen[clean] = true;
    out.push(makeUrl(clean));
  }

  function makeUrl(raw) {
    var withoutScheme = raw.replace(/^[a-z]+:\/\//i, '');
    var authority = withoutScheme.split(/[\/?#]/)[0];
    var hasAt = authority.indexOf('@') !== -1;
    var hostPart = hasAt ? authority.slice(authority.lastIndexOf('@') + 1) : authority;
    var host = hostPart.replace(/:\d+$/, '').toLowerCase();
    return { raw: raw, host: host, hasAt: hasAt };
  }

  // Pull a hostname out of a URL-like string (used for misleading-link checks).
  function hostOfUrl(str) {
    if (!str) return '';
    var s = String(str).trim();
    var m = /^https?:\/\/([^\/?#\s]+)/i.exec(s);
    if (m) return m[1].replace(/^[^@]*@/, '').replace(/:\d+$/, '').toLowerCase();
    if (/^www\./i.test(s)) return s.split(/[\/?#\s]/)[0].toLowerCase();
    return '';
  }

  function domainFromText(str) {
    var m = /\b([a-z0-9-]+(?:\.[a-z0-9-]+)+)\b/i.exec(str || '');
    return m ? m[1].toLowerCase() : '';
  }

  function extractAddress(str) {
    if (!str) return null;
    var m = /<([^>]+)>/.exec(str);
    var addr = (m ? m[1] : str).trim().replace(/^mailto:/i, '');
    var at = addr.lastIndexOf('@');
    if (at === -1) return { raw: addr, domain: '', local: addr };
    var domain = addr.slice(at + 1).toLowerCase().replace(/[>;,].*$/, '').trim();
    return { raw: addr, domain: domain, local: addr.slice(0, at) };
  }

  function extractDisplayName(str) {
    var m = /^\s*"?([^"<]*?)"?\s*</.exec(str || '');
    if (m && m[1].trim()) return m[1].trim();
    return '';
  }

  // Parse an email header block into a lookup object.
  function parseHeaders(text) {
    var lines = String(text).split(/\r?\n/);
    var headers = {};
    var lastKey = null;
    var strongCount = 0;
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i];
      var m = /^([A-Za-z][A-Za-z0-9-]*):\s?(.*)$/.exec(line);
      if (m) {
        var key = m[1].toLowerCase();
        var val = m[2].trim();
        headers[key] = headers[key] ? headers[key] + ' ' + val : val;
        lastKey = key;
        if (STRONG_HEADERS.indexOf(key) !== -1) strongCount++;
      } else if (lastKey && /^\s+\S/.test(line)) {
        headers[lastKey] += ' ' + line.trim();
      }
    }
    headers.__hasHeaders = strongCount >= 1;
    return headers;
  }

  function getHeader(headers, name) {
    return headers[name.toLowerCase()] || '';
  }

  /* ------------------------------------------------------------------ *
   * The rules
   * Each rule has a fixed point value, a severity, a plain-English
   * explanation and a detect() function that returns matched evidence.
   * ------------------------------------------------------------------ */

  var RULES = [
    {
      id: 'urgency', label: 'Urgency or pressure language', category: 'Social engineering',
      points: 10, severity: 'medium',
      explanation: 'Phishing relies on rushing you so you act before you think. Phrases that create panic or a tight deadline are a classic warning sign.',
      detect: function (ctx) { return findMatches(RE_URGENCY, ctx.raw); }
    },
    {
      id: 'threat_suspension', label: 'Threat of account suspension or closure', category: 'Social engineering',
      points: 15, severity: 'high',
      explanation: 'Threatening to lock, suspend or close an account is a scare tactic designed to force a quick, panicked response.',
      detect: function (ctx) { return findMatches(RE_THREAT, ctx.raw); }
    },
    {
      id: 'reward_language', label: 'Prize, reward or "you have won" language', category: 'Social engineering',
      points: 15, severity: 'high',
      explanation: 'Unexpected prizes, refunds or windfalls are a common lure. If you did not enter, you cannot have won.',
      detect: function (ctx) { return findMatches(RE_REWARD, ctx.raw); }
    },
    {
      id: 'generic_greeting', label: 'Generic greeting', category: 'Social engineering',
      points: 5, severity: 'low',
      explanation: 'Real organisations you deal with usually know your name. "Dear customer" or "Dear sir" can indicate a mass-mailing.',
      detect: function (ctx) { return findMatches(RE_GREETING, ctx.raw); }
    },
    {
      id: 'impersonation', label: 'Impersonation language', category: 'Impersonation',
      points: 12, severity: 'medium',
      explanation: 'Criminals pose as a brand and add an authority-sounding role (such as "Security Team") to appear trustworthy.',
      detect: function (ctx) {
        var brand = findBrandInText(ctx.raw);
        if (!brand) return [];
        var roles = findMatches(RE_IMPERSONATION_ROLE, ctx.raw, 3);
        if (!roles.length) return [];
        return [brand.brand.name + ' + "' + roles[0] + '"'];
      }
    },
    {
      id: 'request_password', label: 'Request for your password', category: 'Credential theft',
      points: 20, severity: 'high',
      explanation: 'No legitimate organisation asks you to send, confirm or re-enter your password by email. This is the core of credential theft.',
      detect: function (ctx) {
        if (!new RegExp(RE_PASSWORD.source, 'i').test(ctx.raw)) return [];
        if (!new RegExp(RE_REQUEST_VERB.source, 'i').test(ctx.raw)) return [];
        var ev = findMatches(RE_PASSWORD_PAIR, ctx.raw, 4);
        if (!ev.length) ev = findMatches(RE_PASSWORD, ctx.raw, 3);
        return ev;
      }
    },
    {
      id: 'request_mfa', label: 'Request for an MFA / verification code', category: 'Credential theft',
      points: 20, severity: 'high',
      explanation: 'One-time codes defeat two-factor protection. Being asked to hand one over by email or message is a strong sign of an account-takeover attempt.',
      detect: function (ctx) { return findMatches(RE_MFA, ctx.raw); }
    },
    {
      id: 'credential_harvesting', label: 'Credential-harvesting language', category: 'Credential theft',
      points: 18, severity: 'high',
      explanation: 'Phrases like "verify your account" or "click here to sign in" are designed to send you to a fake login page that steals your details.',
      detect: function (ctx) { return findMatches(RE_CREDENTIALS, ctx.raw); }
    },
    {
      id: 'payment_giftcard', label: 'Payment or gift-card request', category: 'Financial',
      points: 20, severity: 'high',
      explanation: 'Requests to pay by gift card, wire transfer or cryptocurrency are hallmarks of fraud because those payments are hard to trace or reverse.',
      detect: function (ctx) { return findMatches(RE_PAYMENT, ctx.raw); }
    },
    {
      id: 'bank_change', label: 'Request to change bank details', category: 'Financial',
      points: 20, severity: 'high',
      explanation: 'Last-minute changes to bank or payment details are a classic invoice-fraud tactic that redirects money to the criminal.',
      detect: function (ctx) { return findMatches(RE_BANK, ctx.raw); }
    },
    {
      id: 'invoice_language', label: 'Unexpected invoice or payment language', category: 'Financial',
      points: 12, severity: 'medium',
      explanation: 'Invoices you were not expecting, or pressure about overdue payments, are frequently used to trigger a rushed payment.',
      detect: function (ctx) { return findMatches(RE_INVOICE, ctx.raw); }
    },
    {
      id: 'suspicious_url', label: 'Suspicious link characteristics', category: 'Links',
      points: 12, severity: 'medium',
      explanation: 'Unusual top-level domains, deeply nested subdomains, many hyphens or hidden characters often point to links built to deceive.',
      detect: function (ctx) {
        var ev = [];
        for (var i = 0; i < ctx.urls.length && ev.length < 5; i++) {
          var u = ctx.urls[i];
          if (isIp(u.host) || isShortener(u.host)) continue;
          var reasons = [];
          if (hasSuspiciousTld(u.host)) reasons.push('unusual top-level domain');
          if (u.hasAt) reasons.push('hidden text before "@"');
          if (isPunycode(u.host)) reasons.push('punycode / encoded characters');
          if (hyphenCount(u.host) >= 2) reasons.push('many hyphens');
          if (labelCount(u.host) >= 4) reasons.push('deeply nested subdomains');
          if (reasons.length) ev.push(u.raw + '  (' + reasons.join(', ') + ')');
        }
        return ev;
      }
    },
    {
      id: 'lookalike_domain', label: 'Look-alike (fake) domain', category: 'Links',
      points: 15, severity: 'high',
      explanation: 'The link mimics a well-known brand but is not on that brand\'s real domain - often using swapped characters such as a zero for the letter "o".',
      detect: function (ctx) {
        var ev = [];
        for (var i = 0; i < ctx.urls.length && ev.length < 5; i++) {
          var u = ctx.urls[i];
          if (isIp(u.host)) continue;
          var found = findBrandInHost(u.host);
          if (found && !hostMatchesOfficial(u.host, found.brand.domains)) {
            ev.push(u.raw + '  (mimics ' + found.brand.name + ')');
          }
        }
        return ev;
      }
    },
    {
      id: 'shortened_url', label: 'Shortened link', category: 'Links',
      points: 10, severity: 'medium',
      explanation: 'Link shorteners hide the real destination. You cannot tell where a shortened link goes without clicking it - which you should not do.',
      detect: function (ctx) {
        var ev = [];
        for (var i = 0; i < ctx.urls.length && ev.length < 5; i++) {
          if (isShortener(ctx.urls[i].host)) ev.push(ctx.urls[i].raw);
        }
        return ev;
      }
    },
    {
      id: 'raw_ip_url', label: 'Link using a raw IP address', category: 'Links',
      points: 15, severity: 'high',
      explanation: 'Legitimate services use domain names, not bare numeric addresses like 192.168.1.1. A raw IP in a link is a strong warning sign.',
      detect: function (ctx) {
        var ev = [];
        for (var i = 0; i < ctx.urls.length && ev.length < 5; i++) {
          if (isIp(ctx.urls[i].host)) ev.push(ctx.urls[i].raw);
        }
        return ev;
      }
    },
    {
      id: 'misleading_link', label: 'Misleading link text', category: 'Links',
      points: 18, severity: 'high',
      explanation: 'The visible text of the link looks like one address but the actual destination is different. This is a classic way to disguise a malicious link.',
      detect: function (ctx) {
        var ev = [];
        var m;
        var anchorRe = /<a\b[^>]*href\s*=\s*["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;
        while ((m = anchorRe.exec(ctx.raw)) !== null && ev.length < 5) {
          checkLinkPair(m[1], stripTags(m[2]), ev);
        }
        var mdRe = /\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/gi;
        while ((m = mdRe.exec(ctx.raw)) !== null && ev.length < 5) {
          checkLinkPair(m[2], m[1], ev);
        }
        return ev;
      }
    },
    {
      id: 'executable_attachment', label: 'Executable or script attachment', category: 'Attachments',
      points: 20, severity: 'high',
      explanation: 'Attachments ending in .exe, .js, .vbs, .bat and similar run code when opened and are a primary way malware is delivered.',
      detect: function (ctx) { return findMatches(RE_EXEC, ctx.raw); }
    },
    {
      id: 'unusual_attachment', label: 'Unusual or double-extension filename', category: 'Attachments',
      points: 12, severity: 'high',
      explanation: 'A filename like "invoice.pdf.exe" pretends to be a document but is really a program. Double extensions are a well-known trick.',
      detect: function (ctx) { return findMatches(RE_DOUBLE_EXT, ctx.raw); }
    },
    {
      id: 'enable_macros', label: 'Request to enable macros or editing', category: 'Attachments',
      points: 20, severity: 'high',
      explanation: 'Being asked to "enable content" or "enable macros" is a common way to get you to run malicious code hidden in a document.',
      detect: function (ctx) { return findMatches(RE_MACROS, ctx.raw); }
    },
    {
      id: 'display_name_mismatch', label: 'Sender name does not match the address', category: 'Sender',
      points: 12, severity: 'medium',
      explanation: 'The friendly name says one thing (e.g. "PayPal") but the actual email address is on a different domain - a strong sign of spoofing.',
      detect: function (ctx) {
        if (!ctx.headers.__hasHeaders) return [];
        var from = getHeader(ctx.headers, 'from');
        if (!from) return [];
        var name = extractDisplayName(from);
        if (!name) return [];
        var brand = findBrandInText(name);
        if (!brand) return [];
        var addr = extractAddress(from);
        if (addr && addr.domain && hostMatchesOfficial(addr.domain, brand.brand.domains)) return [];
        return ['Name shows "' + name + '" but the address domain is "' + (addr ? addr.domain : 'unknown') + '"'];
      }
    },
    {
      id: 'sender_replyto_mismatch', label: 'From and Reply-To addresses differ', category: 'Sender',
      points: 15, severity: 'high',
      explanation: 'A Reply-To on a different domain redirects your reply to the attacker, even if the "From" looks genuine.',
      detect: function (ctx) {
        if (!ctx.headers.__hasHeaders) return [];
        var from = extractAddress(getHeader(ctx.headers, 'from'));
        var reply = extractAddress(getHeader(ctx.headers, 'reply-to'));
        if (!from || !reply || !from.domain || !reply.domain) return [];
        if (registrableDomain(from.domain) === registrableDomain(reply.domain)) return [];
        return ['From domain "' + from.domain + '" vs Reply-To domain "' + reply.domain + '"'];
      }
    },
    {
      id: 'spf_fail', label: 'SPF authentication failure', category: 'Authentication',
      points: 12, severity: 'medium',
      explanation: 'SPF checks whether the sending server was allowed to send for that domain. A failure or softfail means the sender could not be verified.',
      detect: function (ctx) { var m = RE_SPF.exec(ctx.lower); return m ? [m[0]] : []; }
    },
    {
      id: 'dkim_fail', label: 'DKIM authentication failure', category: 'Authentication',
      points: 10, severity: 'medium',
      explanation: 'DKIM verifies that the message was genuinely sent by the domain and not altered in transit. A failure is a warning sign.',
      detect: function (ctx) { var m = RE_DKIM.exec(ctx.lower); return m ? [m[0]] : []; }
    },
    {
      id: 'dmarc_fail', label: 'DMARC authentication failure', category: 'Authentication',
      points: 12, severity: 'high',
      explanation: 'DMARC ties SPF and DKIM together. A DMARC failure means the message did not meet the domain\'s own email policy.',
      detect: function (ctx) { var m = RE_DMARC.exec(ctx.lower); return m ? [m[0]] : []; }
    }
  ];

  /* ------------------------------------------------------------------ *
   * Analysis orchestration
   * ------------------------------------------------------------------ */

  // Compare a link's visible text with its real destination. If the text looks
  // like a URL/domain on a different domain than the destination, flag it.
  function checkLinkPair(href, text, ev) {
    var destHost = hostOfUrl(href);
    var textHost = hostOfUrl(text) || domainFromText(text);
    if (!destHost || !textHost) return;
    if (registrableDomain(destHost) !== registrableDomain(textHost)) {
      ev.push('Link text "' + text + '" actually points to ' + href);
    }
  }

  function buildContext(text) {
    return {
      raw: text,
      lower: text.toLowerCase(),
      urls: extractUrls(text),
      headers: parseHeaders(text)
    };
  }

  function buildRecommendations(indicators) {
    var has = {};
    for (var i = 0; i < indicators.length; i++) has[indicators[i].id] = true;

    var recs = [];
    recs.push('Do not click any links or open any attachments in this email. If you need to check something, open the organisation\'s website or app yourself by typing its address.');

    if (has.request_password || has.request_mfa || has.credential_harvesting) {
      recs.push('No legitimate organisation will ask for your password or a one-time security code by email. Never share them with anyone.');
    }
    if (has.payment_giftcard || has.bank_change || has.invoice_language) {
      recs.push('Treat any request to pay, change bank details or settle an invoice as fraud until you confirm it by phone using a contact you already know.');
    }
    if (has.executable_attachment || has.unusual_attachment || has.enable_macros) {
      recs.push('Do not open the attachment. Report the email to your IT or security team, then delete it.');
    }
    if (has.misleading_link || has.shortened_url || has.raw_ip_url || has.suspicious_url || has.lookalike_domain) {
      recs.push('Hover over links (without clicking) to see the real destination. Shortened and look-alike links often hide a different, dangerous address.');
    }
    if (has.spf_fail || has.dkim_fail || has.dmarc_fail || has.sender_replyto_mismatch || has.display_name_mismatch) {
      recs.push('The sender could not be verified. Contact the organisation using details from its official website, not the ones in this email.');
    }
    if (has.urgency || has.threat_suspension || has.reward_language) {
      recs.push('Urgency, threats and "you have won" claims are manipulation tactics designed to stop you thinking. Slow down and verify before acting.');
    }

    recs.push('If you may have already clicked a link or entered information, change the affected passwords immediately and tell your IT/security team or bank.');
    recs.push('Remember: this tool only highlights warning signs. When in doubt, verify the message through a trusted, independent channel.');
    return recs;
  }

  function analyse(text) {
    var clean = text == null ? '' : String(text);
    var ctx = buildContext(clean);

    var indicators = [];
    for (var i = 0; i < RULES.length; i++) {
      var rule = RULES[i];
      var evidence;
      try {
        evidence = rule.detect(ctx) || [];
      } catch (err) {
        evidence = [];
      }
      if (evidence.length) {
        indicators.push({
          id: rule.id,
          label: rule.label,
          category: rule.category,
          points: rule.points,
          severity: rule.severity,
          explanation: rule.explanation,
          evidence: evidence
        });
      }
    }

    // Strongest first, so the most important reasons are seen first.
    indicators.sort(function (a, b) { return b.points - a.points; });

    return {
      summary: Scoring.compute(indicators),
      indicators: indicators,
      recommendations: buildRecommendations(indicators),
      stats: { urls: ctx.urls.length },
      hasHeaders: !!ctx.headers.__hasHeaders
    };
  }

  var api = {
    analyse: analyse,
    RULES: RULES,
    extractUrls: extractUrls,
    parseHeaders: parseHeaders
  };

  root.PhishingAnalyser = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
