# Phishing Email Analyser

A polished, **privacy-first** web app that helps you learn to spot phishing and
social-engineering warning signs. Paste the contents of a suspicious email and it
returns a **0–100 risk score**, a **classification** (Low Risk / Suspicious /
High Risk), an **explanation of every warning sign**, and **recommendations**.

> **Educational triage tool.** It highlights warning signs only — it can never
> prove whether an email is malicious or safe. Never click links or open
> attachments just to test them. Verify important messages independently through
> an organisation's official website, app or a phone number you already trust.

## Privacy by design

- **No backend, no database, no accounts, no API keys, no tracking.**
- All analysis runs **locally in the visitor's browser** using plain JavaScript.
- Email content is **never** uploaded to a server, AI provider, analytics service
  or any external API. Closing the tab clears everything.

## How it works

| File | Purpose |
|------|---------|
| `index.html` | The page: input, results, privacy notice, disclaimers. |
| `css/styles.css` | All styling. Dark "security console" look, responsive. |
| `js/scoring.js` | Turns detected indicators into a capped 0–100 score + classification. |
| `js/analyser.js` | The detection engine: all the phishing rules and explanations. |
| `js/demo-emails.js` | Six **fictional** sample emails for learning (no real/working links). |
| `js/app.js` | Wires the page to the engine and renders the results. |

### The scoring is explainable

Each detected indicator adds a **fixed number of points** and is shown with its
own explanation and the exact text that triggered it. The total is **capped at
100**. Classification thresholds:

- **0–29** → Low Risk
- **30–59** → Suspicious
- **60–100** → High Risk

### Indicators checked

Urgency/pressure language · threats of account suspension/closure · requests for
passwords · requests for MFA/verification codes · payment or gift-card requests ·
requests to change bank details · suspicious URLs · shortened URLs · raw-IP URLs ·
misleading link text · impersonation language · unusual attachment filenames ·
executable attachment types · requests to enable macros · unexpected invoice
language · credential-harvesting language · From/Reply-To mismatches · display-name
mismatches · and SPF / DKIM / DMARC failures when authentication headers are
included.

## Running it locally

Because it is fully static, you can simply **open `index.html` in a browser** —
no build step, no installs, no server required.

## Hosting it for free

Upload the folder to any static host, for example:

- **GitHub Pages** – push the files to a repository and enable Pages.
- **Netlify** or **Cloudflare Pages** – drag-and-drop the folder.

No environment variables, keys or server configuration are needed.

## Safety notes for contributors

- Keep the demo emails **fictional**. Use only reserved/placeholder domains such
  as `example.com`, `.test` and `.invalid`, and **never** working malicious links.
- Do not add network calls, analytics or telemetry of any kind.
- Keep dependencies at zero: plain HTML, CSS and JavaScript only.
