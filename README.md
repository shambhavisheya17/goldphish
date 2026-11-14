# Goldphish

**A privacy-first Chrome extension that checks links in Gmail and WhatsApp Web before they open.**

Goldphish stops users before they reach a phishing page. When a link is clicked, the extension analyses the web address on the user's own device. Safe links open normally. Fake shopping sites that imitate Flipkart, Amazon or Myntra are blocked, and other suspicious links show a warning with the reasons.

Project-Based Learning (PBL) submission, UPES. Submitted to Prof. Priyabrata Das.

## Problem

Phishing links are often shared through email and messaging apps, and fake "sale" sites that copy well-known shopping brands are especially common. Users usually cannot tell a fake address from a real one before clicking, and by the time the page loads it is already too late.

## Features

- **Link interception:** catches clicks on links in Gmail and WhatsApp Web, including links that load later in a conversation.
- **Official-domain check for shopping brands:** a link that imitates Flipkart, Amazon or Myntra but is not on that brand's official domain list is blocked, including look-alike spellings such as `flipkaart` or `amaz0n`.
- **Heuristic risk scoring:** other links are scored for warning signs such as a raw IP address, HTTP instead of HTTPS, a hidden `@` section, look-alike characters, many subdomains, risky domain endings, shortened links and suspicious words.
- **Clear warning page:** shows the risk level, the link and the reasons. Blocked links have no "Proceed anyway" button.
- **Local blocklist:** known-bad domains are stored in a structured JSON data file.

## Security and privacy

- **Data minimisation:** only the address of the clicked link is read. Message text, email bodies, contacts and sender details are never accessed.
- **Local processing:** all analysis happens on the device. No link is sent to a server, and nothing is logged or stored.
- **Least privilege:** the extension can only run on `mail.google.com` and `web.whatsapp.com`.
- **Safe display:** the warning page shows links as plain text, so a malicious address cannot inject code.
- **Tamper resistance:** "Proceed anyway" re-checks the link in the background script, so a blocked link can never be forced through.

## How it works

```
Click on a link in Gmail / WhatsApp Web
        |
content.js  (stops the click, sends only the URL)
        |
background.js  (service worker)
        |
analyzer.js  (blocklist -> brand check -> risk score)
        |
   Low risk ──> link opens in a new tab
   Otherwise ─> warning.html (risk level + reasons)
```

## Project structure

| File | Purpose |
|---|---|
| `manifest.json` | Extension settings (Manifest V3), permissions and entry points |
| `content.js` | Runs inside Gmail and WhatsApp Web; detects link clicks |
| `background.js` | Service worker; receives the URL and decides what to do |
| `analyzer.js` | The checking rules: blocklist, brand check, heuristic scoring |
| `warning.html`, `warning.js` | The warning page shown for risky or blocked links |
| `data/goldphish-data.json` | Structured data store: blocklist, official brand domains, keywords |

## Installation

1. Download this repository as a ZIP (**Code** > **Download ZIP**) and unzip it.
2. Open Chrome and go to `chrome://extensions`.
3. Turn on **Developer mode** (top right).
4. Click **Load unpacked** and select the folder that directly contains `manifest.json`.
5. Open Gmail or WhatsApp Web, and reload the tab.

## Testing it

Send yourself these links on WhatsApp Web or Gmail and click each one.

| Link | Expected result |
|---|---|
| `https://www.amazon.com` | Opens normally |
| `https://www.flipkart.com` | Opens normally |
| `https://www.flipkart.machine.com` | Blocked (imitates Flipkart) |
| `https://www.amazon.sale.com` | Blocked (imitates Amazon) |
| `https://myntra-eorss-sale.shop/claim` | Blocked (imitates Myntra) |
| `http://192.168.4.5/login` | High-risk warning |

## Limitations

- Works only on Google Chrome, and only on Gmail and WhatsApp Web.
- The blocklist in this prototype contains demonstration entries only. A real deployment would use a maintained threat feed.
- Heuristic rules cannot catch every phishing site and can produce false positives.
- Only Flipkart, Amazon and Myntra have the strict official-domain check.
- Links opened through the right-click menu are not intercepted.
- Goldphish protects data by not collecting it. It does not encrypt data.
