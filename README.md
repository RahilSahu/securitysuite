# SecuritySuite

A light, browser-based web application security testing toolkit: intercept, edit, repeat, fuzz and scan HTTP traffic without installing a desktop proxy.

**Live:** https://securitysuite-woad.vercel.app

For authorized testing only, on systems you own or have written permission to test.

## Features

- **Dashboard**: visual attack surface site map graph, scan overview, scope filters, live event log
- **Proxy / Intercept**: hold, edit, forward or drop requests; HAR and cURL import
- **Repeater**: full HTTP client with raw, headers, body and auth editing, response viewer, history, cURL export
- **Intruder**: payload positions, Sniper / Battering Ram / Pitchfork attack types, built-in SQLi, XSS, path traversal, IDOR and auth payload sets (60 requests per run cap)
- **Scanner (passive)**: security headers, CORS, cookie flags, JWT issues, sensitive data patterns
- **Browser / Crawler**: an in-app fetch-browser that logs every navigation and form submit to Proxy History, plus a crawler that builds the site map automatically (50 page cap)
- **Capture / Proxy Bridge**: a downloadable single-file Python proxy for capturing same-network phone traffic into the suite, protected by a per-run token
- **Decoder / Comparer / Sequencer**: Base64, URL, hex, HTML entities and full JWT inspection
- **AI Copilot**: local heuristics that flag testable fields in responses (for example `isAdmin: false`) and suggest payloads

## Transports

Every tool can send traffic three ways, switchable in the top bar:

| Mode | How it works | Best for |
| --- | --- | --- |
| **Relay** (default) | Requests go through the `/api/fetch` server function, which fetches the target server-side, so browser CORS never blocks you | Public targets |
| **Direct** | The browser fetches the target itself | CORS-enabled targets, offline use |
| **Bridge** | Traffic captured by the local Proxy Bridge on your network | LAN targets, mobile app traffic |

The relay has an SSRF guard: it only fetches public targets and blocks localhost, private/LAN, link-local and cloud metadata addresses, re-checks every redirect, and caps responses at 2 MB with a 15 s timeout. LAN targets belong on the Bridge.

## AI agent API

SecuritySuite is designed to be driven by AI agents. Give any agent the live URL and the prompt from the in-app **Agent API** tab. The page exposes:

```js
window.SecuritySuite.send({ method, url, headers, body })
window.SecuritySuite.repeater(...)
window.SecuritySuite.intruder(...)
window.SecuritySuite.browse(url)
window.SecuritySuite.crawl(url)
window.SecuritySuite.decode(...)
window.SecuritySuite.scan(...)
window.SecuritySuite.getHistory()
window.SecuritySuite.getState()
```

All calls return JSON. Agents can also read the full API reference from the Agent API tab in the app.

## Android app

`android/` contains a native Android app (single Activity, no dependencies): a Suite tab with the full web app, a Chromium WebView browser tab, and a Captures tab that logs every request the browser makes (method, URL, headers, HTTP errors), with JSON export.

Build it with JDK 17 and Android build-tools 34 on the path:

```bash
cd android && ./build.sh
```

This produces a signed `SecuritySuite.apk` for sideloading (the signing keystore is generated locally and git-ignored). Note: Android WebView does not expose POST bodies or response bodies for pages it loads itself, use the Relay / Repeater for full bodies.

## Deploy your own

The web app is a single static `index.html` plus one serverless function:

- Host `index.html` anywhere static
- Deploy `api/fetch.js` as a Vercel Function in the same project so `/api/fetch` resolves on the same origin

## Limitations, stated plainly

- A web page cannot intercept other tabs' or apps' traffic like a desktop proxy. SecuritySuite works on traffic sent through it, imported, crawled, or captured via the Proxy Bridge.
- HTTPS through the Proxy Bridge is tunnelled, so you see hosts, not encrypted bodies, without a full CA setup.
- JavaScript-heavy apps do not fully execute in the fetch-browser. Use the Android app's Chromium browser or the Bridge for those.

## License

MIT
