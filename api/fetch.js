// SecuritySuite Server Relay - /api/fetch
// Fetches a public target server-side so the browser app is not blocked by CORS.
// SSRF guard: public targets only. Blocks private, loopback, link-local,
// reserved and cloud-metadata destinations, and re-checks every redirect hop.

const dns = require("dns").promises;

const MAX_REDIRECTS = 5;
const TIMEOUT_MS = 15000;
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024; // 2 MB
const MAX_REQUEST_BODY_CHARS = 1024 * 1024; // 1 MB

function ipv4Blocked(ip) {
  const p = ip.split(".").map(Number);
  if (p.length !== 4 || p.some((n) => Number.isNaN(n))) return true;
  const [a, b] = p;
  if (a === 0) return true; // 0.0.0.0/8
  if (a === 10) return true; // private
  if (a === 127) return true; // loopback
  if (a === 169 && b === 254) return true; // link-local + metadata
  if (a === 172 && b >= 16 && b <= 31) return true; // private
  if (a === 192 && b === 168) return true; // private
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
  if (a >= 224) return true; // multicast + reserved
  if (a === 192 && b === 0) return true; // 192.0.0.0/24 etc.
  if (a === 198 && (b === 18 || b === 19)) return true; // benchmarking
  return false;
}

function ipv6Blocked(ip) {
  const s = ip.toLowerCase();
  if (s === "::1" || s === "::") return true;
  if (s.startsWith("fe8") || s.startsWith("fe9") || s.startsWith("fea") || s.startsWith("feb")) return true; // link-local fe80::/10
  if (s.startsWith("fc") || s.startsWith("fd")) return true; // unique local fc00::/7
  if (s.startsWith("::ffff:")) return ipv4Blocked(s.slice(7)); // v4-mapped
  return false;
}

function ipBlocked(ip) {
  return ip.includes(":") ? ipv6Blocked(ip) : ipv4Blocked(ip);
}

function isIpLiteral(host) {
  return /^[0-9.]+$/.test(host) || host.includes(":");
}

async function assertPublicHost(hostname) {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (host === "localhost" || host.endsWith(".localhost")) {
    throw Object.assign(new Error("Blocked: local targets are not allowed through the relay. Use the Proxy Bridge for LAN targets."), { code: "BLOCKED_HOST" });
  }
  if (isIpLiteral(host)) {
    if (ipBlocked(host)) {
      throw Object.assign(new Error("Blocked: private, loopback or metadata IP addresses are not allowed through the relay. Use the Proxy Bridge for LAN targets."), { code: "BLOCKED_HOST" });
    }
    return;
  }
  let records;
  try {
    records = await dns.lookup(host, { all: true });
  } catch (e) {
    throw Object.assign(new Error("DNS lookup failed for " + host), { code: "DNS_FAIL" });
  }
  if (!records.length) {
    throw Object.assign(new Error("DNS lookup returned no addresses for " + host), { code: "DNS_FAIL" });
  }
  for (const r of records) {
    if (ipBlocked(r.address)) {
      throw Object.assign(new Error("Blocked: " + host + " resolves to a private or reserved address. Use the Proxy Bridge for LAN targets."), { code: "BLOCKED_HOST" });
    }
  }
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (chunk) => {
      data += chunk;
      if (data.length > 4 * 1024 * 1024) reject(new Error("Request too large"));
    });
    req.on("end", () => resolve(data));
    req.on("error", reject);
  });
}

module.exports = async (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") { res.status(204).end(); return; }
  if (req.method !== "POST") { res.status(405).json({ error: "POST only" }); return; }

  let payload;
  try {
    const raw = typeof req.body === "string" ? req.body : (req.body ? JSON.stringify(req.body) : await readBody(req));
    payload = JSON.parse(raw || "{}");
  } catch (e) {
    res.status(400).json({ error: "Invalid JSON body" });
    return;
  }

  const method = String(payload.method || "GET").toUpperCase();
  if (!["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"].includes(method)) {
    res.status(400).json({ error: "Method not allowed: " + method });
    return;
  }
  let urlStr = String(payload.url || "");
  if (!/^https?:\/\//i.test(urlStr)) {
    res.status(400).json({ error: "URL must start with http:// or https://" });
    return;
  }
  const reqBody = typeof payload.body === "string" ? payload.body : undefined;
  if (reqBody && reqBody.length > MAX_REQUEST_BODY_CHARS) {
    res.status(413).json({ error: "Request body too large (1 MB cap)" });
    return;
  }
  const fwdHeaders = {};
  if (payload.headers && typeof payload.headers === "object") {
    for (const [k, v] of Object.entries(payload.headers)) {
      const lk = k.toLowerCase();
      if (["host", "content-length", "connection", "origin", "referer"].includes(lk)) continue;
      fwdHeaders[k] = String(v);
    }
  }
  if (!Object.keys(fwdHeaders).some((k) => k.toLowerCase() === "user-agent")) {
    fwdHeaders["User-Agent"] = "SecuritySuite-Relay/1.2 (authorized security testing)";
  }

  const started = Date.now();
  try {
    let currentUrl = urlStr;
    let response = null;
    let redirectCount = 0;
    while (true) {
      const u = new URL(currentUrl);
      if (!["http:", "https:"].includes(u.protocol)) {
        throw Object.assign(new Error("Blocked: only http and https targets are allowed."), { code: "BLOCKED_HOST" });
      }
      await assertPublicHost(u.hostname);
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
      try {
        response = await fetch(currentUrl, {
          method,
          headers: fwdHeaders,
          body: ["GET", "HEAD"].includes(method) ? undefined : reqBody,
          redirect: "manual",
          signal: controller.signal,
        });
      } finally {
        clearTimeout(timer);
      }
      if ([301, 302, 303, 307, 308].includes(response.status)) {
        const loc = response.headers.get("location");
        if (loc && redirectCount < MAX_REDIRECTS) {
          currentUrl = new URL(loc, currentUrl).toString();
          redirectCount++;
          continue;
        }
      }
      urlStr = currentUrl;
      break;
    }

    const headersObj = {};
    response.headers.forEach((v, k) => { headersObj[k] = v; });

    const buf = Buffer.from(await response.arrayBuffer());
    const truncated = buf.length > MAX_RESPONSE_BYTES;
    const bodyText = buf.slice(0, MAX_RESPONSE_BYTES).toString("utf8");

    res.status(200).json({
      ok: true,
      status: response.status,
      statusText: response.statusText || "",
      headers: headersObj,
      body: method === "HEAD" ? "" : bodyText,
      finalUrl: urlStr,
      redirects: redirectCount,
      elapsedMs: Date.now() - started,
      timeMs: Date.now() - started,
      sizeBytes: buf.length,
      truncated,
      via: "relay",
    });
  } catch (e) {
    const code = e && e.code;
    const status = code === "BLOCKED_HOST" ? 403 : 502;
    res.status(status).json({
      ok: false,
      error: e.name === "AbortError" ? "Target timed out after 15s" : String(e.message || e),
      code: code || "FETCH_FAIL",
      via: "relay",
    });
  }
};
