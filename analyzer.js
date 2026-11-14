// Goldphish analyzer: local blocklist + heuristic URL checks. Runs entirely on-device.
// All lists (blocklist, official brand domains, keywords...) live in data/goldphish-data.json.

// Reads the data store that ships inside the extension (no network involved).
export async function loadData() {
  const response = await fetch(chrome.runtime.getURL("data/goldphish-data.json"));
  return response.json();
}

const LEET = { "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s" };

function normalizeLeet(str) {
  return str.replace(/[013457@$]/g, ch => LEET[ch] || ch);
}

function editDistance(a, b) {
  const dp = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
  for (let j = 0; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1,
        dp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    }
  }
  return dp[a.length][b.length];
}

function registrableDomain(host, twoPartSuffixes) {
  const labels = host.split(".");
  if (labels.length <= 2) return host;
  const lastTwo = labels.slice(-2).join(".");
  if (twoPartSuffixes.includes(lastTwo)) return labels.slice(-3).join(".");
  return lastTwo;
}

function isIpHost(host) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(":") /* IPv6 */;
}

function isOfficialHost(host, officialList) {
  return officialList.some(d => host === d || host.endsWith("." + d));
}

// Protected shopping brands: returns the brand being impersonated, or null.
function findImpersonatedBrand(host, protectedBrands) {
  const labels = host.split(/[.\-]/).filter(Boolean).map(normalizeLeet);
  for (const [brand, cfg] of Object.entries(protectedBrands)) {
    if (isOfficialHost(host, cfg.official)) continue;
    const ignore = cfg.ignore || [];
    const hit = labels.some(l => !ignore.includes(l) && (l.includes(brand) ||
      (l.length >= brand.length - 2 && editDistance(l, brand) <= cfg.maxEdit)));
    if (hit) return brand;
  }
  return null;
}

// D is the data store loaded by loadData().
export function analyzeUrl(rawUrl, D) {
  let u;
  try {
    u = new URL(rawUrl);
  } catch (_) {
    return { url: rawUrl, level: "high", score: 10, reasons: ["The link could not be parsed as a valid URL."], blocked: false };
  }

  const host = u.hostname.toLowerCase().replace(/^www\./, "");
  const domain = registrableDomain(host, D.twoPartSuffixes);
  const reasons = [];
  let score = 0;

  // 1. Known-bad domain: block immediately
  if (D.blocklist.includes(host) || D.blocklist.includes(domain)) {
    return {
      url: u.href, level: "blocked", score: 100, blocked: true,
      reasons: ["This domain is on the known malicious domain list."]
    };
  }

  // 1b. Protected shopping brands: not on the official list = block
  const fake = findImpersonatedBrand(host, D.protectedBrands);
  if (fake) {
    const name = fake[0].toUpperCase() + fake.slice(1);
    return {
      url: u.href, level: "blocked", score: 100, blocked: true,
      reasons: [`This link imitates ${name} but is not an official ${name} domain.`]
    };
  }

  // 2. Heuristics
  if (u.protocol === "http:") { score += 2; reasons.push("Connection is not encrypted (HTTP, not HTTPS)."); }
  if (isIpHost(host)) { score += 3; reasons.push("Link uses a raw IP address instead of a domain name."); }
  if (u.username || u.password) { score += 3; reasons.push("URL contains a username/@ section, a common way to disguise the real destination."); }
  if (host.includes("xn--")) { score += 3; reasons.push("Domain uses punycode, which can imitate other characters (lookalike domain)."); }
  if (host.split(".").length > 4) { score += 2; reasons.push("Unusually many subdomains."); }
  if ((host.match(/-/g) || []).length >= 3) { score += 1; reasons.push("Domain contains many hyphens."); }

  const tld = host.split(".").pop();
  if (D.riskyTlds.includes(tld)) { score += 2; reasons.push(`Domain ends in “.${tld}”, which is often abused.`); }
  if (D.shorteners.includes(domain)) { score += 1; reasons.push("Shortened link: the real destination is hidden."); }
  if (u.href.length > 100) { score += 1; reasons.push("Very long URL."); }

  // Official brand domains (e.g. accounts.google.com) should not be penalised for words like "account"
  const isOfficial = Object.values(D.knownBrands).some(list => list.includes(domain));

  // Suspicious words (cap so they cannot dominate alone)
  const hostHits = isOfficial ? [] : D.keywords.filter(k => host.includes(k));
  if (hostHits.length) { score += Math.min(hostHits.length * 2, 4); reasons.push(`Domain contains suspicious words: ${hostHits.join(", ")}.`); }
  const pathHits = isOfficial ? [] : D.keywords.filter(k => (u.pathname + u.search).toLowerCase().includes(k));
  if (pathHits.length) { score += Math.min(pathHits.length, 2); reasons.push(`Link path contains suspicious words: ${pathHits.join(", ")}.`); }

  // Brand impersonation (general brands): brand name in the host but not the brand's real domain
  for (const [brand, realDomains] of Object.entries(D.knownBrands)) {
    if (host.includes(brand) && !realDomains.includes(domain)) {
      score += 4;
      reasons.push(`Domain mentions “${brand}” but is not an official ${brand} domain.`);
      break;
    }
  }

  const level = score >= 5 ? "high" : score >= 3 ? "medium" : "low";
  return { url: u.href, level, score, reasons, blocked: false };
}
