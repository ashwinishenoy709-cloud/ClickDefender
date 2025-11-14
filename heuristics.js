import {
  SHORTENERS,
  SUSPICIOUS_TLDS,
  BRANDS,
  SUSPICIOUS_WORDS
} from './shared_constants.js';

function levenshtein(a, b) {
  a = (a || "").toLowerCase();
  b = (b || "").toLowerCase();
  const m = a.length,
    n = b.length;
  if (m === 0) return n;
  if (n === 0) return m;
  const dp = Array.from({
    length: m + 1
  }, () => new Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost);
    }
  }
  return dp[m][n];
}

function shannonEntropy(str) {
  if (!str) return 0;
  const map = {};
  for (const c of str) map[c] = (map[c] || 0) + 1;
  const len = str.length;
  let H = 0;
  for (const k in map) {
    const p = map[k] / len;
    H -= p * Math.log2(p);
  }
  return H;
}

export function runExplainableHeuristics(url, domSignals, certInfo) {
  const base = 30;
  let score = base;
  const reasons = [];
  if (!url) return {
    score,
    reasons: ["No URL"],
    status: "unknown"
  };

  try {
    const u = new URL(url);
    const host = u.hostname.replace(/^www\./, "");
    const pathQuery = (u.pathname || "") + (u.search || "");
    const tld = host.split(".").pop() || "";
    const lower = String(url).toLowerCase();

    if (lower.startsWith("https://")) {
      score -= 10;
      reasons.push("Uses HTTPS (-10)");

      if (certInfo && certInfo.validityDurationDays) {
        if (certInfo.validityDurationDays <= 95) {
          score += 15;
          reasons.push(`Short SSL certificate validity (${certInfo.validityDurationDays} days) (+15)`);
        } else if (certInfo.validityDurationDays >= 365) {
          score -= 10;
          reasons.push(`Long SSL certificate validity (${certInfo.validityDurationDays} days) (-10)`);
        }
      }

    } else if (lower.startsWith("http://")) {
      score += 10;
      reasons.push("No HTTPS (+10)");
    }

    if (url.length > 75) {
      score += 12;
      reasons.push("Long URL (>75) (+12)");
    }
    const ent = shannonEntropy(host + pathQuery);
    if (ent >= 4.0) {
      score += 10;
      reasons.push("High URL entropy (+10)");
    }
    const dotCount = (host.match(/\./g) || []).length;
    if (dotCount >= 3) {
      score += 10;
      reasons.push("Many subdomains (+10)");
    }
    if (host.includes("-")) {
      score += 6;
      reasons.push("Hyphen in domain (+6)");
    }
    if (SHORTENERS.includes(host)) {
      score += 18;
      reasons.push("URL shortener (+18)");
    }
    if (SUSPICIOUS_TLDS.includes(tld)) {
      score += 6;
      reasons.push(`Suspicious TLD .${tld} (+6)`);
    }
    if (lower.includes("@")) {
      score += 30;
      reasons.push("Contains '@' (+30)");
    }
    const symbolDensity = (pathQuery.match(/[^\w/]/g) || []).length / Math.max(1, pathQuery.length);
    if (symbolDensity > 0.25 && pathQuery.length > 20) {
      score += 10;
      reasons.push("High symbol density in path/query (+10)");
    }
    if (host.includes("xn--")) {
      score += 18;
      reasons.push("IDN/punycode domain (+18)");
    }

    const hostParts = host.split('.');
    const flaggedBrandsInThisRun = new Set();
    for (const part of hostParts) {
      for (const brand of BRANDS) {
        if (part.includes(brand) && !host.endsWith(`.${brand}.com`)) {
          if (levenshtein(part, brand) <= 2) {
            if (!flaggedBrandsInThisRun.has(brand)) {
              score += 25;
              reasons.push(`Brand impersonation detected: '${brand}' (+25)`);
              flaggedBrandsInThisRun.add(brand);
            }
          }
        }
      }
    }

    const kwHits = SUSPICIOUS_WORDS.filter(k => lower.includes(k));
    if (kwHits.length >= 2) {
      score += 10;
      reasons.push(`Suspicious keywords in URL: ${kwHits.slice(0,3).join(", ")} (+10)`);
    } else if (kwHits.length === 1) {
      score += 6;
      reasons.push(`Keyword '${kwHits[0]}' in URL (+6)`);
    }

  } catch (e) {
    console.error("URL parsing failed:", e);
    score += 6;
    reasons.push("Malformed URL (+6)");
  }

  if (domSignals && typeof domSignals === "object") {
    if (domSignals.passwordForms > 0) {
      score += 8;
      reasons.push("Password form present (+8)");
    }
    if (domSignals.bodyKeywords && domSignals.bodyKeywords.length > 0) {
      score += 8;
      reasons.push(`Phishing keywords in body: ${domSignals.bodyKeywords.join(", ")} (+8)`);
    }
    if (domSignals.suspiciousFormActions && domSignals.suspiciousFormActions.length > 0) {
      score += 30;
      reasons.push(`Form submits data to external domain: ${domSignals.suspiciousFormActions[0]} (+30)`);
    }
    if (domSignals.hiddenElements && domSignals.hiddenElements > 20) {
      score += 10;
      reasons.push(`High number of hidden elements (${domSignals.hiddenElements}) (+10)`);
    }
  }

  score = Math.min(100, Math.max(0, score));
  let status = "unknown";
  if (score <= 25) status = "safe";
  else if (score >= 85) status = "dangerous";
  else status = "suspicious";

  return {score, reasons, status};
}