// background.js 

let lastClickedUrl = null;
let whitelistJson = [];
let blacklistJson = [];

// Load JSON files at startup (non-blocking)
fetch(chrome.runtime.getURL("whitelist.json"))
  .then(r => r.json())
  .then(data => { whitelistJson = data; })
  .catch(e => console.warn("Failed to load whitelist.json:", e));

fetch(chrome.runtime.getURL("blacklist.json"))
  .then(r => r.json())
  .then(data => { blacklistJson = data; })
  .catch(e => console.warn("Failed to load blacklist.json:", e));

import { SAFE_BROWSING_API_KEY } from "./config.js";
const searchEngines = ["www.google.com", "www.bing.com", "search.yahoo.com", "duckduckgo.com"];

// Expand short URLs (HEAD -> fallback GET could be added)
async function expandUrl(url) {
  try {
    const domain = new URL(url).hostname;
    const shorteners = ["bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","buff.ly"];
    if (!shorteners.includes(domain)) return url;
    const resp = await fetch(url, { method: "HEAD", redirect: "manual" });
    if (resp.status >= 300 && resp.status < 400 && resp.headers.get("Location")) {
      const loc = resp.headers.get("Location");
      return loc.startsWith("http") ? loc : new URL(loc, url).href;
    }
  } catch (e) {
    // ignore, return original
  }
  return url;
}

// Mandatory Safe Browsing check
async function checkSafeBrowsing(url) {
  try {
    const apiUrl = `https://safebrowsing.googleapis.com/v5/threatMatches:find?key=${SAFE_BROWSING_API_KEY}`;
    const body = {
      client: { clientId: "ClickDefender", clientVersion: "1.0" },
      threatInfo: {
        threatTypes: ["MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE","POTENTIALLY_HARMFUL_APPLICATION"],
        platformTypes: ["ANY_PLATFORM"],
        threatEntryTypes: ["URL"],
        threatEntries: [{ url }]
      }
    };
    const resp = await fetch(apiUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
    const data = await resp.json();
    if (data && data.matches && data.matches.length > 0) return { malicious: true, info: data.matches };
  } catch (e) {
    console.warn("Safe Browsing request failed:", e);
    // On network/SB failure we treat as not malicious but log error.
  }
  return { malicious: false, info: null };
}

// Heuristics with base score = 30
function runSimpleHeuristics(url) {
  const base = 30;
  let scoreDelta = 0;
  const reasons = [];

  if (!url) return { score: base, reasons: ["No URL"] };

  const lower = url.toLowerCase();
  if (lower.startsWith("https://")) { scoreDelta -= 10; reasons.push("Uses HTTPS"); }
  else if (lower.startsWith("http://")) { scoreDelta += 10; reasons.push("No HTTPS"); }

  if (url.length > 75) { scoreDelta += 18; reasons.push("Long URL (>75 chars)"); }
  if (lower.includes("@")) { scoreDelta += 50; reasons.push("Contains '@' (likely cloaking)"); }

  try {
    const host = new URL(url).hostname;
    const dotCount = (host.match(/\./g) || []).length;
    if (dotCount >= 3) { scoreDelta += 12; reasons.push("Multiple subdomains"); }
    if (host.includes("-")) { scoreDelta += 8; reasons.push("Hyphen in domain name"); }
    const shortList = ["bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","buff.ly"];
    if (shortList.some(s => host.includes(s))) { scoreDelta += 20; reasons.push("URL shortener detected"); }
  } catch (e) {
    scoreDelta += 5; reasons.push("Malformed URL");
  }

  const final = Math.min(100, Math.max(0, base + scoreDelta));
  return { score: final, reasons };
}

// Storage helpers
async function getLists() {
  const store = await chrome.storage.local.get(["whitelist","blacklist"]);
  return {
    whitelist: store.whitelist || [],
    blacklist: store.blacklist || []
  };
}

async function addToList(listName, value) {
  const store = await chrome.storage.local.get([listName]);
  const arr = store[listName] || [];
  if (!arr.includes(value)) arr.push(value);
  await chrome.storage.local.set({ [listName]: arr });
}

// Main analysis: JSON whitelist/blacklist -> local lists -> Safe Browsing (mandatory) -> heuristics
async function analyzeUrlForTab(originalUrl) {
  const expanded = await expandUrl(originalUrl).catch(() => originalUrl);
  const domain = (() => { try { return new URL(expanded).hostname.replace(/^www\./, ""); } catch { return expanded; } })();

  // JSON whitelist
  if (whitelistJson && whitelistJson.some(e => {
    if (!e) return false;
    const dr = e.domain_root || "";
    const u = e.url || "";
    return (dr && dr.replace(/^www\./,"") === domain) || u === expanded;
  })) {
    return { url: expanded, domain, status: "whitelisted", score: 0, reasons: ["Domain in whitelist.json"] };
  }

  // JSON blacklist (also capture reason field)
  const blMatch = (blacklistJson || []).find(e => {
    if (!e) return false;
    const dr = e.domain_root || "";
    const u = e.url || "";
    return (dr && dr.replace(/^www\./,"") === domain) || u === expanded;
  });
  if (blMatch) {
    const r = [];
    if (blMatch.reason) r.push(blMatch.reason);
    return { url: expanded, domain, status: "blacklisted", score: 100, reasons: r.length ? r : ["In blacklist.json"] };
  }

  // Local storage lists
  const { whitelist, blacklist } = await getLists();
  if ((whitelist || []).some(x => x === domain || x === expanded)) {
    return { url: expanded, domain, status: "whitelisted", score: 0, reasons: ["Previously marked SAFE"] };
  }
  if ((blacklist || []).some(x => x === domain || x === expanded)) {
    // attempt to find reason from blacklist.json
    const jsonReason = (blacklistJson || []).find(e => e.url === expanded || (e.domain_root && e.domain_root.replace(/^www\./,"") === domain))?.reason;
    return { url: expanded, domain, status: "blacklisted", score: 100, reasons: [jsonReason || "Previously marked UNSAFE"] };
  }

  // Mandatory Safe Browsing check
  const sb = await checkSafeBrowsing(expanded);
  if (sb.malicious) {
    // include match details if present and include generic reason
    return { url: expanded, domain, status: "known_phish", score: 100, reasons: ["Listed in Safe Browsing API"], sb };
  }

  // Heuristics fallback (only after Safe Browsing returned safe)
  const heur = runSimpleHeuristics(expanded);
  return { url: expanded, domain, status: "unknown", score: heur.score, reasons: heur.reasons };
}

// Track clicked links (content scripts)
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.action === "linkClicked" && msg.url) {
    expandUrl(msg.url).then(expanded => { lastClickedUrl = expanded; });
    return;
  }

  if (msg.action === "getLastClickedUrl") {
    sendResponse({ url: lastClickedUrl });
    return;
  }

  if (msg.action === "analyzeUrl" && msg.url) {
    analyzeUrlForTab(msg.url).then(result => sendResponse(result));
    return true;
  }

  if (msg.action === "addToWhitelist") {
    addToList("whitelist", msg.value).then(() => sendResponse({ ok: true }));
    return true;
  }

  if (msg.action === "addToBlacklist") {
    addToList("blacklist", msg.value).then(() => sendResponse({ ok: true }));
    return true;
  }
});