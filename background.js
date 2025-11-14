import {SAFE_BROWSING_API_KEY} from './config.js';
import {runExplainableHeuristics} from './heuristics.js';
import {SHORTENERS} from './shared_constants.js';

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

const SAFE_BROWSING_API_KEY = 'AIzaSyBD7SJp6VGCwa1-CC6q58SI5MJbFwHduWs';
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
  } catch (e) {}
  return null;
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.action === "analyzeUrl" && msg.url) {
    const tabId = sender.tab.id;
    analyzeUrlForTab(msg.url, tabId, msg.domSignals || null).then(sendResponse);
    return true;
  }
  if (msg.action === "addToWhitelist") {
    addToList("whitelist", msg.value).then(() => sendResponse({
      ok: true
    }));
    return true;
  }
  if (msg.action === "addToBlacklist") {
    addToList("blacklist", msg.value).then(() => sendResponse({
      ok: true
    }));
    return true;
  }
  if (msg.action === 'requestPageData') {
    (async () => {
      const [tab] = await chrome.tabs.query({
        active: true,
        currentWindow: true
      });
      if (tab && tab.url && tab.url.startsWith('http')) {
        try {
          const response = await chrome.tabs.sendMessage(tab.id, {
            action: 'requestPageData'
          });
          sendResponse(response);
        } catch (e) {
          sendResponse(null);
        }
      } else {
        sendResponse(null);
      }
    })();
    return true;
  }
});

async function analyzeUrlForTab(originalUrl, tabId, domSignals) {
  const [expanded, certInfo] = await Promise.all([
    expandUrl(originalUrl),
    getCertificateInfo(tabId)
  ]);

  const domain = (() => {
    try {
      return new URL(expanded).hostname.replace(/^www\./, "");
    } catch {
      return expanded;
    }
  })();

  if (whitelistJson.some(e => (e.domain_root?.replace(/^www\./, "") === domain) || e.url === expanded)) {
    return {
      url: expanded,
      domain,
      status: "whitelisted",
      score: 0,
      reasons: ["Domain in global whitelist"]
    };
  }
  const blMatch = blacklistJson.find(e => (e.domain_root?.replace(/^www\./, "") === domain) || e.url === expanded);
  if (blMatch) {
    return {
      url: expanded,
      domain,
      status: "blacklisted",
      score: 100,
      reasons: [blMatch.reason || "In global blacklist"]
    };
  }
  const {
    whitelist,
    blacklist
  } = await getLists();
  if (whitelist.some(x => x === domain || x === expanded)) {
    return {
      url: expanded,
      domain,
      status: "whitelisted",
      score: 0,
      reasons: ["Previously marked SAFE by user"]
    };
  }
  if (blacklist.some(x => x === domain || x === expanded)) {
    return {
      url: expanded,
      domain,
      status: "blacklisted",
      score: 100,
      reasons: ["Previously marked UNSAFE by user"]
    };
  }

  const sb = await checkSafeBrowsing(expanded);
  if (sb.malicious) {
    return {
      url: expanded,
      domain,
      status: "known_phish",
      score: 100,
      reasons: ["Listed in Google Safe Browsing"],
      sb
    };
  }

  const heur = runExplainableHeuristics(expanded, domSignals, certInfo);
  return {
    url: expanded,
    domain,
    status: heur.status,
    score: heur.score,
    reasons: heur.reasons
  };
}

async function getLists() {
  const store = await chrome.storage.local.get(["whitelist", "blacklist"]);
  return {
    whitelist: store.whitelist || [],
    blacklist: store.blacklist || []
  };
}
async function addToList(listName, value) {
  const store = await chrome.storage.local.get([listName]);
  const arr = store[listName] || [];
  if (!arr.includes(value)) arr.push(value);
  await chrome.storage.local.set({
    [listName]: arr
  });
}
async function expandUrl(url) {
  try {
    const domain = new URL(url).hostname;
    if (!SHORTENERS.includes(domain)) return url;
    const resp = await fetch(url, {
      method: "HEAD",
      redirect: "manual"
    });
    if (resp.status >= 300 && resp.status < 400 && resp.headers.get("Location")) {
      const loc = resp.headers.get("Location");
      return loc.startsWith("http") ? loc : new URL(loc, url).href;
    }
  } catch {}
  return url;
}
async function checkSafeBrowsing(url) {
  if (!SAFE_BROWSING_API_KEY) return {
    malicious: false,
    info: null
  };
  try {
    const apiUrl = `https://safebrowsing.googleapis.com/v5/threatMatches:find?key=${SAFE_BROWSING_API_KEY}`;
    const resp = await fetch(apiUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        client: {
          clientId: "ClickDefender",
          clientVersion: "1.0"
        },
        threatInfo: {
          threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
          platformTypes: ["ANY_PLATFORM"],
          threatEntryTypes: ["URL"],
          threatEntries: [{
            url
          }]
        }
      })
    });
    const data = await resp.json();
    if (data && data.matches && data.matches.length > 0) return {
      malicious: true,
      info: data.matches
    };
  } catch (e) {}
  return {
    malicious: false,
    info: null
  };
}