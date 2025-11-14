// content.js

(async function() {
  if (window.self !== window.top) {
    return;
  }

  // LISTENER FOR POPUP'S "DETAILS" TAB
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'requestPageData') {
      collectAllPageData().then(pageData => sendResponse(pageData));
      return true;
    }
  });

  // MAIN ANALYSIS AND ON-PAGE UI INJECTION
  const main = async () => {
    const currentUrl = window.location.href;
    const searchEngines = ["www.google.com", "www.bing.com", "duckduckgo.com"];
    try { if (searchEngines.includes(new URL(currentUrl).hostname)) return; } catch (e) {}

    const initialPageData = await collectInitialSignals();

    const result = await new Promise(resolve => {
      chrome.runtime.sendMessage({ action: "analyzeUrl", url: currentUrl, domSignals: initialPageData.domSignals }, resolve);
    });

    if (result) {
      chrome.storage.local.set({ lastAnalysis: result });
      injectUI(result);
    }
  };

  main();

  // --- UI INJECTION & DATA COLLECTION (No changes needed in these functions) ---
  function injectUI(result) { if (result.score <= 25) { injectSafeUINonModal(result); } else { injectRiskyUIModal(result); } }
  function injectRiskyUIModal(result) { document.body.style.pointerEvents = 'none'; const host = createUIHost(); const shadow = host.shadowRoot; const iconUrl = chrome.runtime.getURL("icon64.png"); const isDangerous = result.score >= 85; const badgeColor = isDangerous ? "#d63031" : "#f39c12"; const badgeIcon = isDangerous ? "🔴" : "🟡"; const badgeText = isDangerous ? "DANGEROUS" : "SUSPICIOUS"; const extraCardClass = isDangerous ? 'flicker' : ''; const cardHTML = `<style>@keyframes flicker-danger { 0%, 100% { box-shadow: 0 0 5px #d63031, 0 0 10px #d63031, 0 0 20px #d63031, 0 0 40px #ff3838; } 50% { box-shadow: 0 0 10px #d63031, 0 0 20px #d63031, 0 0 40px #ff3838, 0 0 80px #ff3838; } } :host { all: initial; } #cd-overlay { position: fixed; top: 0; left: 0; width: 100vw; height: 100vh; background: rgba(0, 0, 0, 0.6); backdrop-filter: blur(3px); z-index: 2147483646; pointer-events: auto; } #cd-card { position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%); width: 400px; padding: 20px; background: #fff; border-radius: 12px; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; color: #333; z-index: 2147483647; border: 1px solid #ddd; box-shadow: 0 10px 40px rgba(0,0,0,0.25); } #cd-card.flicker { animation: flicker-danger 1.5s infinite ease-in-out; border-color: #d63031; } .button-row { display: flex; gap: 12px; margin-top: 20px; padding-top: 15px; border-top: 1px solid #eee; } .action-button { flex: 1; cursor: pointer; font-size: 15px; font-weight: 600; text-align: center; padding: 10px; border-radius: 8px; transition: filter 0.2s ease; } .action-button:hover { filter: brightness(0.95); } .url-display { font-size: 11px; color: #6c757d; margin-top: 15px; text-align: center; word-break: break-all; border-top: 1px solid #eee; padding-top: 15px; }</style><div id="cd-overlay"></div><div id="cd-card" class="${extraCardClass}"><div style="display: flex; justify-content: space-between; align-items: center;"><div style="display: flex; align-items: center; gap: 8px;"><img src="${iconUrl}" style="width: 24px; height: 24px;"><span style="font-weight: bold; font-size: 18px; color: #000;">ClickDefender</span></div><span style="font-weight: bold; font-size: 14px; display: flex; align-items: center; gap: 6px; color: ${badgeColor};"><span style="font-size: 12px;">${badgeIcon}</span> ${badgeText}</span></div><div style="margin-top: 15px; font-size: 14px; line-height: 1.5;"><div style="margin-top: 4px;"><strong>Score:</strong> ${result.score}</div><div style="margin-top: 8px;"><strong>Reason:</strong><div style="margin-top: 4px; max-height: 120px; overflow-y: auto; font-size: 13px; padding-left: 5px;">${result.reasons.length > 0 ? result.reasons.map(reason => `<div>• ${reason}</div>`).join('') : '<span>No specific risks found.</span>'}</div></div></div><div class="button-row"><div id="cd-continue" class="action-button" style="background-color: #eaf7ee; color: #207a39;">✅ Mark as Safe & Continue</div><div id="cd-exit" class="action-button" style="background-color: #fff0f0; color: #b92c2c;">❌ Leave Page</div></div><div class="url-display"><strong>URL:</strong> <span>${result.url}</span></div></div>`; shadow.innerHTML = cardHTML; function removeDisruption() { document.body.style.pointerEvents = 'auto'; host.remove(); } shadow.querySelector("#cd-continue").addEventListener("click", () => { chrome.runtime.sendMessage({ action: "addToWhitelist", value: result.url }); removeDisruption(); }); shadow.querySelector("#cd-exit").addEventListener("click", () => { chrome.runtime.sendMessage({ action: "addToBlacklist", value: result.url }); window.location.href = "about:blank"; }); }
  function injectSafeUINonModal(result) { const host = createUIHost(); const shadow = host.shadowRoot; const iconUrl = chrome.runtime.getURL("icon64.png"); const cardHTML = `<style>:host { all: initial; } #cd-card { position: fixed; top: 20px; right: 20px; width: 350px; padding: 20px; background: #fff; border-radius: 12px; box-shadow: 0 10px 40px rgba(0,0,0,0.25); font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; color: #333; z-index: 2147483647; border: 1px solid #ddd; } .button-row { display: flex; gap: 8px; margin-top: 15px; padding-top: 15px; border-top: 1px solid #eee; } .action-button { flex: 1; cursor: pointer; font-size: 14px; font-weight: 600; text-align: center; padding: 8px; border-radius: 8px; transition: filter 0.2s ease; } .action-button:hover { filter: brightness(0.95); } .url-display { font-size: 11px; color: #6c757d; margin-top: 15px; text-align: center; word-break: break-all; border-top: 1px solid #eee; padding-top: 15px; }</style><div id="cd-card"><div style="display: flex; justify-content: space-between; align-items: center;"><div style="display: flex; align-items: center; gap: 8px;"><img src="${iconUrl}" style="width: 24px; height: 24px;"><span style="font-weight: bold; font-size: 18px; color: #000;">ClickDefender</span></div><span style="font-weight: bold; font-size: 14px; display: flex; align-items: center; gap: 6px; color: #28a745;"><span style="font-size: 12px;">✅</span> SAFE</span></div><div style="margin-top: 15px; font-size: 14px; line-height: 1.5;"><div style="margin-top: 4px;"><strong>Score:</strong> ${result.score}</div><div style="margin-top: 8px;"><strong>Reason:</strong><div style="margin-top: 4px; max-height: 80px; overflow-y: auto; font-size: 13px; padding-left: 5px;">${result.reasons.length > 0 ? result.reasons.map(reason => `<div>• ${reason}</div>`).join('') : '<span>No specific risks found.</span>'}</div></div></div><div class="button-row"><div id="cd-leave-safe" class="action-button" style="background-color: #f8d7da; color: #721c24;">Leave Page</div><div id="cd-dismiss" class="action-button" style="background-color: #f0f0f0;">Dismiss</div></div><div class="url-display"><strong>URL:</strong> <span>${result.url}</span></div></div>`; shadow.innerHTML = cardHTML; shadow.querySelector("#cd-dismiss").addEventListener("click", () => host.remove()); shadow.querySelector("#cd-leave-safe").addEventListener("click", () => { chrome.runtime.sendMessage({ action: "addToBlacklist", value: result.url }); window.location.href = "about:blank"; }); setTimeout(() => host.remove(), 10000); }
  function createUIHost() { const oldHost = document.getElementById("cd-host"); if (oldHost) oldHost.remove(); const host = document.createElement('div'); host.id = 'cd-host'; host.attachShadow({ mode: 'open' }); document.documentElement.appendChild(host); return host; }
  
  async function collectAllPageData() {
    const data = { isSecure: window.location.protocol === 'https:' };
    const perfPromise = new Promise(resolve => {
      const perfData = { fcp: null, cls: null, loadTime: null, pageWeight: { total: 0, js: 0, image: 0, css: 0 } };
      try {
        const [nav] = performance.getEntriesByType("navigation");
        if (nav) perfData.loadTime = Math.round(nav.duration);
        performance.getEntriesByType('resource').forEach(r => { perfData.pageWeight.total += r.transferSize || 0; if (r.initiatorType === 'script') perfData.pageWeight.js += r.transferSize || 0; if (r.initiatorType === 'img') perfData.pageWeight.image += r.transferSize || 0; if (r.initiatorType === 'css' || r.initiatorType === 'link') perfData.pageWeight.css += r.transferSize || 0; });
      } catch (e) {}
      try {
        new PerformanceObserver(list => { for (const entry of list.getEntriesByName('first-contentful-paint')) { perfData.fcp = entry.startTime; } }).observe({ type: "paint", buffered: true });
        new PerformanceObserver(list => { for (const entry of list.getEntries()) { if (!entry.hadRecentInput) { perfData.cls = (perfData.cls || 0) + entry.value; } } }).observe({type: 'layout-shift', buffered: true});
      } catch (e) {}
      setTimeout(() => resolve(perfData), 500);
    });
    
    // ✅ MODIFIED: SEO promise now also gets the description content.
    const seoPromise = new Promise(resolve => {
        const descEl = document.querySelector('meta[name="description"]');
        const seoData = {
            title: document.title,
            description: descEl ? descEl.content : null
        };
        resolve(seoData);
    });

    const accessibilityPromise = Promise.resolve({ h1Count: document.getElementsByTagName('h1').length, missingAlts: document.querySelectorAll('img:not([alt=""])').length });
    const securityPromise = Promise.resolve({ thirdPartyScripts: new Set(Array.from(document.scripts).map(s => s.src).filter(src => !!src && !src.startsWith(window.location.origin)).map(s => { try { return new URL(s).hostname; } catch { return null; } })).size });
    const [perfData, seoData, accData, securityData] = await Promise.all([perfPromise, seoPromise, accessibilityPromise, securityPromise]);
    data.performance = perfData;
    data.seo = seoData;
    data.accessibility = accData;
    data.security = securityData;
    data.loadTime = perfData.loadTime;
    data.domSignals = { passwordForms: document.querySelectorAll('form input[type="password"]').length };
    return data;
  }
  
  function collectInitialSignals() {
      const data = { domSignals: {} };
      try {
          data.domSignals.passwordForms = document.querySelectorAll('form input[type="password"]').length;
          data.domSignals.bodyKeywords = ["login", "verify", "update", "password", "account", "billing", "secure", "confirm"].filter(w => (document.body?.innerText || "").toLowerCase().includes(w));
      } catch(e) {}
      return data;
  }
})();