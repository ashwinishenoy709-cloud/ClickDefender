document.addEventListener("DOMContentLoaded", async () => {
  const tabAnalysis = document.getElementById('tab-analysis');
  const tabDetails = document.getElementById('tab-details');
  const viewAnalysis = document.getElementById('view-analysis');
  const viewDetails = document.getElementById('view-details');

  let detailsLoaded = false;
  let activeTabInfo = null;

  tabAnalysis.addEventListener('click', () => {
    tabAnalysis.classList.add('active'); 
    tabDetails.classList.remove('active');
    viewAnalysis.classList.add('active'); 
    viewDetails.classList.remove('active');
  });

  tabDetails.addEventListener('click', async () => {
    tabDetails.classList.add('active'); 
    tabAnalysis.classList.remove('active');
    viewDetails.classList.add('active'); 
    viewAnalysis.classList.remove('active');
    if (!detailsLoaded && activeTabInfo) {
      detailsLoaded = true; 
      loadDetailsView(activeTabInfo);
    }
  });

  activeTabInfo = await getActiveTabInfo();
  if (activeTabInfo) loadAnalysisView(activeTabInfo); 
  else {
    document.getElementById("score-text").textContent = '--';
    document.getElementById("status-text").textContent = 'No Page';
    document.getElementById("reasons-list").innerHTML = `<div>Cannot access the current page.</div>`;
  }
});

// --- Analysis View Logic (Working) ---
async function loadAnalysisView(tabInfo) {
  const scoreTextEl = document.getElementById("score-text");
  const statusTextEl = document.getElementById("status-text");
  const gaugeArcEl = document.getElementById("gauge-arc");
  const reasonsListEl = document.getElementById("reasons-list");
  const continueBtn = document.getElementById("continueBtn");
  const exitBtn = document.getElementById("exitBtn");
  const msgEl = document.getElementById("msg");

  function updateUI(result) {
    if (!result || typeof result.score !== 'number') {
      scoreTextEl.textContent = '??';
      statusTextEl.textContent = 'Analysis Failed';
      gaugeArcEl.style.borderColor = '#6c757d';
      gaugeArcEl.style.transform = `rotate(0deg)`;
      reasonsListEl.innerHTML = `<div>Could not analyze this page.</div>`;
      return;
    }

    const { score, reasons } = result;
    scoreTextEl.textContent = score;
    const rotation = Math.min(180, (score / 100) * 180);
    gaugeArcEl.style.transform = `rotate(${rotation}deg)`;

    if (score <= 25) {
      statusTextEl.textContent = 'SAFE';
      statusTextEl.style.color = 'var(--green)';
      gaugeArcEl.style.borderColor = 'var(--green)';
    } else if (score < 85) {
      statusTextEl.textContent = 'SUSPICIOUS';
      statusTextEl.style.color = 'var(--yellow)';
      gaugeArcEl.style.borderColor = 'var(--yellow)';
    } else {
      statusTextEl.textContent = 'DANGEROUS';
      statusTextEl.style.color = 'var(--red)';
      gaugeArcEl.style.borderColor = 'var(--red)';
    }

    reasonsListEl.innerHTML = '';
    if (reasons && reasons.length > 0) {
      reasons.forEach(reason => {
        const isNegative = reason.includes('(-');
        const icon = isNegative ? '🛡️' : '⚠️';
        const color = isNegative ? 'var(--green)' : 'var(--red)';
        const reasonEl = document.createElement('div');
        reasonEl.className = 'reason-item';
        reasonEl.innerHTML = `<div class="reason-icon" style="color: ${color};">${icon}</div>
          <div class="reason-text">${reason.replace(/\(\S+\)/, '').trim()} <span style="color: #888; font-size: 11px;">${reason.match(/\(\S+\)/)?.[0] || ''}</span></div>`;
        reasonsListEl.appendChild(reasonEl);
      });
    } else {
      reasonsListEl.innerHTML = `<div class="reason-item"><div class="reason-icon">✅</div><div class="reason-text">No specific risks found.</div></div>`;
    }

    continueBtn.onclick = () => {
      chrome.runtime.sendMessage({ action: "addToWhitelist", value: result.url }, () => {
        msgEl.textContent = "✅ Marked as SAFE and whitelisted.";
        msgEl.style.color = "var(--green)";
        setTimeout(() => window.close(), 800);
      });
    };
    exitBtn.onclick = () => {
      chrome.runtime.sendMessage({ action: "addToBlacklist", value: result.url }, () => {
        msgEl.textContent = "❌ Marked as UNSAFE and blacklisted.";
        msgEl.style.color = "var(--red)";
        setTimeout(() => window.close(), 800);
      });
    };
  }

  if (!tabInfo || !tabInfo.url || !tabInfo.url.startsWith('http')) {
    updateUI(null); return;
  }
  const result = await getAnalysisResult(tabInfo);
  updateUI(result);
}

// --- Details View Logic (Working) ---
async function loadDetailsView(tabInfo) {
  const loadingEl = document.getElementById('details-loading');
  const contentEl = document.getElementById('details-content');
  if (!tabInfo || !tabInfo.url || !tabInfo.url.startsWith('http')) {
    loadingEl.textContent = "Cannot analyze browser or local pages."; return;
  }

  loadingEl.classList.remove('hidden'); contentEl.classList.add('hidden');

  const [pageData, cookieData] = await Promise.all([getOnPageData(tabInfo.id), getCookieData(tabInfo.url)]);

  if (!pageData) { loadingEl.textContent = "Failed to get data. Reload page."; return; }

  loadingEl.classList.add('hidden'); contentEl.classList.remove('hidden');

  const createStatus = (status) => `<span class="status-icon ${status}">●</span>`;

  // Core Vitals
  const fcpEl = document.getElementById('vitals-fcp');
  const clsEl = document.getElementById('vitals-cls');
  const loadTimeEl = document.getElementById('vitals-load-time');

  const fcp = pageData.performance?.fcp; 
  fcpEl.textContent = fcp ? `${fcp.toFixed(0)}ms` : 'N/A';
  if(fcp) fcpEl.style.color = fcp > 3000 ? 'var(--status-bad)' : fcp > 1800 ? 'var(--status-warn)' : 'var(--status-good)';

  const cls = pageData.performance?.cls;
  clsEl.textContent = cls ? cls.toFixed(3) : 'N/A';
  if(cls) clsEl.style.color = cls > 0.25 ? 'var(--status-bad)' : cls > 0.1 ? 'var(--status-warn)' : 'var(--status-good)';

  loadTimeEl.textContent = pageData.loadTime ? `${pageData.loadTime}ms` : 'N/A';

  // Composition
  const formatBytes = (bytes) => { if(!bytes && bytes!==0) return "N/A"; const kb = bytes/1024; return kb>1000 ? `${(kb/1024).toFixed(1)} MB` : `${kb.toFixed(0)} KB`; };
  document.getElementById('comp-total').textContent = formatBytes(pageData.performance?.pageWeight?.total);
  document.getElementById('comp-js').textContent = formatBytes(pageData.performance?.pageWeight?.js);
  document.getElementById('comp-img').textContent = formatBytes(pageData.performance?.pageWeight?.image);

  // Privacy
  document.getElementById('priv-https').innerHTML = pageData.isSecure ? `${createStatus('good')} Yes` : `${createStatus('bad')} No`;
  const cookieCount = cookieData.count ?? 0;
  const cookieStatus = cookieCount < 20 ? 'good' : cookieCount < 50 ? 'warn' : 'bad';
  document.getElementById('priv-cookies').innerHTML = `${createStatus(cookieStatus)} ${cookieCount}`;
  const thirdPartyScriptCount = pageData.security?.thirdPartyScripts ?? 0;
  const scriptStatus = thirdPartyScriptCount < 5 ? 'good' : thirdPartyScriptCount < 15 ? 'warn' : 'bad';
  document.getElementById('priv-3p-scripts').innerHTML = `${createStatus(scriptStatus)} ${thirdPartyScriptCount}`;

  // SEO & Accessibility
  const titleLength = pageData.seo?.title?.length || 0;
  const titleStatus = titleLength > 10 && titleLength < 60 ? 'good' : 'warn';
  document.getElementById('seo-title').innerHTML = `${createStatus(titleStatus)} ${titleLength} chars`;

  const descItem = document.getElementById('seo-desc-item');
  const descStatusEl = document.getElementById('seo-desc');
  const descFullEl = document.getElementById('seo-desc-full');
  if(pageData.seo?.description) {
    descStatusEl.innerHTML = `${createStatus('good')} Present`;
    descFullEl.textContent = pageData.seo.description;
    descItem.onclick = () => descFullEl.classList.toggle('hidden');
  } else {
    descStatusEl.innerHTML = `${createStatus('bad')} Missing`;
    descFullEl.classList.add('hidden');
    descItem.onclick = null;
  }

  const h1Count = pageData.accessibility?.h1Count ?? 0;
  const h1Status = h1Count === 1 ? 'good' : 'bad';
  document.getElementById('seo-h1').innerHTML = `${createStatus(h1Status)} ${h1Count} found`;

  const altCount = pageData.accessibility?.missingAlts ?? 0;
  const altStatus = altCount === 0 ? 'good' : altCount < 5 ? 'warn' : 'bad';
  document.getElementById('seo-alt').innerHTML = `${createStatus(altStatus)} ${altCount} missing`;
}

// --- Data Helpers ---
async function getActiveTabInfo() { const [tab] = await chrome.tabs.query({ active:true,currentWindow:true }); return tab||null; }
async function getAnalysisResult(tabInfo) {
  const cached = await chrome.storage.local.get("lastAnalysis");
  if(cached.lastAnalysis?.url===tabInfo.url) return cached.lastAnalysis;
  const pageData = await getOnPageData(tabInfo.id);
  const domSignals = pageData?.domSignals;
  return new Promise(resolve => chrome.runtime.sendMessage({ action:"analyzeUrl", url:tabInfo.url, domSignals }, result=>{
    if(chrome.runtime.lastError) resolve(null); else resolve(result);
  }));
}
async function getOnPageData(tabId) {
  try { return await chrome.tabs.sendMessage(tabId,{action:"requestPageData"}); } catch { return null; }
}
async function getCookieData(url) {
  try { const cookies = await chrome.cookies.getAll({url}); return { count: cookies.length }; } catch { return { count: 'N/A' }; }
}
