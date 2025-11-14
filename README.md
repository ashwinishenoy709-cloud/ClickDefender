```markdown
# ClickDefender

Real-time phishing detection browser extension with explainable scoring, Safe Browsing integration, and user feedback looping.

---

## Features
- Floating overlay on visited pages plus popup panel for last-clicked URL.
- Layered decision pipeline:
  1. Curated JSON whitelist/blacklist (with reasons)
  2. User feedback via `chrome.storage.local`
  3. Google Safe Browsing v5 lookup
  4. Research-inspired heuristics (URL/host + DOM cues)
- Explainable reasons for every verdict (SAFE / SUSPICIOUS / DANGEROUS).
- Offline resilience: heuristics + JSON lists work even if Safe Browsing fails.
- Redirect on “Exit” to stop navigation; “Continue” whitelists and clears overlay.

---

## Install (Developer Mode)
1. Set your Google Safe Browsing key in `config.js`.
2. Chrome → `chrome://extensions` → Enable Developer Mode → Load unpacked → select project folder.
3. After edits, click “Reload” in the extensions page.

---

## Detection Flow
1. JSON whitelist → SAFE (reason shown).
2. JSON blacklist → DANGEROUS (reason from file).
3. Local whitelist/blacklist (user feedback) override.
4. Google Safe Browsing → immediate 100 score if matched.
5. Heuristics adjust score (base 30, clamped 0–100):
   - HTTPS –10, HTTP +10
   - Long URL (>75) +12
   - Many subdomains +10
   - Hyphen in domain +6
   - URL shortener +18
   - Suspicious TLD (.zip/.mov/.tk/…) +6
   - `@` in URL +30
  - High symbol density +10
   - High entropy +10
   - IDN/punycode +18
   - Brand lookalike (edit distance ≤2) +16
   - Phishing keywords (login/verify/…) +6/10
   - Password form +8
   - External form action +14
   - Custom `onsubmit` +6
   - Invisible iframe +8
   - Right-click blocked +4
   - Title/body phishing keywords +6/+8
   - Favicon domain mismatch +8

Status mapping:
- Score ≤ 25 → SAFE
- Score ≥ 85 → DANGEROUS
- Otherwise → SUSPICIOUS

---

## Files
- `manifest.json`: MV3 configuration.
- `background.js`: loads lists, runs Safe Browsing + heuristics, handles storage/messages.
- `content.js`: overlay UI, DOM signal collection, user feedback actions.
- `popup.html/css/js`: popup UI mirroring analysis.
- `whitelist.json` / `blacklist.json`: curated baseline data (`reason` supported).
- `config.js`: Safe Browsing API key.
- `icon64.png`, `icon128.png`.

---

## References
- Dhamija et al. “Why Phishing Works” (CHI 2006)
- Zhang et al. “CANTINA” (WWW 2007) & Xiang et al. “CANTINA+” (IEEE TDSC 2011)
- Ma et al. “Beyond Blacklists / Learning to Detect Malicious URLs” (KDD 2009, ACM TIST 2011)
- Canali et al. “Prophiler” (WWW 2011)
- Kintis et al. “Typosquatting and Lookalike Domains” (NDSS 2017)
- Jain & Gupta “Survey of Phishing Techniques and Detection” (IEEE Comms Surveys 2018)
- Google Safe Browsing documentation/papers

```