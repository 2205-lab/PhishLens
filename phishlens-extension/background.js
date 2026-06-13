// PhishLens AI Agent — background.js
// 1. Intercepts navigation, scores the URL, redirects to blocked.html if dangerous
// 2. Responds to SCORE_URL messages from content.js (hover badges on links)

const API = "http://localhost:5000/score";
const checkedCache = new Map(); // url -> result
const CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour

// Risk levels that trigger a full block page on navigation.
const BLOCK_RISK_LEVELS = ["CRITICAL", "HIGH", "MEDIUM"];

async function scoreUrl(url) {
  if (checkedCache.has(url)) return checkedCache.get(url);

  const res = await fetch(API, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url: url })
  });

  if (!res.ok) throw new Error("Server returned " + res.status);

  const data = await res.json();
  checkedCache.set(url, data);
  setTimeout(() => checkedCache.delete(url), CACHE_TTL_MS);
  return data;
}

// ── 1. Navigation interception (auto-block) ──────────────────────
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return; // main frame only
  const url = details.url;
  if (!url.startsWith("http")) return;
  if (url.includes(chrome.runtime.id)) return; // skip our own blocked.html

  try {
    const data = await scoreUrl(url);
    chrome.storage.local.set({ lastResult: { url, ...data } });

    const isDangerous =
      data.status === "phishing" && BLOCK_RISK_LEVELS.includes(data.risk_level);

    if (isDangerous) {
      const blockedUrl =
        chrome.runtime.getURL("blocked.html") +
        `?url=${encodeURIComponent(url)}` +
        `&risk=${encodeURIComponent(data.risk_level)}` +
        `&prob=${encodeURIComponent(data.confidence)}`;
      chrome.tabs.update(details.tabId, { url: blockedUrl });
    }
  } catch (e) {
    console.warn("PhishLens: scoring failed for", url, e);
    // fail open
  }
});

// ── 2. Message handler for content.js (hover badges) ─────────────
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "SCORE_URL") {
    scoreUrl(msg.url)
      .then(data => sendResponse(data))
      .catch(() => sendResponse(null));
    return true; // keep the message channel open for async response
  }
});
