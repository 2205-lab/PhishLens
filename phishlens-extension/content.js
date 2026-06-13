const PHISHLENS_API = "http://localhost:5000/score";
const scannedUrls = new Map();

const tooltip = document.createElement("div");
tooltip.id = "phishlens-tooltip";
tooltip.style.cssText = `
  position: fixed;
  z-index: 2147483647;
  bottom: 20px;
  right: 20px;
  padding: 8px 14px;
  border-radius: 4px;
  font-family: 'Courier New', monospace;
  font-size: 12px;
  font-weight: 600;
  letter-spacing: 0.5px;
  pointer-events: none;
  display: none;
  box-shadow: 0 4px 20px rgba(0,0,0,0.4);
  border-left: 3px solid;
  backdrop-filter: blur(8px);
`;
document.body.appendChild(tooltip);

function showTooltip(data) {
  const { status, risk_level, confidence } = data;
  const isPhishing = status === "phishing";
  const conf = Math.round((confidence || 0.5) * 100);
  let bg, border, text, icon;
  if (risk_level === "CRITICAL") {
    bg = "rgba(30,0,0,0.95)"; border = "#ff2244"; text = "#ff6688"; icon = "🚨";
  } else if (risk_level === "HIGH") {
    bg = "rgba(30,15,0,0.95)"; border = "#ff8800"; text = "#ffaa44"; icon = "⚠️";
  } else if (risk_level === "MEDIUM") {
    bg = "rgba(30,28,0,0.95)"; border = "#ffdd00"; text = "#ffee66"; icon = "⚡";
  } else {
    bg = "rgba(0,20,10,0.95)"; border = "#00ff88"; text = "#00cc66"; icon = "✅";
  }
  tooltip.style.background = bg;
  tooltip.style.borderLeftColor = border;
  tooltip.style.color = text;
  tooltip.innerHTML = `${icon} PhishLens: <strong>${isPhishing ? risk_level : "SAFE"}</strong> · ${conf}% confidence`;
  tooltip.style.display = "block";
}

function hideTooltip() {
  tooltip.style.display = "none";
}

async function scanLink(url) {
  if (scannedUrls.has(url)) return scannedUrls.get(url);
  if (!url.startsWith("http") || url.includes("localhost")) return null;
  try {
    const result = await chrome.runtime.sendMessage({ type: "SCORE_URL", url });
    scannedUrls.set(url, result);
    return result;
  } catch (e) {
    return null;
  }
}

function attachListeners() {
  document.querySelectorAll("a[href]").forEach(link => {
    if (link.dataset.phishlens) return;
    link.dataset.phishlens = "1";
    const url = link.href;
    if (!url.startsWith("http") || url.includes("localhost")) return;

    link.addEventListener("mouseenter", async (e) => {
      const result = await scanLink(url);
      if (result) showTooltip(result);
    });

    link.addEventListener("mouseleave", hideTooltip);

    link.addEventListener("mouseenter", async () => {
      const result = await scanLink(url);
      if (!result) return;
      if (result.risk_level === "CRITICAL") {
        link.style.outline = "2px solid #ff2244";
        link.style.outlineOffset = "2px";
      } else if (result.risk_level === "HIGH") {
        link.style.outline = "2px solid #ff8800";
        link.style.outlineOffset = "2px";
      }
    });
  });
}

attachListeners();
const observer = new MutationObserver(() => attachListeners());
observer.observe(document.body, { childList: true, subtree: true });
