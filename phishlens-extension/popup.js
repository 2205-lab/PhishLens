const PHISHLENS_API = "http://localhost:5000/score";

chrome.storage.local.get(["total","blocked","safe"], data => {
  document.getElementById("stat-scanned").textContent = data.total || 0;
  document.getElementById("stat-blocked").textContent = data.blocked || 0;
  document.getElementById("stat-safe").textContent = data.safe || 0;
});

chrome.tabs.query({active: true, currentWindow: true}, async tabs => {
  const tab = tabs[0];
  const url = tab.url;
  document.getElementById("current-url").textContent = url || "Unknown";

  if (!url || !url.startsWith("http") || url.includes("localhost")) {
    setResult("result-unknown", "⬡", "INTERNAL PAGE", "Not scanned");
    return;
  }

  try {
    const r = await fetch(PHISHLENS_API, {
      method: "POST",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify({url, source:"popup_scan"})
    });
    const data = await r.json();
    displayResult(data);
  } catch(e) {
    setResult("result-unknown", "⬡", "API OFFLINE", "Start server.py to enable scanning");
  }
});

function displayResult(data) {
  const risk = data.risk_level || "SAFE";
  const conf = Math.round((data.confidence || 0.5) * 100);
  let cls, icon, label, desc;
  if (risk === "CRITICAL") {
    cls="result-critical"; icon="🚨"; label="CRITICAL THREAT"; desc=conf+"% phishing · FLAGGED CRITICAL";
  } else if (risk === "HIGH") {
    cls="result-high"; icon="⚠️"; label="HIGH RISK"; desc=conf+"% phishing · Proceed with caution";
  } else if (risk === "MEDIUM") {
    cls="result-medium"; icon="⚡"; label="SUSPICIOUS"; desc=conf+"% phishing · Flagged for review";
  } else {
    cls="result-safe"; icon="✅"; label="VERIFIED SAFE"; desc=conf+"% confidence · Safe to browse";
  }
  setResult(cls, icon, label, desc);

  chrome.storage.local.get(["total","blocked","safe"], d => {
    const total = (d.total||0)+1;
    const blocked = (d.blocked||0)+(risk==="CRITICAL"||risk==="HIGH"?1:0);
    const safe = (d.safe||0)+(data.status==="phishing"?0:1);
    chrome.storage.local.set({total, blocked, safe});
    document.getElementById("stat-scanned").textContent = total;
    document.getElementById("stat-blocked").textContent = blocked;
    document.getElementById("stat-safe").textContent = safe;
  });
}

function setResult(cls, icon, label, desc) {
  document.getElementById("scan-result").className = "scan-result " + cls;
  document.getElementById("result-icon").textContent = icon;
  document.getElementById("result-label").textContent = label;
  document.getElementById("result-conf").textContent = desc;
}

document.getElementById("scan-btn").addEventListener("click", async () => {
  const url = document.getElementById("url-input").value.trim();
  if (!url) return;
  setResult("result-unknown", "⬡", "SCANNING...", url.slice(0,40));
  try {
    const r = await fetch(PHISHLENS_API, {
      method:"POST", headers:{"Content-Type":"application/json"},
      body: JSON.stringify({url, source:"manual_popup_scan"})
    });
    const data = await r.json();
    displayResult(data);
  } catch(e) {
    setResult("result-unknown","⬡","API OFFLINE","Start server.py first");
  }
});

document.getElementById("url-input").addEventListener("keydown", e => {
  if (e.key === "Enter") document.getElementById("scan-btn").click();
});
