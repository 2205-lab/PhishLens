"""
PhishLens Live Agent v3
========================
Feeds REAL URLs into scoring API from live sources only:
  - OpenPhish feed
  - PhishTank feed
  - Email inbox monitor (optional)

Synthetic/fake URL generator has been REMOVED — every URL on the
dashboard now comes from a real external source.

Secrets are read from environment variables / a .env file — nothing
is hardcoded. Copy .env.example to .env and fill in your own values.

Run: py phishlens_live_agent.py
"""

import os, time, json, random, imaplib, email, logging, threading, re, smtplib
from datetime import datetime
from urllib.parse import urlparse
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

import requests
import schedule
from dotenv import load_dotenv

load_dotenv()  # reads .env file in the same folder

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("PhishLens")

# ── CONFIG (from environment / .env — never hardcoded) ───────────
SPLUNK_HEC_URL   = os.getenv("SPLUNK_HEC_URL", "http://localhost:8088/services/collector")
SPLUNK_HEC_TOKEN = os.getenv("SPLUNK_HEC_TOKEN", "")
PHISHLENS_API    = os.getenv("PHISHLENS_API", "http://localhost:5000/score")

EMAIL_HOST = os.getenv("EMAIL_HOST", "imap.gmail.com")
EMAIL_USER = os.getenv("EMAIL_USER", "")
EMAIL_PASS = os.getenv("EMAIL_PASS", "")
ALERT_TO   = os.getenv("ALERT_TO", "")
SMTP_HOST  = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT  = int(os.getenv("SMTP_PORT", "587"))

ENABLE_EMAIL_ALERTS = os.getenv("ENABLE_EMAIL_ALERTS", "false").lower() == "true"
ENABLE_EMAIL_MONITOR = bool(EMAIL_USER and EMAIL_PASS)

FEED_INTERVAL_OPENPHISH  = 300    # every 5 min
FEED_INTERVAL_PHISHTANK  = 600    # every 10 min
FEED_INTERVAL_EMAIL      = 28800  # every 8 hours
BATCH_SIZE = 20

alerted_urls = set()

# ── SPLUNK HEC ────────────────────────────────────────────────────
def send_to_splunk(events):
    if not events or not SPLUNK_HEC_TOKEN:
        if not SPLUNK_HEC_TOKEN:
            log.error("SPLUNK_HEC_TOKEN not set — events not sent. Check your .env file.")
        return
    headers = {
        "Authorization": f"Splunk {SPLUNK_HEC_TOKEN}",
        "Content-Type": "application/json"
    }
    payload = ""
    for ev in events:
        payload += json.dumps({
            "time": ev.get("timestamp", time.time()),
            "host": "phishlens-agent",
            "source": ev.get("source", "phishlens_live"),
            "sourcetype": "_json",
            "index": "main",
            "event": ev
        }) + "\n"
    try:
        r = requests.post(SPLUNK_HEC_URL, headers=headers, data=payload, timeout=10)
        if r.status_code == 200:
            log.info(f"✅ Sent {len(events)} events to Splunk HEC")
        else:
            log.error(f"HEC error {r.status_code}: {r.text}")
    except Exception as e:
        log.error(f"HEC connection failed: {e}")


# ── EMAIL ALERT ───────────────────────────────────────────────────
def send_alert_email(threat):
    if not ENABLE_EMAIL_ALERTS:
        return
    if not EMAIL_USER or not EMAIL_PASS or not ALERT_TO:
        return
    url = threat.get("url", "unknown")
    if url in alerted_urls:
        return
    alerted_urls.add(url)
    try:
        msg = MIMEMultipart()
        msg["Subject"] = "PhishLens Alert - High-Risk URL Flagged"
        msg["From"] = EMAIL_USER
        msg["To"] = ALERT_TO
        body = f"""
        <h2 style="color:red">PhishLens Agent - Threat Flagged for Review</h2>
        <p><b>URL:</b> {url}</p>
        <p><b>Risk:</b> {threat.get("risk_level","CRITICAL")}</p>
        <p><b>Action:</b> Flagged for SOC review / browser extension check</p>
        <p><b>Confidence:</b> {threat.get("confidence",0.95):.1%}</p>
        <p><b>Time:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        """
        msg.attach(MIMEText(body, "html"))
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
            s.starttls()
            s.login(EMAIL_USER, EMAIL_PASS)
            s.sendmail(EMAIL_USER, ALERT_TO, msg.as_string())
        log.info(f"📧 ALERT EMAIL SENT for {url[:60]}")
    except Exception as e:
        log.error(f"Alert email failed: {e}")


# ── SCORING ───────────────────────────────────────────────────────
def score_url(url, source):
    try:
        r = requests.post(PHISHLENS_API, json={"url": url, "source": source}, timeout=15)
        if r.status_code == 200:
            result = r.json()
            result["source"] = source
            result["timestamp"] = time.time()
            return result
    except Exception as e:
        log.error(f"Score error: {e}")
    return None

def score_batch(urls, source):
    results = []
    for url in urls[:BATCH_SIZE]:
        ev = score_url(url, source)
        if ev:
            results.append(ev)
            icon = "🔴" if ev.get("status") == "phishing" else "🟢"
            log.info(f"{icon} [{ev.get('risk_level','?')}] {url[:80]}")
            if ev.get("risk_level") == "CRITICAL":
                send_alert_email(ev)
    if results:
        send_to_splunk(results)
    return results


# ── SOURCE 1: OpenPhish ───────────────────────────────────────────
def fetch_openphish():
    try:
        r = requests.get("https://openphish.com/feed.txt", timeout=20)
        urls = [u.strip() for u in r.text.splitlines() if u.strip().startswith("http")]
        log.info(f"OpenPhish: fetched {len(urls)} URLs")
        return random.sample(urls, min(BATCH_SIZE, len(urls)))
    except Exception as e:
        log.error(f"OpenPhish fetch failed: {e}")
        return []

def run_openphish():
    log.info("🔄 Running OpenPhish feeder...")
    urls = fetch_openphish()
    if urls:
        score_batch(urls, "openphish_feed")


# ── SOURCE 2: PhishTank ───────────────────────────────────────────
def fetch_phishtank():
    try:
        r = requests.get(
            "http://data.phishtank.com/data/online-valid.json",
            headers={"User-Agent": "PhishLens/1.0"},
            timeout=30
        )
        data = r.json()
        urls = [e["url"] for e in data if e.get("url")]
        log.info(f"PhishTank: fetched {len(urls)} URLs")
        return random.sample(urls, min(BATCH_SIZE, len(urls)))
    except Exception as e:
        log.error(f"PhishTank fetch failed: {e}")
        return []

def run_phishtank():
    log.info("🔄 Running PhishTank feeder...")
    urls = fetch_phishtank()
    if urls:
        score_batch(urls, "phishtank_feed")


# ── SOURCE 3: Email Monitor (optional — only runs if EMAIL_USER/PASS set) ──
URL_REGEX = re.compile(r'https?://[^\s\'"<>]+')

def extract_urls_from_email(msg):
    urls = []
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() in ("text/plain", "text/html"):
                try:
                    body = part.get_payload(decode=True).decode(errors="ignore")
                    urls.extend(URL_REGEX.findall(body))
                except Exception:
                    pass
    else:
        try:
            body = msg.get_payload(decode=True).decode(errors="ignore")
            urls.extend(URL_REGEX.findall(body))
        except Exception:
            pass
    seen = set()
    safe = {"google.com", "microsoft.com", "apple.com", "github.com", "linkedin.com"}
    result = []
    for u in urls:
        domain = urlparse(u).netloc.lower().replace("www.", "")
        if u not in seen and not any(s in domain for s in safe):
            seen.add(u)
            result.append(u)
    return result

def run_email_monitor():
    if not ENABLE_EMAIL_MONITOR:
        return
    log.info("📧 Checking inbox...")
    try:
        mail = imaplib.IMAP4_SSL(EMAIL_HOST)
        mail.login(EMAIL_USER, EMAIL_PASS)
        mail.select("INBOX")
        _, msg_ids = mail.search(None, "UNSEEN")
        ids = msg_ids[0].split()
        all_urls = []
        for mid in ids[-20:]:
            _, data = mail.fetch(mid, "(RFC822)")
            msg = email.message_from_bytes(data[0][1])
            all_urls.extend(extract_urls_from_email(msg))
            mail.store(mid, "+FLAGS", "\\Seen")
        mail.logout()
        if all_urls:
            log.info(f"Email: {len(all_urls)} URLs to score")
            score_batch(all_urls, "email_monitor")
    except Exception as e:
        log.error(f"Email monitor failed: {e}")


# ── MAIN SCHEDULER ────────────────────────────────────────────────
def start():
    schedule.every(FEED_INTERVAL_OPENPHISH).seconds.do(run_openphish)
    schedule.every(FEED_INTERVAL_PHISHTANK).seconds.do(run_phishtank)
    if ENABLE_EMAIL_MONITOR:
        schedule.every(FEED_INTERVAL_EMAIL).seconds.do(run_email_monitor)

    log.info("=" * 55)
    log.info("  PhishLens Live Agent v3 (real feeds only)")
    log.info(f"  Scoring API    : {PHISHLENS_API}")
    log.info(f"  Splunk HEC     : {SPLUNK_HEC_URL}")
    log.info(f"  HEC token set  : {'YES' if SPLUNK_HEC_TOKEN else 'NO - set SPLUNK_HEC_TOKEN in .env'}")
    log.info(f"  Email monitor  : {'ON' if ENABLE_EMAIL_MONITOR else 'OFF (set EMAIL_USER/EMAIL_PASS to enable)'}")
    log.info(f"  Email alerts   : {'ON' if ENABLE_EMAIL_ALERTS else 'OFF'}")
    log.info(f"  OpenPhish      : every {FEED_INTERVAL_OPENPHISH}s")
    log.info(f"  PhishTank      : every {FEED_INTERVAL_PHISHTANK}s")
    log.info("=" * 55)

    # Run feeders once immediately at startup
    feeders = [run_openphish, run_phishtank]
    if ENABLE_EMAIL_MONITOR:
        feeders.append(run_email_monitor)
    for fn in feeders:
        threading.Thread(target=fn, daemon=True).start()

    time.sleep(5)

    while True:
        schedule.run_pending()
        time.sleep(1)


if __name__ == "__main__":
    start()