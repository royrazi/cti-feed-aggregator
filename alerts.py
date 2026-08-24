import requests
from config import TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, logging

CLOUD_PROVIDERS = ["DigitalOcean", "Amazon", "Hetzner", "Google", "OVH"]


def should_send_alert(ioc, is_new):
    if is_new and ioc["score"] == 100 and len(ioc["sources"]) >= 2:
        for provider in CLOUD_PROVIDERS:
            if provider in ioc["isp"]:
                return True
    return False


def send_telegram_alert(ioc):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    sources_str = ", ".join(ioc["sources"])

    message_text = (
        f"🚨 <b>CRITICAL CYBER THREAT DETECTED</b> 🚨\n\n"
        f"📍 <b>IP Address:</b> {ioc['value']}\n"
        f"📊 <b>Threat Score:</b> {ioc['score']}/100\n"
        f"🌐 <b>Country:</b> {ioc['country']}\n"
        f"🏢 <b>ISP:</b> {ioc['isp']}\n"
        f"🛡️ <b>Sources:</b> {sources_str}"
    )

    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message_text,
        "parse_mode": "HTML"
    }

    try:
        response = requests.post(url, data=payload, timeout=10)
        if response.status_code == 200:
            logging.info(f"Telegram alert sent successfully for IP: {ioc['value']}")
            return True
        else:
            logging.error(f"Failed to send Telegram alert. Status code: {response.status_code}")
            return False
    except Exception as e:
        logging.error(f"Error sending Telegram alert: {e}")
        return False


# --- בלוק הרצה עצמאי לבדיקת המודול ---
if __name__ == "__main__":
    dummy_ioc = {
        "value": "162.243.103.246",
        "type": "IP",
        "sources": ["Feodo_Tracker", "ThreatFox"],
        "score": 100,
        "country": "United States",
        "isp": "DigitalOcean, LLC"
    }

    print("בודק את תנאי ההתראה...")
    if should_send_alert(dummy_ioc, is_new=True):
        print("התנאי התקיים! שולח התראה לטלגרם...")
        send_telegram_alert(dummy_ioc)
    else:
        print("התנאי לא התקיים.")