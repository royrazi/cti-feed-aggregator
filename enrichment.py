import requests
from config import SOURCE_WEIGHTS, logging

def calculate_threat_score(source_list):
    total_score = 0
    for src in source_list:
        total_score += SOURCE_WEIGHTS.get(src, 10)

    if len(source_list) > 1:
        total_score += 25

    return min(total_score, 100)

def fetch_live_iocs():
    url = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
    headers = {"User-Agent": "CTI-Engine/1.0"}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status() 
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"Network error fetching Feodo Tracker: {e}")
        return []
    except ValueError as e:
        logging.error(f"JSON parsing error from Feodo Tracker: {e}")
        return []

def fetch_second_feed():
    url = "https://threatfox.abuse.ch/export/json/recent/"
    headers = {"User-Agent": "CTI-Engine/1.0"}
    iocs = []

    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()
        
    
        if data.get("query_status") == "ok" and isinstance(data.get("data"), list):
            for item in data["data"]:
                ioc_val = item.get("ioc") or item.get("ip_address")
                if ioc_val:
                    ip_clean = str(ioc_val).split(":")[0].strip()
                    parts = ip_clean.split(".")
                    if len(parts) == 4 and all(p.isdigit() for p in parts):
                        iocs.append({"ip_address": ip_clean, "source": "ThreatFox"})
                        
    except requests.exceptions.RequestException as e:
        logging.error(f"Network error fetching ThreatFox API: {e}")
    except ValueError as e:
        logging.error(f"JSON parsing error from ThreatFox API: {e}")

    # Fallback מנגנון
    if not iocs:
        try:
            fallback_url = "https://cinsscore.com/list/ci-badguys.txt"
            resp = requests.get(fallback_url, headers=headers, timeout=10)
            resp.raise_for_status()
            for line in resp.text.splitlines():
                ip_candidate = line.strip()
                parts = ip_candidate.split(".")
                if len(parts) == 4 and all(p.isdigit() for p in parts):
                    iocs.append({"ip_address": ip_candidate, "source": "Blocklist_DE"})
        except requests.exceptions.RequestException as e:
            logging.error(f"Network error fetching fallback feed: {e}")

    return iocs[:30]

def enrich_geoip(ip):
    url = f"http://ip-api.com/json/{ip}"
    try:
        response = requests.get(url, timeout=3)
        response.raise_for_status()
        data = response.json()
        return {
            "country": data.get("country", "Unknown"),
            "isp": data.get("isp", "Unknown")
        }
    except requests.exceptions.RequestException as e:
        logging.error(f"Network error enriching IP {ip}: {e}")
        return {"country": "Unknown", "isp": "Unknown"}
    except ValueError as e:
        logging.error(f"JSON parsing error for IP {ip}: {e}")
        return {"country": "Unknown", "isp": "Unknown"}
