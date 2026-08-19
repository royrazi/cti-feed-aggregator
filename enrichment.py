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
        if response.status_code == 200:
            return response.json()
        else:
            logging.error(f"Failed to fetch Feodo Tracker feed. Status: {response.status_code}")
            return []
    except Exception as e:
        logging.error(f"Error fetching Feodo Tracker: {e}")
        return []


def fetch_second_feed():
    url = "https://threatfox.abuse.ch/export/json/recent/"
    headers = {"User-Agent": "CTI-Engine/1.0"}
    iocs = []

    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            raw_items = []
            if isinstance(data, dict):
                if "data" in data and isinstance(data["data"], list):
                    raw_items = data["data"]
                else:
                    for val in data.values():
                        if isinstance(val, list):
                            raw_items.extend(val)
                        elif isinstance(val, dict):
                            raw_items.append(val)
            elif isinstance(data, list):
                raw_items = data

            for item in raw_items:
                if isinstance(item, dict):
                    ioc_val = item.get("ioc") or item.get("ip_address")
                    if ioc_val:
                        ip_clean = str(ioc_val).split(":")[0].strip()
                        parts = ip_clean.split(".")
                        if len(parts) == 4 and all(p.isdigit() for p in parts):
                            iocs.append({"ip_address": ip_clean, "source": "ThreatFox"})
    except Exception as e:
        logging.error(f"Error fetching ThreatFox JSON: {e}")

    if not iocs:
        try:
            fallback_url = "https://cinsscore.com/list/ci-badguys.txt"
            resp = requests.get(fallback_url, headers=headers, timeout=10)
            if resp.status_code == 200:
                for line in resp.text.splitlines():
                    ip_candidate = line.strip()
                    parts = ip_candidate.split(".")
                    if len(parts) == 4 and all(p.isdigit() for p in parts):
                        iocs.append({"ip_address": ip_candidate, "source": "Blocklist_DE"})
        except Exception as e:
            logging.error(f"Error fetching fallback feed: {e}")

    return iocs[:30]


def enrich_geoip(ip):
    url = f"http://ip-api.com/json/{ip}"
    try:
        response = requests.get(url, timeout=3)
        if response.status_code == 200:
            data = response.json()
            return {
                "country": data.get("country", "Unknown"),
                "isp": data.get("isp", "Unknown")
            }
        return {"country": "Unknown", "isp": "Unknown"}
    except Exception as e:
        logging.error(f"Error enriching IP {ip}: {e}")
        return {"country": "Unknown", "isp": "Unknown"}