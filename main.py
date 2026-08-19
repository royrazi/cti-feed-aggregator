import time
import schedule
from config import logging, FETCH_INTERVAL_MINUTES
from database import init_db, save_iocs_to_db, is_already_notified, mark_as_notified
from enrichment import fetch_live_iocs, fetch_second_feed, enrich_geoip, calculate_threat_score
from alerts import should_send_alert, send_telegram_alert


def process_ioc(ioc):
    ioc_val = ioc["value"]
    ioc_type = ioc["type"]
    ioc_src = ioc["sources"]
    score = ioc.get("score", 50)

    if ioc_type == "IP":
        logging.info(f"[VALID] IP indicator detected: {ioc_val} | Threat Score: {score}/100 (Source: {ioc_src})")
    else:
        logging.warning(f"[SKIP] Unsupported indicator type: {ioc_type} for {ioc_val}")


def run_cti_pipeline():
    logging.info("=== CTI Feed Aggregator - Starting Scheduled Cycle ===")
    try:
        feed1_data = fetch_live_iocs()
        logging.info(f"Successfully fetched {len(feed1_data)} raw indicators from Feodo Tracker!")

        feed2_data = fetch_second_feed()
        logging.info(f"Successfully fetched {len(feed2_data)} raw indicators from ThreatFox API!")

        all_raw_data = feed1_data + feed2_data

        logging.info("=== Processing Batch & Deduplicating ===")
        unique_iocs = {}

        for item in all_raw_data:
            ip_val = item.get("ip_address", "0.0.0.0")
            src_name = item.get("source", "Feodo_Tracker")

            if not ip_val or ip_val == "0.0.0.0":
                continue

            if ip_val in unique_iocs:
                if src_name not in unique_iocs[ip_val]["sources"]:
                    unique_iocs[ip_val]["sources"].append(src_name)
                unique_iocs[ip_val]["score"] = calculate_threat_score(unique_iocs[ip_val]["sources"])
            else:
                geo_info = enrich_geoip(ip_val)
                source_list = [src_name]
                normalized_ioc = {
                    "value": ip_val,
                    "type": "IP",
                    "sources": source_list,
                    "score": calculate_threat_score(source_list),
                    "country": geo_info["country"],
                    "isp": geo_info["isp"]
                }
                unique_iocs[ip_val] = normalized_ioc

        save_iocs_to_db(unique_iocs)

        logging.info("=== Displaying Results & Sending Alerts ===")

        for ioc_obj in unique_iocs.values():
            process_ioc(ioc_obj)

            if should_send_alert(ioc_obj, is_new=True):
                if not is_already_notified(ioc_obj["value"]):
                    if send_telegram_alert(ioc_obj):
                        mark_as_notified(ioc_obj["value"])

        logging.info(f"=== Cycle Completed. Waiting {FETCH_INTERVAL_MINUTES} minutes for next cycle... ===")

    except Exception as e:
        logging.error(f"Error during CTI pipeline execution cycle: {e}")


if __name__ == "__main__":
    init_db()
    run_cti_pipeline()

    schedule.every(FETCH_INTERVAL_MINUTES).minutes.do(run_cti_pipeline)

    logging.info("CTI Engine is running continuously. Press Ctrl+C to stop.")

    try:
        while True:
            schedule.run_pending()
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("CTI Engine stopped gracefully by user")