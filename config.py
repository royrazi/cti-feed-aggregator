import logging
import os
from dotenv import load_dotenv

load_dotenv() 

# עדכון ה-Logger לכתיבה כפולה (קובץ + טרמינל)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("cti_engine.log", encoding="utf-8"),  # שמירה בדיסק
        logging.StreamHandler()                                   # הדפסה בלייב (stdout)
    ]
)

SOURCE_WEIGHTS = {
    "Feodo_Tracker": 40,
    "ThreatFox": 35,
    "Blocklist_DE": 20
}

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

FETCH_INTERVAL_MINUTES = 5