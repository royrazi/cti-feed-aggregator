import os
import psycopg2
from psycopg2 import Error as Psycopg2Error
from dotenv import load_dotenv
from config import logging

load_dotenv()

DB_CONFIG = {
    "host": os.getenv("DB_HOST", "db"),
    "port": int(os.getenv("DB_PORT", 5432)),
    "dbname": os.getenv("DB_NAME", "cti_db"),
    "user": os.getenv("DB_USER", "cti_user"),
    "password": os.getenv("DB_PASSWORD", "cti_password")
}

def get_db_connection():
    return psycopg2.connect(**DB_CONFIG)

def init_db():
    create_table_query = """
    CREATE TABLE IF NOT EXISTS iocs (
        value VARCHAR(255) PRIMARY KEY,
        type VARCHAR(50) NOT NULL,
        score INT NOT NULL,
        country VARCHAR(100),
        isp VARCHAR(255),
        sources TEXT NOT NULL,
        notified BOOLEAN DEFAULT FALSE,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(create_table_query)
                conn.commit()
                logging.info("PostgreSQL database initialized successfully!")
    except Psycopg2Error as e:
        logging.error(f"PostgreSQL Error during database initialization: {e}")

def is_already_notified(ip_value):
    query = "SELECT notified FROM iocs WHERE value = %s;"
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(query, (ip_value,))
                result = cursor.fetchone()
                return result[0] if result else False
    except Psycopg2Error as e:
        logging.error(f"PostgreSQL Error checking notification status for {ip_value}: {e}")
        return False

def mark_as_notified(ip_value):
    query = "UPDATE iocs SET notified = TRUE WHERE value = %s;"
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(query, (ip_value,))
                conn.commit()
    except Psycopg2Error as e:
        logging.error(f"PostgreSQL Error marking {ip_value} as notified: {e}")

def save_iocs_to_db(iocs_dict):
    if not iocs_dict:
        return

    insert_query = """
    INSERT INTO iocs (value, type, score, country, isp, sources)
    VALUES (%s, %s, %s, %s, %s, %s)
    ON CONFLICT (value) 
    DO UPDATE SET 
        score = EXCLUDED.score,
        sources = EXCLUDED.sources,
        updated_at = CURRENT_TIMESTAMP;
    """

    records = []
    for ioc in iocs_dict.values():
        sources_str = ",".join(ioc["sources"])
        records.append((
            ioc["value"],
            ioc["type"],
            ioc["score"],
            ioc["country"],
            ioc["isp"],
            sources_str
        ))

    try:
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.executemany(insert_query, records)
                conn.commit()
                logging.info(f"Successfully saved {len(records)} indicators to PostgreSQL!")
    except Psycopg2Error as e:
        logging.error(f"PostgreSQL Error saving IoCs to DB: {e}")
