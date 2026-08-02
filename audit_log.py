import sqlite3
import hashlib
import datetime
import json

DB_NAME = "csps_audit.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            sender TEXT,
            text_hash TEXT,
            risk_label TEXT,
            confidence_score REAL,
            flags_json TEXT
        )
    ''')
    conn.commit()
    conn.close()

def log_scan(sender, body_text, risk, confidence, breakdown):
    text_hash = hashlib.sha256(body_text.encode('utf-8')).hexdigest()
    timestamp = datetime.datetime.utcnow().isoformat() + "Z"
    
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO scan_logs (timestamp, sender, text_hash, risk_label, confidence_score, flags_json)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (timestamp, sender, text_hash, risk, confidence, json.dumps(breakdown)))
    conn.commit()
    conn.close()

init_db()
