import sqlite3
import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

# Database file will be created in the same directory as this file
DB_PATH = Path(__file__).parent / 'scans.db'

def get_connection():
    """Get a database connection."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row  # Access columns by name
    return conn

def init_db():
    """Initialize the database with required tables."""
    with get_connection() as conn:
        conn.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            target TEXT NOT NULL,
            status TEXT NOT NULL,
            scan_type TEXT NOT NULL,
            authorized BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            started_at TIMESTAMP,
            completed_at TIMESTAMP,
            client_ip TEXT,
            results TEXT
        )
        ''')
        conn.commit()

# Initialize database when this module is imported
init_db()

def save_scan(scan_id: str, target: str, scan_type: str, authorized: bool, client_ip: str):
    """Save a new scan to the database."""
    with get_connection() as conn:
        conn.execute(
            '''
            INSERT INTO scans (id, target, status, scan_type, authorized, client_ip)
            VALUES (?, ?, ?, ?, ?, ?)
            ''',
            (scan_id, target, 'queued', scan_type, 1 if authorized else 0, client_ip)
        )
        conn.commit()

def update_scan_status(scan_id: str, status: str, results: Dict[str, Any] = None):
    """Update scan status and optionally store results."""
    with get_connection() as conn:
        if status == 'running':
            conn.execute(
                'UPDATE scans SET status = ?, started_at = ? WHERE id = ?',
                (status, datetime.utcnow(), scan_id)
            )
        elif status in ['completed', 'failed']:
            conn.execute(
                '''
                UPDATE scans 
                SET status = ?, completed_at = ?, results = ?
                WHERE id = ?
                ''',
                (status, datetime.utcnow(), json.dumps(results) if results else None, scan_id)
            )
        else:
            conn.execute(
                'UPDATE scans SET status = ? WHERE id = ?',
                (status, scan_id)
            )
        conn.commit()

def get_scan(scan_id: str) -> Optional[Dict[str, Any]]:
    """Get scan details by ID."""
    with get_connection() as conn:
        row = conn.execute('SELECT * FROM scans WHERE id = ?', (scan_id,)).fetchone()
        if not row:
            return None
        
        # Convert row to dict
        scan = dict(row)
        
        # Parse JSON results if they exist
        if scan.get('results'):
            scan['results'] = json.loads(scan['results'])
            
        return scan

def get_recent_scans(limit: int = 10) -> List[Dict[str, Any]]:
    """Get most recent scans."""
    with get_connection() as conn:
        rows = conn.execute(
            'SELECT * FROM scans ORDER BY created_at DESC LIMIT ?',
            (limit,)
        ).fetchall()
        
        scans = []
        for row in rows:
            scan = dict(row)
            if scan.get('results'):
                scan['results'] = json.loads(scan['results'])
            scans.append(scan)
            
        return scans
