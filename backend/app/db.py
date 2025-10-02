import sqlite3
import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Union
import os

# Database file will be created in the instance directory
DB_DIR = Path(__file__).parent.parent / 'instance'
DB_PATH = DB_DIR / 'scans.db'

# Flag to track if database has been initialized
_db_initialized = False

def init_db():
    """Initialize the database if it doesn't exist."""
    global _db_initialized
    
    if _db_initialized:
        return
        
    # Create instance directory if it doesn't exist
    DB_DIR.mkdir(parents=True, exist_ok=True)
    
    # Connect to the database (creates it if it doesn't exist)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    
    try:
        cursor = conn.cursor()
        
        # Enable foreign keys
        cursor.execute('PRAGMA foreign_keys = ON')
        
        # Create scans table if it doesn't exist
        cursor.execute('''
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
        _db_initialized = True
        print("Database initialized successfully")
    except Exception as e:
        print(f"Error initializing database: {e}")
        raise
    finally:
        conn.close()

def get_connection() -> sqlite3.Connection:
    """Get a database connection."""
    # Initialize the database if not already done
    if not _db_initialized:
        init_db()
        
    # Create and return a new connection
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON')
    return conn

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
