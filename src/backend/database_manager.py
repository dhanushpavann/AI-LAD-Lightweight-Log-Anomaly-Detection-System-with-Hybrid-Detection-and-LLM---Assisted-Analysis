import sqlite3
import threading
from typing import List, Dict, Any, Optional, Tuple
import os
import shutil
from datetime import datetime
import hashlib
import secrets
import json
import time

# --- Configuration Placeholder (REQUIRED) ---
# NOTE: This assumes 'config' module is available in your environment 
# and contains a variable named DB_PATH.
try:
    from src.config import DB_PATH 
except ImportError:
    # Fallback/Mock for testing only if config is missing (use a standard location)
    DB_PATH = os.path.join(os.path.expanduser('~'), '.ai_logguard', 'logguard.db')
    print(f"Warning: 'config.py' not found. Using fallback DB_PATH: {DB_PATH}")
    
# --- Global Thread Lock ---
_DB_LOCK = threading.Lock() # Lock for thread safety

class DatabaseManager:
    """
    Thread-safe SQLite manager for AI LAD.
    Manages users, traffic logs, reports, rules, settings, and audit logs.
    Implements the Singleton pattern.
    """
    _instance: Optional['DatabaseManager'] = None
    _initialized = False 

    def __new__(cls, *args, **kwargs) -> 'DatabaseManager':
        """ Implements the Singleton pattern. """
        with _DB_LOCK: # Ensure thread safety during instance creation check
            if not cls._instance:
                cls._instance = super(DatabaseManager, cls).__new__(cls)
        return cls._instance

    def __init__(self, db_path: str = DB_PATH):
        # Initial status for session tracking
        self.user_info = {"id": 0, "username": "System (Unauthenticated)", "role": "admin"}

        if DatabaseManager._initialized: return

        self.db_path = db_path
        
        # Ensure directory exists before connecting
        os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)

        try:
            # check_same_thread=False allows multiple threads to use the same connection, 
            # but requires external locking (which is handled by _DB_LOCK).
            self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self.conn.row_factory = sqlite3.Row 
            self._ensure_schema() 
            DatabaseManager._initialized = True
            print(f"DatabaseManager initialized at: {self.db_path}")

        except sqlite3.Error as e:
            print(f"FATAL: Could not connect or initialize database at {self.db_path}: {e}")
            # Prevent re-initialization if connection failed
            self.conn = None
            DatabaseManager._initialized = False 
            
    def _exec(self, sql: str, params: tuple = (), commit: bool = False) -> sqlite3.Cursor:
        """ Executes SQL queries safely using a lock. """
        if not self.conn:
            raise sqlite3.ProgrammingError("Database connection is not initialized.")
            
        with _DB_LOCK: 
            cur = self.conn.cursor()
            try:
                cur.execute(sql, params)
                if commit:
                    self.conn.commit()
            except sqlite3.Error as e:
                print(f"Database Error: {e}\nSQL: {sql}\nParams: {params}")
                self.conn.rollback() 
                raise # Re-raise the exception after rollback
            return cur

    def _ensure_schema(self):
        """ Ensures all required tables exist and runs necessary migrations. """
        
        # --- Users Table ---
        self._exec("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                salt BLOB NOT NULL,
                pw_hash BLOB NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                created_at TEXT DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now', 'localtime'))
            )""")

        # --- Traffic Logs Table (For Live Monitor History) ---
        self._exec("""
            CREATE TABLE IF NOT EXISTS traffic_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                source_ip TEXT,
                level TEXT,
                message TEXT,
                category TEXT
            )""")

        # --- Reports Table ---
        self._exec("""
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                type TEXT NOT NULL,
                filename TEXT NOT NULL,
                format TEXT NOT NULL,
                date_range TEXT,
                timestamp TEXT NOT NULL
            )""")

        # --- Response Rules Table ---
        self._exec("""
            CREATE TABLE IF NOT EXISTS response_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                condition TEXT NOT NULL,
                action TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                priority INTEGER NOT NULL DEFAULT 0
            )""")

        # --- Forensic Analysis Table (For LLM Reports) ---
        self._exec("""
            CREATE TABLE IF NOT EXISTS forensic_analysis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now', 'localtime')),
                log_reference TEXT,
                log_snippet TEXT NOT NULL,
                analysis_summary TEXT,
                recommendation TEXT,
                user_id INTEGER,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
            )""")

        # --- Settings & Audit ---
        self._exec("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)")
        self._exec("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT NOT NULL,
                details TEXT,
                timestamp TEXT DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now', 'localtime')),
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
            )""")
        
        # --- IP Reputation Cache Table ---
        self._exec("""
            CREATE TABLE IF NOT EXISTS ip_reputation (
                ip TEXT PRIMARY KEY,
                country TEXT,
                city TEXT,
                isp TEXT,
                org TEXT,
                updated_at REAL
            )""")
            
        # --- Schema Migrations (Robustly checking for 'priority' column) ---
        try:
            # Check if column exists by retrieving table info
            cur = self._exec("PRAGMA table_info(response_rules)")
            columns = [col[1] for col in cur.fetchall()]
            if 'priority' not in columns:
                 print("Migrating: Adding 'priority' column to response_rules.")
                 self._exec("ALTER TABLE response_rules ADD COLUMN priority INTEGER NOT NULL DEFAULT 0", commit=True)
        except Exception as e:
            print(f"Migration check failed: {e}")
            raise

        self._exec("", commit=True) # Final commit for all schema changes
        
    # -------------------------------------------------
    # IP Reputation Methods
    # -------------------------------------------------
    def get_ip_info(self, ip: str) -> Optional[Dict[str, Any]]:
        """Retrieves cached IP info if it exists."""
        cur = self._exec("SELECT * FROM ip_reputation WHERE ip = ?", (ip,))
        row = cur.fetchone()
        return dict(row) if row else None
    
    def save_ip_info(self, ip: str, data: Dict[str, Any]):
        """Upserts IP info into the cache."""
        country = data.get('country', 'Unknown')
        city = data.get('city', 'Unknown')
        isp = data.get('isp', 'Unknown')
        org = data.get('org', 'Unknown')
        updated_at = time.time() 
        
        self._exec("""
            INSERT OR REPLACE INTO ip_reputation (ip, country, city, isp, org, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (ip, country, city, isp, org, updated_at), commit=True)

    # -------------------------------------------------
    # Traffic Log Methods (For LiveMonitor & Reports)
    # -------------------------------------------------
    def insert_traffic_log(self, timestamp: str, ip: str, level: str, message: str, category: str = "General"):
        """Inserts a new traffic log entry."""
        self._exec(
            "INSERT INTO traffic_logs (timestamp, source_ip, level, message, category) VALUES (?, ?, ?, ?, ?)",
            (timestamp, ip, level, message, category), commit=True
        )

    def fetch_traffic_logs(self, limit: int = 1000, level_filter: Optional[str] = None) -> List[Dict]:
        """Retrieves logs for reporting."""
        sql = "SELECT * FROM traffic_logs"
        params: List[Any] = []
        if level_filter:
            sql += " WHERE level = ?"
            params.append(level_filter)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        cur = self._exec(sql, tuple(params))
        return [dict(r) for r in cur.fetchall()]
        
    def fetch_logs_for_analysis(self, limit: int = 50, start_date: Optional[datetime] = None, end_date: Optional[datetime] = None) -> List[str]:
        """Retrieves raw message strings from traffic_logs for LLM analysis, filtered by date."""
        sql = "SELECT message FROM traffic_logs WHERE 1=1"
        params: List[Any] = []
        
        # Use ISO format for SQLite comparison
        if start_date:
            sql += " AND timestamp >= ?"
            params.append(start_date.strftime('%Y-%m-%d %H:%M:%S'))
        
        if end_date:
            sql += " AND timestamp < ?" 
            params.append(end_date.strftime('%Y-%m-%d %H:%M:%S'))

        sql += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        cur = self._exec(sql, tuple(params))
        return [row['message'] for row in cur.fetchall()]


    # -------------------------------------------------
    # Forensic Analysis Methods
    # -------------------------------------------------
    def insert_forensic_analysis(self, log_snippet: str, summary: str, recommendation: str, log_reference: Optional[str] = None, user_id: Optional[int] = None) -> int:
        """Inserts a new LLM-based forensic analysis report."""
        user_id_to_use = user_id if user_id is not None else self.user_info.get('id')
        cur = self._exec(
            "INSERT INTO forensic_analysis (log_snippet, analysis_summary, recommendation, log_reference, user_id) VALUES (?, ?, ?, ?, ?)",
            (log_snippet, summary, recommendation, log_reference, user_id_to_use), commit=True
        )
        return cur.lastrowid
        
    def fetch_forensic_analysis(self, limit: int = 10) -> List[Dict]:
        """Retrieves recent forensic analysis reports for the history panel."""
        sql = "SELECT * FROM forensic_analysis ORDER BY timestamp DESC LIMIT ?"
        cur = self._exec(sql, (limit,))
        return [dict(r) for r in cur.fetchall()]
        
    def fetch_forensic_analysis_report(self, analysis_id: int) -> Optional[Dict]:
        """Retrieves a single forensic analysis report by ID."""
        sql = "SELECT * FROM forensic_analysis WHERE id = ?"
        cur = self._exec(sql, (analysis_id,))
        row = cur.fetchone()
        return dict(row) if row else None

    def delete_forensic_analysis(self, report_id: int):
        """Deletes a forensic analysis report by ID."""
        self._exec("DELETE FROM forensic_analysis WHERE id = ?", (report_id,), commit=True)

    # -------------------------------------------------
    # User Management Methods
    # -------------------------------------------------
    def hash_password(self, password: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """Generates a salt and hash for the given password."""
        if salt is None: salt = secrets.token_bytes(16)
        # 150,000 iterations for PBKDF2-HMAC-SHA256
        pw_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 150000)
        return salt, pw_hash

    def create_user(self, name: str, email: str, password: str) -> Tuple[bool, str]:
        """Creates a new user with hashed credentials."""
        try:
            salt, pw_hash = self.hash_password(password)
            now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            self._exec("INSERT INTO users (name, email, salt, pw_hash, role, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                          (name, email.lower(), salt, pw_hash, 'user', now_str), commit=True)
            return True, "User created successfully."
        except sqlite3.IntegrityError:
            return False, "Email already registered."
        except Exception as e:
            return False, f"Error creating user: {e}"

    def verify_user(self, email: str, password: str) -> Tuple[bool, Optional[Dict]]:
        """Verifies a user's password against the stored hash."""
        cur = self._exec("SELECT * FROM users WHERE email = ?", (email.lower(),))
        row = cur.fetchone()
        if not row: return False, None
        
        salt_val = row["salt"]
        stored_hash = row["pw_hash"]
        
        # Calculate the hash for the provided password using the stored salt
        _, candidate_hash = self.hash_password(password, salt_val)
        
        # Use secrets.compare_digest to prevent timing attacks
        is_valid = secrets.compare_digest(candidate_hash, stored_hash)
        user_data = dict(row)
        # Remove sensitive information before returning
        user_data.pop("salt", None)
        user_data.pop("pw_hash", None)
        
        return (True, user_data) if is_valid else (False, None)

    def get_user_by_id(self, user_id: int) -> Optional[Dict]:
        """Retrieves user data by ID, excluding sensitive fields."""
        cur = self._exec("SELECT id, name, email, role, created_at FROM users WHERE id = ?", (user_id,))
        row = cur.fetchone()
        return dict(row) if row else None
        
    def update_user_name(self, user_id: int, new_name: str) -> Tuple[bool, str]:
        """Updates a user's display name."""
        try:
            self._exec("UPDATE users SET name = ? WHERE id = ?", (new_name, user_id), commit=True)
            return True, "Name updated."
        except Exception as e: return False, str(e)

    def update_user_password(self, user_id: int, new_password: str) -> Tuple[bool, str]:
        """Updates a user's password with a new hash and salt."""
        try:
            salt, pw_hash = self.hash_password(new_password)
            self._exec("UPDATE users SET salt = ?, pw_hash = ? WHERE id = ?", (salt, pw_hash, user_id), commit=True)
            return True, "Password updated."
        except Exception as e: return False, str(e)

    def delete_user(self, user_id: int) -> Tuple[bool, str]:
        """Deletes a user from the database."""
        try:
            self._exec("DELETE FROM users WHERE id = ?", (user_id,), commit=True)
            return True, "User deleted."
        except Exception as e: return False, str(e)

    # -------------------------------------------------
    # Response Rules Management
    # -------------------------------------------------
    def insert_rule(self, name: str, condition: str, action: str, enabled: bool = True, priority: int = 0) -> int:
        """Inserts a new response rule."""
        cur = self._exec(
            "INSERT INTO response_rules (name, condition, action, enabled, priority) VALUES (?, ?, ?, ?, ?)",
            (name, condition, action, int(enabled), priority), commit=True)
        return cur.lastrowid

    def update_rule(self, rule_id: int, name: str, condition: str, action: str, enabled: bool, priority: int):
        """Updates an existing response rule."""
        self._exec(
            "UPDATE response_rules SET name = ?, condition = ?, action = ?, enabled = ?, priority = ? WHERE id = ?",
            (name, condition, action, int(enabled), priority, rule_id), commit=True)

    def delete_rule(self, rule_id: int):
        """Deletes a response rule by ID."""
        self._exec("DELETE FROM response_rules WHERE id = ?", (rule_id,), commit=True)

    def list_rules(self) -> List[Dict[str, Any]]:
        """
        Retrieves all rules from the database and safely parses their JSON fields.
        Returns a list of dictionaries.
        """
        # Order by priority (low is high priority) and then by name
        cur = self._exec("SELECT * FROM response_rules ORDER BY priority ASC, name COLLATE NOCASE ASC")
        
        parsed_rules = []
        for row in cur.fetchall():
            r = dict(row)
            
            # Safely parse JSON fields and attach a '_parsed' key
            for field in ['action', 'condition']:
                json_str = r.get(field, '{}')
                if not json_str or json_str.strip() == "":
                    json_str = '{}'
                try:
                    r[f'{field}_parsed'] = json.loads(json_str)
                except json.JSONDecodeError:
                    print(f"Warning: Failed to parse JSON for rule {r.get('id', 'Unknown')}, field {field}.")
                    r[f'{field}_parsed'] = {}
            
            parsed_rules.append(r)
        return parsed_rules

    # -------------------------------------------------
    # Settings & Audit
    # -------------------------------------------------
    def log_action(self, action: str, user_id: Optional[int] = None, details: str = ""):
        """Records an action in the audit log."""
        try:
            # Use the logged-in user ID if not provided
            uid = user_id if user_id is not None else self.user_info.get('id')
            now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            self._exec("INSERT INTO audit_log (user_id, action, details, timestamp) VALUES (?, ?, ?, ?)",
                          (uid, action, details, now_str), commit=True)
        except Exception as e: print(f"Error logging action: {e}")

    def get_setting(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """Retrieves a single setting value."""
        cur = self._exec("SELECT value FROM settings WHERE key = ?", (key,))
        row = cur.fetchone()
        return row['value'] if row else default

    def set_setting(self, key: str, value: str):
        """Sets or updates a configuration setting."""
        self._exec("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value), commit=True)
    
    # -------------------------------------------------
    # Reports Management
    # -------------------------------------------------
    def insert_report(self, type_: str, filename: str, format_: str, date_range: str) -> int:
        """Records a generated report."""
        ts_iso = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        cur = self._exec("INSERT INTO reports (type, filename, format, date_range, timestamp) VALUES (?, ?, ?, ?, ?)",
                          (type_, filename, format_, date_range, ts_iso), commit=True)
        return cur.lastrowid

    def list_reports(self) -> List[Dict[str, Any]]:
        """Lists all generated reports."""
        cur = self._exec("SELECT * FROM reports ORDER BY timestamp DESC")
        return [dict(r) for r in cur.fetchall()]

    def delete_report(self, report_id: int):
        """Deletes a report record."""
        self._exec("DELETE FROM reports WHERE id = ?", (report_id,), commit=True)

    # -------------------------------------------------
    # Utilities (Backup/Close)
    # -------------------------------------------------
    def backup_database(self, backup_path: str) -> Tuple[bool, str]:
        """Safely backs up the database file by temporarily closing the connection."""
        result = (False, "Backup failed")
        
        # Preserve current initialization state to know if we need to re-open
        was_initialized = DatabaseManager._initialized

        with _DB_LOCK:
            # 1. Temporarily close the connection to ensure the file is not locked
            if was_initialized and self.conn:
                try:
                    self.conn.close()
                    DatabaseManager._initialized = False # Mark as closed
                except Exception as e: 
                    print(f"Warning: Failed to close connection for backup: {e}")
                    # Continue attempting the copy, as SQLite might still allow access
            
            # 2. Perform the file copy
            if not os.path.exists(self.db_path):
                result = (False, "Database file not found.")
            else:
                try:
                    os.makedirs(os.path.dirname(backup_path) or ".", exist_ok=True)
                    shutil.copyfile(self.db_path, backup_path)
                    result = (True, f"Backup successful to {backup_path}")
                except Exception as e:
                    result = (False, f"Backup error: {e}")

            # 3. Re-initialize the connection if it was open before
            if was_initialized and not DatabaseManager._initialized:
                try:
                    self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
                    self.conn.row_factory = sqlite3.Row
                    DatabaseManager._initialized = True
                except Exception as e: 
                    print(f"CRITICAL: Failed to re-open database connection after backup: {e}")
                    if result[0]:
                        result = (False, f"Backup done, but DB re-open failed. Restart required. Error: {e}")
                    else:
                        result = (False, f"Backup failed and DB re-open failed. Error: {e}")
        return result

    def close(self):
        """Closes the database connection safely."""
        if DatabaseManager._initialized and self.conn:
            try:
                with _DB_LOCK: self.conn.close()
                DatabaseManager._initialized = False
                # Ensure the singleton instance is also reset to allow clean restart if needed
                DatabaseManager._instance = None 
            except Exception as e: 
                print(f"Error closing database connection: {e}")
                
# Singleton getter function
def get_db_instance() -> DatabaseManager:
    """Provides the single instance of the DatabaseManager."""
    return DatabaseManager()