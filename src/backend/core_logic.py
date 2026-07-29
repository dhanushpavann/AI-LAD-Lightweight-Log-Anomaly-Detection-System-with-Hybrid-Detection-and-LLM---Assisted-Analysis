import threading
import time
from collections import deque, Counter
from datetime import datetime, timedelta
import random
from typing import Dict, Any, Deque, List, Tuple, Optional, Set
import os
import re
import pickle
import sys
import json

# --- Conditional Imports ---
try:
    from sklearn.ensemble import IsolationForest
    from sklearn.feature_extraction.text import TfidfVectorizer
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    print("CoreLogic: Scikit-learn is NOT installed. ML Anomaly Detection is permanently disabled.")

# --- LLM Service Import ---
# This block attempts to import the actual service classes and function.
# The `SeverityLevel` and `LogAnalysis` definitions are now expected from llm_service.py.
try:
    from src.backend.llm_service import get_llm_service, LogAnalysis, SeverityLevel
    
    # Initialize the LLM Service, catching potential config/API errors
    try:
        LLM_SERVICE_AVAILABLE = True
        # NOTE: Analyzer initialization is moved to CoreLogic.__init__
    except Exception as e:
        LLM_SERVICE_AVAILABLE = False
        print(f"CoreLogic: WARNING: LLM Service setup failed during import check: {e}")

except ImportError as e:
    # This happens if llm_service.py is missing or structure is incorrect
    LLM_SERVICE_AVAILABLE = False
    # Define minimal placeholder classes if the service file is missing to prevent total crash
    class SeverityLevel:
        INFO = "INFO"
        ERROR = "ERROR"
        CRITICAL = "CRITICAL"
    class LogEvent:
        def __init__(self, description: str, recommended_actions: List[str]):
            self.description = description
            self.recommended_actions = recommended_actions
    class LogAnalysis:
        def __init__(self):
            self.summary = ""
            self.highest_severity: Optional[SeverityLevel] = SeverityLevel.INFO
            self.events: List[LogEvent] = []
    print(f"CoreLogic: WARNING: LLM Service file import failed ({e}). LLM functionality disabled.")
    
# ----------------------------------------------------------------------
# --- DB/Config Import (Removed MockDB) ---
# ----------------------------------------------------------------------
# Define fallback constants in case imports fail
COLOR_RED_CONSOLE = "\033[91m"
COLOR_BLUE_CONSOLE = "\033[94m"
COLOR_END_CONSOLE = "\033[0m"
SEV_ORDER = ["Critical", "Error", "Warn", "Info", "Debug"]
BUILT_IN_MODEL_PATH = "mock_model.pkl" 
BUILT_IN_VECTORIZER_PATH = "mock_vectorizer.pkl"

try:
    # Imports constants like BUILT_IN_MODEL_PATH, SEV_ORDER, COLOR_*, etc.
    from src.config import SEV_ORDER, COLOR_RED_CONSOLE, COLOR_BLUE_CONSOLE, COLOR_END_CONSOLE, BUILT_IN_MODEL_PATH, BUILT_IN_VECTORIZER_PATH 
    # This must be the actual DatabaseManager file you provided
    from src.backend.database_manager import get_db_instance
    
    # Initialize the real database instance
    DB = get_db_instance() 
    print("CoreLogic: Successfully connected to the real DatabaseManager.")

except ImportError as e:
    # If the required files (config or database_manager) are missing, we cannot run.
    print(f"\n{COLOR_RED_CONSOLE}FATAL IMPORT ERROR: Cannot initialize CoreLogic without required files.{COLOR_END_CONSOLE}")
    print(f"Missing dependency: {e}")
    # Define minimal fallbacks to prevent a crash, but functionality will be severely limited.
    class DummyDB: # Minimal dummy to allow type hinting and method calls without crash
        def log_action(self, *args, **kwargs): pass
        def close(self): pass
        def list_rules(self): return []
        def insert_traffic_log(self, *args): pass
    DB = DummyDB()
    SKLEARN_AVAILABLE = False 

# --- CORE REGEX PATTERNS ---
# Robust IP extraction (Supports IPv4 and basic IPv6)
IP_REGEX = re.compile(r'(?:\d{1,3}\.){3}\d{1,3}|(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}')

# Flexible Log Pattern (Captures TS, Level, and the rest of the message)
LOG_PATTERN = re.compile(
    r'^\[(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]\s+'
    r'\[(?P<level>[A-Za-z]+)\]\s+'
    r'(?P<message>.*)$'
)

# Detection modes used for evaluation/benchmark ablation.
DETECTION_MODES = {"hybrid", "heuristic_only", "ml_only"}

# Blocklist cleanup interval (seconds)
BLOCKLIST_CLEANUP_INTERVAL = 300 
# Rule tracker cleanup interval (seconds)
RULE_TRACKER_CLEANUP_INTERVAL = 30 


class CoreLogic:
    """
    The backend engine. It runs in a dedicated thread to perform log analysis, 
    AI detection, status updates, and database persistence.
    """
    def __init__(self, shared_stats: Dict[str, Any], log_queue: Deque[Dict[str, Any]], alert_queue: Deque[Dict[str, Any]], graph_data: Deque, speed_data: Deque = None):
        
        # --- CRITICAL: THREAD SAFETY LOCK ---
        self.lock = threading.Lock() 
        
        # Shared State (Protected by self.lock)
        self.stats = shared_stats
        self.log_queue = log_queue       # Deque for Dashboard History/Persistence
        self.alert_queue = alert_queue   # Deque for UI Notifications
        self.graph_data = graph_data     # Deque for Dashboard Efficacy Trend
        self.speed_data = speed_data     # Deque for Anomaly Rate (events/sec)
        
        # Internal State
        self.is_running = False
        self.active_thread: Optional[threading.Thread] = None
        
        # Active Defense State: Stores (IP, Expiration_Time)
        self.blocklist: Dict[str, datetime] = {} 
        self.last_blocklist_cleanup = datetime.now()
        
        # Rule Management State
        self.rules: List[Dict[str, Any]] = [] 
        # Stores (IP, RuleID): Deque[timestamps] for rate limiting checks
        self.rule_hit_tracker: Dict[Tuple[str, int], Deque[datetime]] = {} 
        self.last_rule_tracker_cleanup = datetime.now()
        
        # AI Components
        self.model = None
        self.vectorizer = None
        self.using_custom_model = False
        
        # LLM Component Initialization
        self.llm_analyzer = None
        if LLM_SERVICE_AVAILABLE:
            try:
                # Use the actual service provided by llm_service.py
                self.llm_analyzer = get_llm_service().get_analyzer()
                print("CoreLogic: Real LLM Analyzer initialized.")
            except Exception as e:
                self.llm_analyzer = None
                print(f"{COLOR_RED_CONSOLE}CoreLogic: LLM Analyzer failed to initialize: {e}{COLOR_END_CONSOLE}")
        
        # Monitoring State
        self.monitoring_target = "Simulation"
        self.monitoring_mode = "sim"
        self.ui_consumer_page = None
        
        # --- GRAPH FIX: New variables for tracking rate ---
        self.last_graph_update = datetime.now()
        self.last_speed_update = datetime.now()
        self.anomalies_in_current_interval = 0 # NEW: Tracks hits for the current 1-second interval
        self.graph_update_interval_sec = 1.0 # The interval for the rate calculation
        # --------------------------------------------------

        # Load rules and models
        self.load_rules()
        if SKLEARN_AVAILABLE:
            self._load_builtin_model()
        else:
            print(f"{COLOR_RED_CONSOLE}CoreLogic: ML Anomaly Detection is inactive.{COLOR_END_CONSOLE}")

    # -------------------------------------------------
    # Rule Management Methods
    # -------------------------------------------------
    def load_rules(self):
        """
        Loads all enabled rules from the database. 
        It uses the list_rules method from DatabaseManager which returns pre-parsed JSON.
        """
        try:
            # list_rules() returns dicts where 'condition_parsed' and 'action_parsed' are dicts
            db_rules = DB.list_rules() 
            new_rules = []
            
            for r in db_rules:
                if not r.get("enabled", 1): continue 
                
                # Use the pre-parsed fields from DatabaseManager
                if isinstance(r.get('condition_parsed'), dict) and isinstance(r.get('action_parsed'), dict):
                    # Rename the keys to simplify internal logic if necessary, or just use the parsed ones
                    r['condition'] = r.pop('condition_parsed')
                    r['action'] = r.pop('action_parsed')
                    new_rules.append(r)
                else:
                    print(f"{COLOR_RED_CONSOLE}CoreLogic: WARNING: Rule ID {r.get('id', 'N/A')} has invalid parsed JSON and was skipped.{COLOR_END_CONSOLE}")
            
            # Sort rules by priority (lower number = higher priority)
            new_rules.sort(key=lambda x: x.get('priority', 99))
            
            # Update the internal state
            self.rules = new_rules
            print(f"CoreLogic: Loaded {len(self.rules)} active response rules.")
        except Exception as e:
            print(f"{COLOR_RED_CONSOLE}CoreLogic: FATAL ERROR loading rules from DB: {e}{COLOR_END_CONSOLE}")
            self.rules = []

    def _cleanup_rule_tracker(self):
        """Removes expired timestamps and empty trackers from the rule hit tracker."""
        now = datetime.now()
        
        if (now - self.last_rule_tracker_cleanup).total_seconds() < RULE_TRACKER_CLEANUP_INTERVAL:
            return
            
        keys_to_delete = []
        for key, tracker in self.rule_hit_tracker.items():
            rule_id = key[1]
            try:
                # Find the rule to get the correct window setting
                rule_info = next(r for r in self.rules if r['id'] == rule_id)
                window = rule_info['condition'].get('window', 60) # Default to 60s
            except StopIteration:
                # Rule doesn't exist anymore, mark for deletion
                keys_to_delete.append(key)
                continue

            window_delta = timedelta(seconds=window)
            
            # Efficiently clean up the deque
            while tracker and (now - tracker[0]) > window_delta:
                tracker.popleft() 
                
            if not tracker:
                keys_to_delete.append(key)

        for key in keys_to_delete:
            self.rule_hit_tracker.pop(key, None)
            
        self.last_rule_tracker_cleanup = now


    def _check_and_execute_rules(self, log_entry: Dict[str, Any]):
        """
        Iterates over active rules (sorted by priority) and executes actions.
        Stops processing only if a strong, immediate action is taken.
        """
        ip = log_entry.get('ip')
        
        # Optimization: Only check rules for non-Info/Debug levels or confirmed anomalies
        if log_entry.get('level') in ["Info", "Debug"] and not log_entry.get('anomaly'):
            return

        for rule in self.rules:
            condition = rule['condition']
            action = rule['action']
            rule_match = False
            cond_type = condition.get("type")
            log_level = log_entry['level']

            # --- Rule Condition Checks ---
            
            # 1. Check Severity Level
            if cond_type == "Severity Level":
                required_level = condition.get('level', 'Critical')
                try:
                    # Uses the global SEV_ORDER list defined in config.py
                    if SEV_ORDER.index(log_level) <= SEV_ORDER.index(required_level):
                        rule_match = True
                except ValueError: pass

            # 2. Check Source IP 
            elif cond_type == "Source IP" and ip and ip != "N/A":
                ip_cidr = condition.get('ip_cidr')
                if ip_cidr and ip == ip_cidr: 
                    rule_match = True

            # 3. Check Log Message Content
            elif cond_type == "Log Message Content":
                contains = condition.get('contains', '').lower()
                if contains and contains in log_entry['message'].lower():
                    rule_match = True
            
            # 4. Check Repeated Event (Rate Limiting)
            elif cond_type == "Repeated Event" and ip and ip != "N/A":
                attempts = condition.get('attempts', 5)
                window = condition.get('window', 60) # seconds
                key = (ip, rule['id'])
                now = datetime.now()
                
                # Use a specific message or general log matching for counting hits
                
                if key not in self.rule_hit_tracker:
                    self.rule_hit_tracker[key] = deque(maxlen=attempts)
                
                tracker = self.rule_hit_tracker[key]
                tracker.append(now)
                
                window_delta = timedelta(seconds=window)
                while tracker and (now - tracker[0]) > window_delta:
                    tracker.popleft() 

                if len(tracker) >= attempts:
                    # Trigger the rule, but also reset the tracker to prevent immediate re-trigger
                    rule_match = True
                    # This rule has fired. Empty the tracker to start counting anew after this event.
                    tracker.clear() 
            
            # --- EXECUTE ACTION ---
            if rule_match:
                print(f"{COLOR_RED_CONSOLE}[RULE MATCHED] Rule ID {rule['id']} ('{rule['name']}') triggered by {log_level} log from {ip}.{COLOR_END_CONSOLE}")
                
                self._execute_rule_action(rule, log_entry)
                
                # CRITICAL: Break only on high-impact, immediate actions
                if action.get('type') in ["Block IP", "Execute Script"]:
                    break # Stop processing subsequent rules for this log entry


    def _execute_rule_action(self, rule: Dict[str, Any], log_entry: Dict[str, Any]):
        """Simulates the execution of the rule's defined action and logs it to the DB."""
        action_type = rule['action'].get('type')
        action_data = rule['action']
        
        user_id = self.stats.get('user_id', 0)
        log_details = f"Rule: '{rule['name']}' ({rule['id']}), Log IP: {log_entry['ip']}, Action: {action_type}, Log: {log_entry['message'][:80]}..."
        
        with self.lock:
            # Update the shared response summary counter
            action_counter = self.stats.get('rule_action_counts') 
            if isinstance(action_counter, Counter):
                action_counter.update({action_type: 1})
        
        if action_type == "Block IP":
            duration_minutes = action_data.get('duration', 60)
            ip = log_entry.get('ip')
            if ip and ip != "N/A":
                expiration = datetime.now() + timedelta(minutes=duration_minutes)
                with self.lock:
                    self.blocklist[ip] = expiration
                print(f"[ACTION] Temporarily blocked IP {ip} until {expiration.strftime('%H:%M:%S')}. (Simulated Firewall Update)")
                DB.log_action("ACTION_BLOCK_IP", user_id=user_id, details=log_details + f", Duration: {duration_minutes} min.")
        
        elif action_type == "Send Email Alert":
            print(f"[ACTION] Email alert sent. (Simulated)")
            DB.log_action("ACTION_EMAIL_SENT", user_id=user_id, details=log_details)
        
        elif action_type == "Execute Script":
            # In a real system, this would spawn a subprocess
            print(f"[ACTION] Executing external script. (Simulated)")
            DB.log_action("ACTION_SCRIPT_EXEC", user_id=user_id, details=log_details)
        
        elif action_type == "Log Event":
            print("[ACTION] Rule triggered, logging event internally (No external action).")
            DB.log_action("ACTION_LOG_EVENT", user_id=user_id, details=log_details)


    def reload_rules(self):
        """Public method to force reloading and sorting of all active rules."""
        self.load_rules()

    # -------------------------------------------------
    # ML Model Load/Control Methods
    # -------------------------------------------------

    def _load_builtin_model(self):
        """Loads external trained models (Isolation Forest and TfidfVectorizer)."""
        if not SKLEARN_AVAILABLE:
            return
        
        try:
            MODEL_PATH = BUILT_IN_MODEL_PATH
            VECTORIZER_PATH = BUILT_IN_VECTORIZER_PATH
            
            if not os.path.exists(MODEL_PATH) or not os.path.exists(VECTORIZER_PATH):
                print(f"{COLOR_RED_CONSOLE}CoreLogic: WARNING: Built-in models not found at expected paths. ML Anomaly Detection inactive.{COLOR_END_CONSOLE}")
                self.model = None 
                self.vectorizer = None
                return
            
            with open(MODEL_PATH, 'rb') as f: self.model = pickle.load(f)
            with open(VECTORIZER_PATH, 'rb') as f: self.vectorizer = pickle.load(f)
            
            self.using_custom_model = False
            print(f"{COLOR_BLUE_CONSOLE}CoreLogic: Built-in ML models loaded successfully.{COLOR_END_CONSOLE}")

        except Exception as e:
            print(f"{COLOR_RED_CONSOLE}CoreLogic: Error loading built-in models: {e}. ML Anomaly Detection is disabled.{COLOR_END_CONSOLE}")
            self.model = None
            self.vectorizer = None


    def load_custom_model(self, model_path, vectorizer_path) -> Tuple[bool, str]:
        """Loads a custom .pkl model and vectorizer from an arbitrary path."""
        if not SKLEARN_AVAILABLE:
            return False, "Scikit-learn not available. Cannot load custom ML model."
        try:
            if not os.path.exists(model_path) or not os.path.exists(vectorizer_path):
                return False, "Model or vectorizer file not found."
                    
            with open(model_path, 'rb') as f: self.model = pickle.load(f)
            with open(vectorizer_path, 'rb') as f: self.vectorizer = pickle.load(f)
            
            self.using_custom_model = True
            return True, "Custom ML model loaded successfully."
        except Exception as e:
            print(f"Error loading custom model: {e}")
            self.model = None 
            self.vectorizer = None
            self.using_custom_model = False
            return False, f"Failed to load custom model: {str(e)}"

    def get_ai_status(self) -> str:
        """Returns the current status of the AI/LLM components."""
        ml_status = ""
        if not SKLEARN_AVAILABLE: 
            ml_status = "ML Unavailable (No sklearn)"
        elif self.model is None: 
            ml_status = "ML Ready (models not trained)" 
        elif self.using_custom_model: 
            ml_status = "Custom ML Active"
        else: 
            ml_status = "Built-in ML Active" 
              
        llm_status = "LLM Active" if self.llm_analyzer else "LLM Disabled" 
        
        return f"{llm_status} / {ml_status}"


    def analyze_with_llm(self, log_text: str) -> Dict[str, Any]:
        """Runs a forensic analysis on a log snippet using the integrated LLM service."""
        if self.llm_analyzer is None:
            return {
                "summary": "LLM Analysis Disabled or Failed to Initialize.",
                "recommendation": "CRITICAL. Check LLM_API_KEY and service dependencies.",
                "severity": "CRITICAL"
            }
        
        try:
            logs_list = log_text.splitlines() or [log_text]
            
            # analysis_result is an instance of LogAnalysis from llm_service
            analysis_result: LogAnalysis = self.llm_analyzer.analyze_logs(logs_list, log_type="Security Event Log Snippet")
            
            all_recommendations = []
            if analysis_result.events:
                # Note: events is a list of WebSecurityEvent in the real structure
                for event in analysis_result.events:
                    all_recommendations.extend(event.recommended_actions) 

            recommendation_str = " | ".join(all_recommendations) if all_recommendations else "No immediate action suggested."
            
            # --- Insert analysis into the real database ---
            user_id = self.stats.get('user_id', 0)
            DB.insert_forensic_analysis(
                log_snippet=log_text, 
                summary=analysis_result.summary, 
                recommendation=recommendation_str, 
                log_reference=f"Manual Analysis by User {user_id}",
                user_id=user_id
            )
            
            # The highest_severity is a SeverityLevel enum, convert to string
            final_severity_str = analysis_result.highest_severity.value if analysis_result.highest_severity else SeverityLevel.INFO.value

            return {
                "summary": analysis_result.summary,
                "recommendation": recommendation_str,
                "severity": final_severity_str
            }
            
        except Exception as e:
            return {
                "summary": f"LLM Analysis failed during execution: {type(e).__name__}",
                "recommendation": "Check context window limits or LLM service status.",
                "severity": SeverityLevel.ERROR.value # Fallback to ERROR from SeverityLevel
            }

    # --- BLOCKLIST INTEGRATION ---
    def _cleanup_blocklist(self):
        """Removes expired IPs from the blocklist."""
        now = datetime.now()
        
        if (now - self.last_blocklist_cleanup).total_seconds() < BLOCKLIST_CLEANUP_INTERVAL:
            return
            
        expired_ips = [ip for ip, expiration in self.blocklist.items() if expiration < now]
        
        with self.lock:
            for ip in expired_ips:
                self.blocklist.pop(ip)
                print(f"[ACTION] IP {ip} block has expired and been removed.")
        
        self.last_blocklist_cleanup = now

    def set_active_blocklist(self, blocklist: Set[str]):
        """
        Updates the internal blocklist with permanent/manual entries.
        """
        expiry_date = datetime.now() + timedelta(days=365*100) # Effectively permanent
        new_blocklist = {ip: expiry_date for ip in blocklist}
        
        with self.lock:
            self.blocklist.update(new_blocklist) 
        print(f"CoreLogic: Updated blocklist with {len(self.blocklist)} total entries (including temporary/permanent).")
    
    # -------------------------------------------------
    # Monitoring Control (Start/Stop/Loops)
    # -------------------------------------------------
    def start_monitoring(self, target: str, mode: str, consumer_ui):
        """Starts a new monitoring thread, stopping any previous one."""
        self.stop() 
        self.is_running = True
        
        self.monitoring_target = target
        self.monitoring_mode = mode
        self.ui_consumer_page = consumer_ui
        
        if mode == 'file':
            target_func = self._file_loop
        elif mode == 'link_stream':
            target_func = self._sim_loop 
        else:
            target_func = self._sim_loop

        self.active_thread = threading.Thread(
            target=target_func, 
            args=(target, consumer_ui), 
            daemon=True,
            name=f"MonitorThread-{mode}"
        )
        self.active_thread.start()
        print(f"[CORE_LOGIC] Monitoring thread started in mode '{mode}' with target '{target}'")


    def stop(self):
        """Stops the active monitoring thread gracefully."""
        self.is_running = False
        
        if self.active_thread and self.active_thread.is_alive():
            self.active_thread.join(timeout=0.5)
            if self.active_thread.is_alive():
                print("CoreLogic: Warning: Main monitoring thread did not stop immediately.")
            self.active_thread = None
            
        print("CoreLogic: Monitoring thread signaled to stop.")


    def _file_loop(self, path, consumer):
        """Continuously tails a file for new log lines."""
        if not os.path.exists(path):
            try: consumer.process_line(f"{COLOR_RED_CONSOLE}[ERROR] File not found: {path}{COLOR_END_CONSOLE}")
            except Exception: pass
            self.is_running = False
            return

        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                
                # Process historical lines first
                f.seek(0, os.SEEK_SET)
                initial_lines = f.readlines()
                
                if initial_lines:
                    try: consumer.process_line(f"{COLOR_BLUE_CONSOLE}[INFO] Processing {len(initial_lines)} historical lines...{COLOR_END_CONSOLE}")
                    except Exception: pass
                    for line in initial_lines:
                        self._process_single_log(line.strip(), consumer)
                
                f.seek(0, os.SEEK_END)
                last_pos = f.tell()
                    
                try: consumer.process_line(f"{COLOR_BLUE_CONSOLE}[INFO] Monitoring {path} started. Awaiting new entries.{COLOR_END_CONSOLE}")
                except Exception: pass
                
                while self.is_running:
                    # Cleanup routines
                    self._cleanup_blocklist()
                    self._cleanup_rule_tracker()
                    
                    try:
                        current_size = os.path.getsize(path)
                    except FileNotFoundError:
                        try: consumer.process_line(f"{COLOR_RED_CONSOLE}[ERROR] Monitored file disappeared: {path}{COLOR_END_CONSOLE}")
                        except Exception: pass
                        break
                        
                    if current_size < last_pos:
                        try: consumer.process_line(f"{COLOR_RED_CONSOLE}[WARNING] Log file truncated. Restarting read.{COLOR_END_CONSOLE}")
                        except Exception: pass
                        f.seek(0, os.SEEK_SET)
                        last_pos = 0

                    elif current_size > last_pos:
                        f.seek(last_pos, os.SEEK_SET) 
                        for line in f:
                            self._process_single_log(line.strip(), consumer)
                        last_pos = f.tell() 
                            
                    time.sleep(0.5) 
                
        except Exception as e:
            error_msg = f"{COLOR_RED_CONSOLE}[ERROR] File Monitor Fatal Error: {type(e).__name__}: {e}{COLOR_END_CONSOLE}"
            try: consumer.process_line(error_msg)
            except Exception: pass
        finally:
            self.is_running = False
            try: consumer.process_line(f"{COLOR_BLUE_CONSOLE}Monitoring stopped.{COLOR_END_CONSOLE}")
            except Exception: pass


    def _sim_loop(self, target, consumer):
        """Simulates log line streaming with random anomalies (Generates dummy data)."""
        while self.is_running:
            try:
                self._cleanup_blocklist()
                self._cleanup_rule_tracker()

                is_anomaly = random.random() < 0.15
                timestamp = datetime.now() 
                ts_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')
                
                if is_anomaly:
                    # Use a general level here, final level determined by _perform_detection
                    level = random.choice(["Critical", "Error", "Warn"]) 
                    msg = random.choice(["SQL Injection Detected", "Root Login Failed", "Unauthorized access", "Denial of Service (DoS)"])
                    ip = f"103.{random.randint(100, 200)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
                    line = f"[{ts_str}] [{level}] {ip} - {msg} (SIM)"
                else:
                    level = random.choice(["Info", "Debug"])
                    msg = random.choice(["Health Check OK", "User 123 logged out", "Database connection successful", "Debug trace logged"])
                    ip = f"192.168.1.{random.randint(1,50)}"
                    line = f"[{ts_str}] [{level}] {ip} - {msg} (SIM)"

                self._process_single_log(line, consumer)
                
                time.sleep(random.uniform(0.1, 0.5))
            
            except Exception as e:
                error_msg = f"{COLOR_RED_CONSOLE}[ERROR] Simulator Loop Error: {type(e).__name__}: {e}{COLOR_END_CONSOLE}"
                print(error_msg)
                try: consumer.process_line(error_msg)
                except Exception: pass
                time.sleep(2) 
        
        try: consumer.process_line(f"{COLOR_BLUE_CONSOLE}Monitoring stopped.{COLOR_END_CONSOLE}")
        except Exception: pass


    def _process_single_log(self, line: str, consumer):
        """
        Processes, analyzes, updates shared queues, and sends the line to the UI consumer.
        """
        if not line: return 
        
        # --- 1. Parse Log Line ---
        parsed_data = self._parse_log_line(line)
        if not parsed_data: return # Failed to parse

        timestamp, level, message = parsed_data
        
        # 2. Heuristic and AI Scoring
        is_anomaly, final_level, category, ip, ai_score, ai_flag = self._perform_detection(line, message)
        
        # --- Check Active Blocklist (Proactive Defense) ---
        is_blocked = False
        with self.lock:
            if ip in self.blocklist and self.blocklist[ip] > datetime.now(): 
                is_blocked = True
                self.stats["threats_blocked"] += 1
            elif ip in self.blocklist and self.blocklist[ip] <= datetime.now():
                # Block has expired
                self.blocklist.pop(ip)
        
        if is_blocked:
            DB.log_action("PROACTIVE_IP_BLOCK", user_id=self.stats.get('user_id'), details=f"Blocked traffic from active blocklist IP: {ip}")
            try: consumer.process_line(f"{COLOR_BLUE_CONSOLE}[BLOCKED] {ip}: Traffic dropped due to active blocklist.{COLOR_END_CONSOLE}")
            except Exception: pass
            return # DROP THE LOG

        # 3. Update Global Stats and Shared Buffers
        with self.lock:
            self.stats["logs_processed"] += 1
            
            log_entry = {
                "timestamp": timestamp, 
                "level": final_level, 
                "ip": ip,
                "message": line,
                "category": category,
                "anomaly": is_anomaly
            }
            
            self.log_queue.appendleft(log_entry)
        
        # --- 4. Persistence (Traffic Log for Reports) ---
        try:
            DB.insert_traffic_log(timestamp.strftime('%Y-%m-%d %H:%M:%S'), ip, final_level, line, category) 
        except Exception as e:
            # Cannot use f-string with COLOR variables here without causing issues on non-console environment
            print(f"\033[91mDB Insert Failed: {e}\033[0m") 
            pass

        # 5. Handle Anomalies (Anomaly specific actions)
        if is_anomaly:
            
            with self.lock:
                self.stats["anomalies_total"] += 1
                self.stats["anomalies_this_second"] = self.stats.get("anomalies_this_second", 0) + 1 
                self.anomalies_in_current_interval += 1
            
            # Execute rules on the structured log entry
            self._check_and_execute_rules(log_entry)
            
            # --- Alert Queue Update ---
            alert_entry = {
                "timestamp": timestamp, 
                "severity": final_level, 
                "ip": ip,
                "description": f"[{category}] {message[:100]}...",
            }
            with self.lock:
                self.alert_queue.appendleft(alert_entry)

        # 6. Dashboard History Update
        now = datetime.now()
        
        with self.lock:
            # Update efficacy trend graph (cumulative)
            if (now - self.last_graph_update).total_seconds() >= 1.0 or is_anomaly:
                self.graph_data.appendleft((
                    now, 
                    self.stats["anomalies_total"], 
                    self.stats["threats_blocked"]
                ))
                self.last_graph_update = now
            
            # Update speed data (anomaly rate per second)
            if self.speed_data and (now - self.last_speed_update).total_seconds() >= 1.0:
                anomaly_rate = self.stats.get("anomalies_this_second", 0)
                self.speed_data.append((now, anomaly_rate))
                print(f"[SPEED_DATA] Appended anomaly rate: {anomaly_rate} at {now.strftime('%H:%M:%S')}, total in deque: {len(self.speed_data)}")
                self.stats["anomalies_this_second"] = 0  # Reset counter for next second
                self.last_speed_update = now

        # 7. Send to UI (LiveMonitorPage)
        ui_line = line
        if ai_flag:
            ui_line = f"{ui_line} {COLOR_RED_CONSOLE}[AI SCORE: {ai_score:.2f}]{COLOR_END_CONSOLE}"
        
        try:
            consumer.process_line(ui_line)
        except Exception:
            print("UI Consumer destroyed. Stopping CoreLogic thread.")
            self.stop() 


    def _parse_log_line(self, line: str) -> Optional[Tuple[datetime, str, str]]:
        """Parses a raw log line using a flexible regex."""
        match = LOG_PATTERN.match(line)
        if not match:
            # Fallback for completely unformatted lines
            timestamp = datetime.now()
            level = "Debug"
            message = line
            ip = IP_REGEX.search(line)
            if ip:
                # Remove IP from message for cleaner processing
                message = message.replace(ip.group(0), 'IP_REDACTED') 
            return timestamp, level, message
            
        try:
            timestamp = datetime.strptime(match.group('timestamp'), '%Y-%m-%d %H:%M:%S')
            level = match.group('level')
            message = match.group('message')
            return timestamp, level, message
        except ValueError as e:
            print(f"{COLOR_RED_CONSOLE}Parsing error: {e} for line: {line}{COLOR_END_CONSOLE}")
            return None


    def _perform_detection(
        self,
        line: str,
        message: str,
        detection_mode: str = "hybrid",
    ) -> Tuple[bool, str, str, str, float, bool]:
        """Runs heuristic and AI model to determine severity."""
        mode = (detection_mode or "hybrid").strip().lower()
        if mode not in DETECTION_MODES:
            mode = "hybrid"

        use_heuristic = mode in {"hybrid", "heuristic_only"}
        use_ml = mode in {"hybrid", "ml_only"}

        text = message.upper()
        score = 0.0
        ip = "N/A"
        ai_flag = False
        ai_score = 0.0
        
        # Extract IP from the full line, not just the message part
        ips = IP_REGEX.findall(line) 
        if ips: ip = ips[0]
        
        # --- Heuristic Scoring ---
        category = "General"
        # The scoring thresholds are now mapped to the five SeverityLevel strings
        
        if use_heuristic:
            if "CRITICAL" in text or "ROOT" in text or "DOS" in text or "MALWARE" in text:
                score += 2.0
                category = "Critical" 
            elif "ERROR" in text or "SQL" in text or "INJECTION" in text or "PRIVILEGE" in text:
                score += 1.2
                category = "Error"
            elif "FAILED" in text or "WARN" in text or "TIMEOUT" in text or "AUTH" in text or "UNAUTHORIZED" in text:
                score += 0.5
                category = "Warn"
            elif "INFO" in text or "HEALTH" in text or "DEBUG" in text:
                category = "Info"
            
        # --- AI/ML Scoring (Isolation Forest) ---
        if use_ml and SKLEARN_AVAILABLE and self.model and self.vectorizer:
            try:
                vec = self.vectorizer.transform([message])
                
                # IsolationForest prediction (-1 = anomaly, 1 = normal)
                if int(self.model.predict(vec)[0]) == -1: 
                    ai_flag = True
                    decision_score = self.model.decision_function(vec)[0] 
                    
                    # Normalize score for display (adjust if model output range changes)
                    ai_score = max(0.01, (1.0 - (decision_score / -0.5))) 
                    ai_score = min(1.0, ai_score)
                    
                    score += 1.5 
                    if category in ["General", "Info"]: category = "MLAnomaly"
            except Exception as e: 
                # Suppress frequent prediction errors unless debugging is needed
                pass
        
        # --- Final Severity Mapping --
        is_anomaly = score > 0.4 # Threshold for any non-info/debug event
        
        # Map the internal score to the five-level severity scale defined in config.py's SEV_ORDER 
        # (usually: Critical, Error, Warn, Info, Debug)
        final_level = "Info"
        if score >= 1.8: final_level = "Critical"
        elif score >= 1.0: final_level = "Error"
        elif score >= 0.5: final_level = "Warn"
        
        return is_anomaly, final_level, category, ip, ai_score, ai_flag

    def detect_line_for_evaluation(
        self,
        line: str,
        detection_mode: str = "hybrid",
    ) -> Optional[Dict[str, Any]]:
        """
        Lightweight inference helper for offline evaluation.
        Reuses the same parsing and detection path as live monitoring.
        """
        parsed = self._parse_log_line(line)
        if not parsed:
            return None

        timestamp, parsed_level, message = parsed
        is_anomaly, final_level, category, ip, ai_score, ai_flag = self._perform_detection(
            line,
            message,
            detection_mode=detection_mode,
        )

        return {
            "timestamp": timestamp,
            "parsed_level": parsed_level,
            "message": message,
            "predicted_anomaly": is_anomaly,
            "predicted_severity": final_level,
            "predicted_category": category,
            "source_ip": ip,
            "ai_score": ai_score,
            "ai_flag": ai_flag,
        }
