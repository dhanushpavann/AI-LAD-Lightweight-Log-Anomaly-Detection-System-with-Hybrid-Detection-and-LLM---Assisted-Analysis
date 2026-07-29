import os
import sys
import re
import json
import importlib
import subprocess
from datetime import datetime
from typing import List, Optional, Dict, Any, Tuple, Set 
import queue
import threading
from collections import deque, Counter 
import traceback


def _bootstrap_local_site_packages() -> None:
    """
    Ensure optional third-party dependencies can be found even when the app is
    launched with a different interpreter than the project venv.
    """
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    py_ver = f"python{sys.version_info.major}.{sys.version_info.minor}"
    candidates = [
        os.path.join(project_root, "venv", "lib", py_ver, "site-packages"),
        os.path.join(project_root, ".venv", "lib", py_ver, "site-packages"),
        os.path.join(project_root, "venv", "Lib", "site-packages"),   # Windows
        os.path.join(project_root, ".venv", "Lib", "site-packages"),  # Windows
    ]

    for candidate in candidates:
        if os.path.isdir(candidate) and candidate not in sys.path:
            sys.path.insert(0, candidate)


_bootstrap_local_site_packages()

import customtkinter as ctk
from tkinter import messagebox, Menu, Toplevel
from PIL import Image, ImageTk

# Try importing psutil for system health monitoring
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


# ====================================================================
# --- EXTERNAL DEPENDENCY IMPORTS (Non-Mocked) ---
# ====================================================================
# Import all constants and color mappings
from src.config import *

# Import core modules
from src.backend.database_manager import get_db_instance
from src.ui.components.modern_components import ModernComponents
# Use absolute package import for CoreLogic
from src.backend.core_logic import CoreLogic
# UI page imports (module resolution happens relative to package namespace)
from src.ui.pages.LoginPage import LoginPage
from src.ui.pages.PlaceholderPage import PlaceholderPage

def _safe_import_page(module_path: str, class_name: str):
    """Load page class safely; fallback to PlaceholderPage when import fails."""
    try:
        module = importlib.import_module(module_path)
        return getattr(module, class_name)
    except Exception as e:
        print(f"Warning: Falling back to PlaceholderPage for {class_name}: {e}")
        return PlaceholderPage


# --- RESILIENT PAGE IMPORTS ---
DashboardPage = _safe_import_page("src.ui.pages.Dashboard", "DashboardPage")
LiveMonitorPage = _safe_import_page("src.ui.pages.LiveMonitorPage", "LiveMonitorPage")
AlertsPage = _safe_import_page("src.ui.pages.AlertsPage", "AlertsPage")
ReportsPage = _safe_import_page("src.ui.pages.ReportsPage", "ReportsPage")
ResponseRulesPage = _safe_import_page("src.ui.pages.ResponseRulesPage", "ResponseRulesPage")
SettingsPage = _safe_import_page("src.ui.pages.SettingsPage", "SettingsPage")
ThreatIntelPage = _safe_import_page("src.ui.pages.ThreatIntelPage", "ThreatIntelPage")
LLMForensicsPage = _safe_import_page("src.ui.pages.LLMForensicsPage", "LLMForensicsPage")


# Use the function to get the single DB instance
DB = get_db_instance()

# Regex for IP extraction (needed by monitoring loops)
IP_REGEX = re.compile(r'(?:\d{1,3}\.){3}\d{1,3}')


def resource_path(relative_path: str) -> str:
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try: base_path = sys._MEIPASS
    except Exception: base_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    return os.path.join(base_path, relative_path)

# =========================================================================
# VALIDATION/ANIMATION HELPERS 
# =========================================================================
PANEL_W = 400
ANIM_STEPS = 40
ANIM_DELAY = 8

def _ease_in_out_cubic(t: float) -> float:
    if t < 0.5: return 4.0 * t * t * t
    else: t -= 1.0; return 4.0 * t * t * t + 1.0
        
# --- Spacing Constant (Derived from 8px grid logic) ---
G = 8
# =========================================================================


# --- Notification and User Dropdown Classes (Retained) ---
class ToastNotification:
# ... (Implementation retained) ...
    def __init__(self, master, message, toast_type="info", duration=3000):
        self.master = master
        self.message = message
        self.toast_type = toast_type
        self.duration = duration
        
        self.type_colors = {
            "info": ("ℹ️", COLOR_PRIMARY, COLOR_BG),
            "success": ("✅", COLOR_SUCCESS, COLOR_BG),
            "warning": ("⚠️", COLOR_WARNING, COLOR_BG),
            "error": ("❌", COLOR_ERROR, COLOR_BG)
        }
        
        self.icon, self.bg_color, self.text_color = self.type_colors.get(toast_type, self.type_colors["info"])
        
        self._create_toast()
        
    def _create_toast(self):
        self.toast = ctk.CTkToplevel(self.master)
        self.toast.wm_overrideredirect(True)
        self.toast.attributes('-topmost', True)
        self.toast.attributes('-alpha', 0.0)
        
        frame = ctk.CTkFrame(self.toast, fg_color=self.bg_color, corner_radius=UI_SETTINGS["corner_radius"])
        frame.pack(fill="both", expand=True, padx=2, pady=2)
        
        content = ctk.CTkFrame(frame, fg_color="transparent")
        content.pack(fill="x", padx=15, pady=12)
        
        ctk.CTkLabel(content, text=self.icon, font=(FONT_FAMILY, 18, "normal"), text_color=self.text_color).pack(side="left", padx=(0, 10))
        ctk.CTkLabel(content, text=self.message, font=FONT_BODY_MEDIUM, text_color=self.text_color).pack(side="left")
        
        self._position_toast()
        
        self._animate_in()
        
        self.toast.after(self.duration, self._animate_out)
        
    def _position_toast(self):
        self.master.update_idletasks()
        x = self.master.winfo_x() + self.master.winfo_width() - 350
        y = self.master.winfo_y() + 30
        self.toast.geometry(f"320x60+{x}+{y}")
        
    def _animate_in(self):
        def _fade(step=0):
            if step <= 10:
                alpha = step / 10
                self.toast.attributes('-alpha', alpha)
                self.toast.after(20, lambda: _fade(step + 1))
        _fade()
        
    def _animate_out(self):
        def _fade(step=10):
            if step >= 0:
                alpha = step / 10
                self.toast.attributes('-alpha', alpha)
                self.toast.after(20, lambda: _fade(step - 1))
            else:
                self.toast.destroy()
        _fade()


class NotificationDropdown:
# ... (Implementation retained) ...
    def __init__(self, master, alerts_queue):
        self.master = master
        self.alerts_queue = alerts_queue
        self.window = None
        self._create_dropdown()
        
    def _create_dropdown(self):
        if self.window:
            self.window.destroy()
            
        self.window = ctk.CTkToplevel(self.master)
        self.window.wm_overrideredirect(True)
        self.window.attributes('-topmost', True)
        
        container = ctk.CTkFrame(self.window, fg_color=COLOR_ELEVATION_1, corner_radius=UI_SETTINGS["corner_radius"])
        container.pack(fill="both", expand=True)
        
        header = ctk.CTkFrame(container, fg_color=COLOR_ELEVATION_2)
        header.pack(fill="x", pady=(0, 1))
        
        ctk.CTkLabel(header, text="Recent Alerts", font=FONT_HEADING, text_color=COLOR_TEXT).pack(side="left", padx=15, pady=10)
        
        clear_btn = ctk.CTkButton(
            header, text="Clear All", command=self._clear_alerts,
            fg_color=COLOR_RED, hover_color=COLOR_ERROR,
            height=28, font=FONT_CAPTION
        )
        clear_btn.pack(side="right", padx=15)
        
        alerts_frame = ctk.CTkScrollableFrame(container, fg_color="transparent", height=300)
        alerts_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        alerts = list(self.alerts_queue)[:10] 
        
        if not alerts:
            ctk.CTkLabel(alerts_frame, text="No alerts", font=FONT_BODY, text_color=COLOR_TEXT_SECONDARY).pack(pady=50)
        else:
            for alert in alerts:
                self._create_alert_item(alerts_frame, alert)
                
        self._position_dropdown()
        
    def _create_alert_item(self, parent, alert):
        severity = alert.get('severity', 'Warn').lower()
        severity_colors = {
            "low": COLOR_SUCCESS, "info": COLOR_INFO, "warn": COLOR_WARNING,
            "medium": COLOR_WARNING, "high": COLOR_RED, "error": COLOR_ERROR,
            "critical": COLOR_ERROR
        }
        color = severity_colors.get(severity, COLOR_WARNING)
        
        item = ctk.CTkFrame(parent, fg_color=COLOR_ELEVATION_2, corner_radius=UI_SETTINGS["corner_radius"])
        item.pack(fill="x", pady=5, padx=5)
        
        icon_frame = ctk.CTkFrame(item, fg_color=color, width=4, corner_radius=0)
        icon_frame.pack(side="left", fill="y")
        icon_frame.pack_propagate(False)
        
        content = ctk.CTkFrame(item, fg_color="transparent")
        content.pack(side="left", fill="both", expand=True, padx=15, pady=12)
        
        title = alert.get('description', 'Untitled Alert')
        timestamp = alert.get('timestamp', '')
        
        ctk.CTkLabel(content, text=title, font=FONT_BODY_MEDIUM, text_color=COLOR_TEXT).pack(anchor="w")
        if timestamp:
            ts_str = timestamp.strftime('%H:%M:%S') if isinstance(timestamp, datetime) else str(timestamp)
            ctk.CTkLabel(content, text=ts_str, font=FONT_CAPTION, text_color=COLOR_TEXT_SECONDARY).pack(anchor="w")
            
    def _position_dropdown(self):
        self.master.update_idletasks()
        
        master_x = self.master.winfo_rootx()
        master_y = self.master.winfo_rooty()
        master_w = self.master.winfo_width()
        master_h = self.master.winfo_height()
        
        dropdown_w = 350
        dropdown_h = 400 
        
        x = master_x + master_w - dropdown_w
        y = master_y + master_h + 5
        
        self.window.geometry(f"{dropdown_w}x{dropdown_h}+{x}+{y}")
        
    def _clear_alerts(self):
        self.alerts_queue.clear()
        if self.window: self.window.destroy()


class UserMenuDropdown:
# ... (Implementation retained) ...
    def __init__(self, master, user_info, on_logout):
        self.master = master
        self.user_info = user_info
        self.on_logout = on_logout
        self.window = None
        self._create_dropdown()
        
    def _create_dropdown(self):
        self.window = ctk.CTkToplevel(self.master)
        self.window.wm_overrideredirect(True)
        self.window.attributes('-topmost', True)
        
        container = ctk.CTkFrame(self.window, fg_color=COLOR_ELEVATION_1, corner_radius=UI_SETTINGS["corner_radius"])
        container.pack(fill="both", expand=True)
        
        user_frame = ctk.CTkFrame(container, fg_color=COLOR_ELEVATION_2)
        user_frame.pack(fill="x", pady=(0, 1))
        
        ctk.CTkLabel(user_frame, text="👤", font=(FONT_FAMILY, 40, "normal"), text_color=COLOR_PRIMARY).pack(pady=(15, 5))
        ctk.CTkLabel(user_frame, text=self.user_info.get('name', 'User'), font=FONT_HEADING, text_color=COLOR_TEXT).pack(pady=(0, 5))
        ctk.CTkLabel(user_frame, text=self.user_info.get('email', 'Guest'), font=FONT_CAPTION, text_color=COLOR_TEXT_SECONDARY).pack(pady=(0, 15))
        
        menu_items = [
            {"text": "👤 Profile Settings", "command": lambda: self._open_settings("👤 Settings")},
            {"text": "🚪 Logout", "command": self._logout, "color": COLOR_RED}
        ]
        
        for item in menu_items:
            btn = ctk.CTkButton(
                container,
                text=item["text"],
                command=item["command"],
                fg_color="transparent",
                hover_color=item.get("color", COLOR_ELEVATION_2) if "color" in item else COLOR_ELEVATION_2,
                text_color=item.get("color", COLOR_TEXT) if "color" in item else COLOR_TEXT,
                height=40,
                font=FONT_BODY,
                anchor="w",
                corner_radius=0
            )
            btn.pack(fill="x", padx=5, pady=2)
            
        self._position_dropdown()
        
    def _position_dropdown(self):
        self.master.update_idletasks()
        
        master_x = self.master.winfo_rootx()
        master_y = self.master.winfo_rooty()
        master_w = self.master.winfo_width()
        master_h = self.master.winfo_height()
        
        dropdown_w = 250
        dropdown_h = 300 
        
        x = master_x + master_w - dropdown_w
        y = master_y + master_h + 5
        
        self.window.geometry(f"{dropdown_w}x{dropdown_h}+{x}+{y}")
        
    def _open_settings(self, page_name):
        self.window.destroy()
        self.master.master.master._on_sidebar_click(page_name) 

    def _logout(self):
        if messagebox.askyesno("Logout", "Are you sure you want to logout?"):
            self.window.destroy()
            self.on_logout()


class Ai_LAD(ctk.CTk):
    """
    Main application window (Controller). 
    Manages central state, delegates monitoring to CoreLogic, and handles navigation/UI.
    """
    # Define FONT_SIDEBAR_BOLD here using the tuple format from config.py
    FONT_SIDEBAR_BOLD = (FONT_FAMILY, 17, "bold") 
    FONT_SIDEBAR_NORMAL = (FONT_FAMILY, 17, "normal") 
    FONT_SIDEBAR_SMALL = (FONT_FAMILY, 14, "normal") 
    
    SIDEBAR_WIDTH = 250 
    RESIZE_THRESHOLD = 1000
    resize_job = None

    def __init__(self, user_info: Dict[str, Any]):
        super().__init__()
        
        self.tk.call('after', 'cancel', 'all')
        
        self.user_info = user_info

        # --- Centralized State ---
        self.global_stats = {
            "logs_processed": 0, "anomalies_total": 0, "threats_blocked": 0,
            "anomalies_this_second": 0, # Used for Live Monitor Speed Graph
            "user_id": user_info.get('id') # Pass user ID for logging actions
        }
        self.global_alert_queue = deque(maxlen=500)
        self.global_log_queue = deque(maxlen=1000)
        self.active_blocklist: set[str] = set()
        self.ip_queue = queue.Queue()
        self.ip_cache = {}

        # --- PERSISTENT DATA BUFFERS (For Dashboard Metrics) ---
        self.global_graph_data = deque(maxlen=60)      # Efficacy Trend (UPDATED BY CORE LOGIC)
        self.global_speed_data = deque(maxlen=60)      # AI Speed Chart Data
        self.global_pie_counts = Counter()             # Threat Categories
        self.global_top_ips = Counter()                # Top Attacking IPs
        self.global_geo_counts = Counter()             # Threat Geographies
        self.global_rule_action_counts = Counter()     # Automated Response Summary (NEW)
        self.global_stats["rule_action_counts"] = self.global_rule_action_counts

        # CORE LOGIC INSTANCE (Instantiate the actual CoreLogic class)
        try:
            # Pass the shared stats dict directly so the Live Monitor sees updates.
            self.core_logic = CoreLogic(
                self.global_stats, 
                self.global_log_queue, 
                self.global_alert_queue, 
                self.global_graph_data, # Efficacy trend
                self.global_speed_data  # Anomaly rate (events/sec)
            )
            self.core_logic.set_active_blocklist(self.active_blocklist)
        except Exception as e:
            print(f"FATAL ERROR: Failed to initialize CoreLogic. Check dependencies. Error: {e}")
            self.core_logic = object() 
            self.core_logic.start_monitoring = lambda *args: print("Monitoring disabled due to CoreLogic error.")
            self.core_logic.stop = lambda: print("Monitoring stop disabled.")
            self.core_logic.get_ai_status = lambda: "AI FAILED: CHECK CORELOGIC"
            self.core_logic.set_active_blocklist = lambda *args: None
            self.core_logic.load_custom_model = lambda *args: (False, "CoreLogic error.")
            self.core_logic.analyze_with_llm = lambda *args: "CoreLogic error."
            
        # Monitoring State
        self.monitoring_target = None
        self.monitoring_mode = None
        self.is_monitoring = False

        # --- UI Job IDs for graceful shutdown ---
        self.notif_job = None
        self.health_job = None

        # --- Window Setup ---
        self.title(f"🛡️ AI LAD  - {self.user_info.get('name', 'User')}")
        self.minsize(1280, 720)
        self.configure(fg_color=COLOR_BG)
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        self._setup_icon()

        # --- UI State ---
        self.sidebar_buttons = {}
        self.current_page: Optional[ctk.CTkFrame] = None
        self.current_page_name: Optional[str] = None
        
        self.header_frame = None
        self.header_notif_btn = None
        self.header_user_btn = None
        self.header_title_label = None 
        self.logo_image = None 

        # --- Page Map ---
        self.page_map = {
            "📊 Dashboard": DashboardPage, 
            "📈 Live Monitor": LiveMonitorPage,
            "🔔 Alerts & Anomalies": AlertsPage, 
            "🧠 AI Forensic": LLMForensicsPage,
            # "🌍 Threat Intel": ThreatIntelPage,
            "⚙️ Response Rules": ResponseRulesPage, 
            "📄 Reports": ReportsPage,
            "👤 Settings": SettingsPage
        }

        # --- Build UI ---
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=0)
        self.grid_columnconfigure(1, weight=1)

        self._build_sidebar()
        self._build_main_area()

        self.bind("<Configure>", self._on_app_resize)

        # --- Start Background Tasks ---
        self._update_notifications()
        self._update_system_health()

        self._apply_resize_styles()

        self.after(100, lambda: self.wm_state('zoomed'))
        self._on_sidebar_click("📊 Dashboard")

    def _setup_icon(self):
        """Sets the window icon from assets/logo.png or fails silently."""
        try:
            icon_path_png = resource_path("assets/logo.png")
            if not os.path.exists(icon_path_png): return

            pil_image = Image.open(icon_path_png).resize((32, 32)) # Reduced size for taskbar icon
            tk_image = ImageTk.PhotoImage(pil_image)
            self.tk_image = tk_image 
            self.iconphoto(True, tk_image)
        except Exception:
            pass

    def _on_app_resize(self, event):
        """ Handles the application resize event. """
        if self.resize_job:
            self.after_cancel(self.resize_job)

        self.resize_job = self.after_idle(self._apply_resize_styles)


    def _apply_resize_styles(self):
        """Applies the necessary font and style changes based on current window size."""
        current_width = self.winfo_width()

        if current_width < self.RESIZE_THRESHOLD:
            font = self.FONT_SIDEBAR_SMALL
        else:
            font = FONT_SIDEBAR

        for btn in self.sidebar_buttons.values():
            btn.configure(font=font)

        if hasattr(self, 'logout_btn'):
            self.logout_btn.configure(font=font)


    def _build_sidebar(self):
        """ Creates the sleek, modern left-hand navigation panel with reduced padding. """
        self.sidebar = ctk.CTkFrame(self, width=self.SIDEBAR_WIDTH, fg_color=COLOR_SIDEBAR, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="ns")
        self.sidebar.pack_propagate(False)
        
        self.sidebar_scroll = ctk.CTkScrollableFrame(self.sidebar, fg_color="transparent", border_width=0)
        self.sidebar_scroll.pack(fill="both", expand=True, padx=0, pady=0)


        self._add_sidebar_logo(self.sidebar_scroll) 

        # --- Navigation Buttons ---
        for text in self.page_map.keys():
            self._add_sidebar_button(text, self.sidebar_scroll)

        # --- Footer Controls (Pinned to the bottom of the main sidebar) ---
        footer_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        footer_frame.pack(side="bottom", fill="x", padx=0, pady=0)
        
        # CPU/RAM Label is now styled as a component with fixed dark background (Original restore)
        self.sys_health_label_frame = ctk.CTkFrame(footer_frame, fg_color=COLOR_ELEVATION_2, height=20, corner_radius=10) # FIX: Fixed dark background
        self.sys_health_label_frame.pack(side="bottom", fill="x", pady=(5, 0))
        
        self.sys_health_label = ctk.CTkLabel(self.sys_health_label_frame, text="CPU: 0% | RAM: 0%", font=FONT_CAPTION, text_color=COLOR_TEXT_SECONDARY)
        self.sys_health_label.pack(side="bottom", pady=G*3, padx=G*2)


        self.logout_btn = ctk.CTkButton(
            footer_frame, text="⛔ Logout", command=self.logout,
            fg_color=COLOR_RED, hover_color=COLOR_ORANGE,
            height=UI_SETTINGS["button_height"]-10, 
            font=FONT_SIDEBAR,
            text_color=COLOR_BG,
            corner_radius=UI_SETTINGS["corner_radius"]
        )
        self.logout_btn.pack(side="bottom", fill="x", padx=G*2, pady=G*2) # Reduced margin

    def _add_sidebar_logo(self, parent_frame):
        """ 
        Adds the logo and tool name, stacked and centered, with increased icon size.
        """
        logo_frame = ctk.CTkFrame(parent_frame, fg_color="transparent")
        logo_frame.pack(pady=(G*2, G*2))
        
        vertical_frame = ctk.CTkFrame(logo_frame, fg_color="transparent")
        vertical_frame.pack(anchor=ctk.CENTER)
        
        # 1. Logo Icon Label (Increased size: 55, Offset margin)
        icon_label = ctk.CTkLabel(
            vertical_frame,
            text="🛡️",
            font=(FONT_FAMILY, 65, "normal"), # Increased size to 55
            text_color=COLOR_PRIMARY 
        )
        # FIX: Added left margin to icon
        icon_label.pack(side="top", padx=(G*4, 0), pady=(0, G/2)) 

        # 2. Tool Name (Increased size and centered)
        ctk.CTkLabel(
            vertical_frame, 
            text="AI LAD", 
            font=(FONT_FAMILY, 22, "bold"), # Slightly increased text size (from 20 to 22)
            text_color=COLOR_PRIMARY
        ).pack(side="top", padx=(0, 0))


    def _add_sidebar_button(self, name: str, parent_frame):
        """Adds a styled navigation button with reduced margin."""
        btn = ctk.CTkButton(
            parent_frame,
            text=name,
            height=UI_SETTINGS["button_height"] - 5, # Slightly reduced height
            fg_color="transparent",
            hover_color=COLOR_ELEVATION_3,
            border_width=UI_SETTINGS["border_width"], 
            border_color=COLOR_DIVIDER,
            text_color=COLOR_TEXT_SECONDARY,
            font=FONT_SIDEBAR,
            anchor="w",
            command=lambda n=name: self._on_sidebar_click(n)
        )
        # Increased margin between buttons (G = 8px padding)
        btn.pack(fill="x", pady=G, padx=G) 
        self.sidebar_buttons[name] = btn

    # --- DEDICATED HEADER BUILDING METHOD (Existing) ---
    def _build_main_area(self):
        """Creates the main content area including the modern header."""
        self.main_panel = ctk.CTkFrame(self, fg_color=COLOR_BG)
        self.main_panel.grid(row=0, column=1, sticky="nsew")
        self.main_panel.grid_rowconfigure(1, weight=1)
        self.main_panel.grid_columnconfigure(0, weight=1)

        self._build_header()
        
        self.content_area = ctk.CTkFrame(self.main_panel, fg_color="transparent")
        self.content_area.grid(row=1, column=0, sticky="nsew", 
                               padx=UI_SETTINGS["spacing"]["md"], 
                               pady=UI_SETTINGS["spacing"]["md"])

    def _build_header(self):
        """
        Builds the modern, dark-themed header bar (Title, Search, Notif, User).
        """
        self_header_frame = ctk.CTkFrame(self.main_panel, fg_color=COLOR_ELEVATION_1, corner_radius=0)
        
        self_header_frame.grid_rowconfigure(0, weight=1)
        self_header_frame.grid_columnconfigure(0, weight=1) 
        self_header_frame.grid_columnconfigure(1, weight=0) 
        
        # 1. Title Label (Left side) 
        self.header_title_label = ctk.CTkLabel(
            self_header_frame, text="", font=FONT_HEADING, text_color=COLOR_PRIMARY
        )
        self.header_title_label.grid(
            row=0, column=0, sticky="w", padx=(UI_SETTINGS["spacing"]["lg"], 0), pady=UI_SETTINGS["spacing"]["md"]
        )
        
        right_frame = ctk.CTkFrame(self_header_frame, fg_color="transparent")
        right_frame.grid(row=0, column=1, sticky="e", padx=(0, UI_SETTINGS["spacing"]["lg"]), pady=UI_SETTINGS["spacing"]["sm"])
        
        # 2. Search Bar 
        search_frame = ctk.CTkFrame(
            right_frame, 
            fg_color=COLOR_ELEVATION_3, 
            corner_radius=UI_SETTINGS["corner_radius"],
            width=250, 
            height=36 
        )
        search_frame.pack(side="left", padx=(0, UI_SETTINGS["spacing"]["md"]), ipady=0)
        search_frame.pack_propagate(False)

        search_icon = ctk.CTkLabel(search_frame, text="🔍", font=(FONT_FAMILY, 16), text_color=COLOR_TEXT_SECONDARY)
        search_icon.pack(side="left", padx=(10, 5))
        
        search_entry = ctk.CTkEntry(
            search_frame, 
            placeholder_text="Search logs, alerts, IPs...", 
            fg_color="transparent",
            border_width=0,
            width=200, 
            font=FONT_BODY_SMALL 
        )
        search_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        search_entry.bind("<Return>", lambda e: self._perform_global_search(search_entry.get()))
        
        # 3. Notification Button 
        count = len(self.global_alert_queue)
        
        notif_fg = COLOR_ELEVATION_3
        notif_hover = COLOR_ELEVATION_4
        notif_text = COLOR_TEXT
        
        if count > 0:
             notif_fg = COLOR_RED
             notif_hover = COLOR_ERROR
             notif_text = COLOR_BG

        self.header_notif_btn = ctk.CTkButton(
            right_frame, 
            text=f"🔔 {count}", 
            command=lambda: NotificationDropdown(self.header_notif_btn, self.global_alert_queue), 
            width=50, 
            height=36, 
            fg_color=notif_fg,
            hover_color=notif_hover,
            text_color=notif_text,
            corner_radius=UI_SETTINGS["corner_radius"],
            font=FONT_BODY_MEDIUM
        )
        self.header_notif_btn.pack(side="left", padx=UI_SETTINGS["spacing"]["md"])
        
        # 4. User Button 
        user_name = self.user_info.get('name', 'User')
        self.header_user_btn = ctk.CTkButton(
            right_frame, 
            text=f"👤 {user_name}", 
            command=lambda: UserMenuDropdown(self.header_user_btn, self.user_info, self.logout),
            height=36, 
            fg_color=COLOR_PRIMARY,
            hover_color=COLOR_PRIMARY_VARIANT, 
            text_color=COLOR_BG,
            corner_radius=UI_SETTINGS["corner_radius"],
            font=FONT_BODY_MEDIUM
        )
        self.header_user_btn.pack(side="left")

        self_header_frame.grid(row=0, column=0, sticky="ew")
        self.header_frame = self_header_frame 

    # --- BLOCKLIST MANAGEMENT & RULE RELOAD ---
    def add_to_blocklist(self, ip: str) -> bool:
        if ip not in self.active_blocklist:
            self.active_blocklist.add(ip)
            try: self.core_logic.set_active_blocklist(self.active_blocklist)
            except AttributeError: pass
            return True
        return False

    def remove_from_blocklist(self, ip: str) -> bool:
        if ip in self.active_blocklist:
            self.active_blocklist.remove(ip)
            try: self.core_logic.set_active_blocklist(self.active_blocklist)
            except AttributeError: pass
            return True
        return False

    def get_active_blocklist(self) -> set[str]:
        return self.active_blocklist

    def get_alert_queue(self) -> deque:
        """Non-destructive getter for the global alert queue."""
        return self.global_alert_queue
        
    def reload_core_logic_rules(self):
        """Triggers the CoreLogic thread to reload rules from the database."""
        if hasattr(self, 'core_logic') and hasattr(self.core_logic, 'reload_rules'):
            try:
                self.core_logic.load_rules() # CoreLogic's load_rules method handles the reload
                return True
            except Exception as e:
                print(f"Error reloading core logic rules: {e}")
                return False
        return False


    # --- UI Update Loops (Performance Indicator) ---
    def _update_notifications(self):
        """Updates the bell icon count based on alert queue size, with color change."""
        if self.header_notif_btn and self.header_notif_btn.winfo_exists():
            count = len(self.global_alert_queue)
            
            text = f"🔔 {count}" if count > 0 else "🔔"
            
            if count > 0:
                fg_color = COLOR_RED
                hover_color = COLOR_ERROR
                text_color = COLOR_BG
            else:
                fg_color = COLOR_ELEVATION_3 
                hover_color = COLOR_ELEVATION_4
                text_color = COLOR_TEXT 
                
            try:
                self.header_notif_btn.configure(
                    text=text, fg_color=fg_color, hover_color=hover_color, text_color=text_color
                )
            except Exception: pass

        self.notif_job = self.after(2000, self._update_notifications)

    def _get_system_health_fallback(self) -> Tuple[Optional[float], Optional[float]]:
        """Best-effort fallback for CPU/RAM when psutil is unavailable."""
        cpu: Optional[float] = None
        mem: Optional[float] = None

        try:
            if sys.platform == "darwin":
                vm_out = subprocess.run(
                    ["vm_stat"],
                    capture_output=True,
                    text=True,
                    timeout=2,
                    check=False
                ).stdout

                page_size_match = re.search(r"page size of (\d+) bytes", vm_out)
                if page_size_match:
                    page_size = float(page_size_match.group(1))
                    pages = {}
                    for line in vm_out.splitlines():
                        stat_match = re.match(r"^([^:]+):\s+(\d+)\.", line.strip())
                        if stat_match:
                            pages[stat_match.group(1).strip().lower()] = float(stat_match.group(2))

                    free_pages = pages.get("pages free", 0.0)
                    active_pages = pages.get("pages active", 0.0)
                    inactive_pages = pages.get("pages inactive", 0.0)
                    wired_pages = pages.get("pages wired down", 0.0)
                    compressed_pages = pages.get("pages occupied by compressor", 0.0)

                    used_pages = active_pages + inactive_pages + wired_pages + compressed_pages
                    total_pages = used_pages + free_pages
                    if total_pages > 0:
                        # Keep page_size parsed/validated, even though ratio is page-count based.
                        _ = page_size
                        mem = (used_pages / total_pages) * 100.0

                try:
                    load_1m = os.getloadavg()[0]
                    cpu_count = max(os.cpu_count() or 1, 1)
                    cpu = min(max((load_1m / cpu_count) * 100.0, 0.0), 100.0)
                except Exception:
                    pass

            elif sys.platform.startswith("linux"):
                try:
                    with open("/proc/meminfo", "r", encoding="utf-8") as f:
                        meminfo = f.read()
                    total_match = re.search(r"MemTotal:\s+(\d+)\s+kB", meminfo)
                    avail_match = re.search(r"MemAvailable:\s+(\d+)\s+kB", meminfo)
                    if total_match and avail_match:
                        total_kb = float(total_match.group(1))
                        avail_kb = float(avail_match.group(1))
                        if total_kb > 0:
                            mem = ((total_kb - avail_kb) / total_kb) * 100.0
                except Exception:
                    pass

                try:
                    load_1m = os.getloadavg()[0]
                    cpu_count = max(os.cpu_count() or 1, 1)
                    cpu = min(max((load_1m / cpu_count) * 100.0, 0.0), 100.0)
                except Exception:
                    pass
        except Exception:
            pass

        return cpu, mem

    def _update_system_health(self):
        """Updates the sidebar system status label with background color change."""
        global PSUTIL_AVAILABLE, psutil
        cpu_val = "N/A"
        ram_val = "N/A"
        
        # Default fixed background
        bg_color = COLOR_ELEVATION_2 
        text_color_final = COLOR_TEXT_SECONDARY

        # Retry import at runtime in case startup import failed due environment timing.
        if not PSUTIL_AVAILABLE:
            try:
                psutil = importlib.import_module("psutil")
                PSUTIL_AVAILABLE = True
            except Exception:
                PSUTIL_AVAILABLE = False

        cpu = None
        mem = None
        if PSUTIL_AVAILABLE:
            try:
                cpu = psutil.cpu_percent(interval=None)
                mem = psutil.virtual_memory().percent
            except Exception:
                pass

        if cpu is None or mem is None:
            fb_cpu, fb_mem = self._get_system_health_fallback()
            if cpu is None:
                cpu = fb_cpu
            if mem is None:
                mem = fb_mem

        if cpu is not None:
            cpu_val = f"{cpu:.1f}%"
        if mem is not None:
            ram_val = f"{mem:.1f}%"

        if cpu is not None and mem is not None:
            # Logic to determine status color
            if cpu > 80 or mem > 85:
                # HIGH LOAD: Text must be RED for urgency
                text_color_final = COLOR_RED
            elif cpu > 50 or mem > 60:
                # MEDIUM LOAD: Text must be ORANGE/WARNING
                text_color_final = COLOR_WARNING
            else:
                # LOW LOAD: Text is GREEN/SUCCESS
                text_color_final = COLOR_SUCCESS

        status = f"CPU: {cpu_val} | RAM: {ram_val}"

        if self.sys_health_label.winfo_exists():
            try:
                # FIX: Text is now bold and uses dynamic status color
                self.sys_health_label.configure(text=status, text_color=text_color_final, font=FONT_BODY_MEDIUM) 
                # FIX: Background is fixed dark (COLOR_ELEVATION_2)
                self.sys_health_label_frame.configure(fg_color=COLOR_ELEVATION_2) 
            except Exception: pass

        self.health_job = self.after(5000, self._update_system_health)

    # --- Navigation ---

    def _switch_page(self, page_class, page_name: str):
        """ Handles the actual page cleanup and loading sequence in the content area. """
        if self.current_page:
            if hasattr(self.current_page, 'stop_threads') and callable(getattr(self.current_page, 'stop_threads')):
                try: 
                    self.current_page.stop_threads()
                except Exception: 
                    print("Warning: Failed to stop threads on previous page.")

            try:
                self.current_page.destroy()
            except Exception: 
                print("Warning: Failed to destroy previous page widget.")
            self.current_page = None

        try:
            if page_class == PlaceholderPage:
                self.current_page = PlaceholderPage(parent=self.content_area, controller=self, page_name=page_name)
            else:
                self.current_page = page_class(parent=self.content_area, controller=self)

            self.current_page.pack(fill="both", expand=True)
            print(f"Loaded new page: {page_name}")
            
        except Exception:
            error_trace = traceback.format_exc()
            print(f"--- PAGE LOAD ERROR: {page_name} ---")
            print(error_trace)
            
            # Show a generic error page
            self.current_page = ctk.CTkFrame(self.content_area, fg_color=COLOR_CARD)
            ctk.CTkLabel(self.current_page, text=f"❌ Page Load Failed: {page_name}", font=FONT_TITLE, text_color=COLOR_RED).pack(pady=20)
            ctk.CTkLabel(self.current_page, text="Check console for traceback.", font=FONT_BODY, text_color=COLOR_TEXT_SECONDARY).pack(pady=5)
            self.current_page.pack(fill="both", expand=True, padx=50, pady=50)


    def _on_sidebar_click(self, name: str):
        """Handles page switching logic and button styling."""
        if self.current_page_name == name: return

        page_class = self.page_map.get(name)
        
        if not page_class:
            print(f"Error: No page class defined for button '{name}'")
            return 
            
        print(f"Switching to page: {name}")
        self.current_page_name = name

        # Update button styles
        for bname, btn in self.sidebar_buttons.items():
            is_active = (bname == name)
            btn.configure(
                fg_color=COLOR_PRIMARY if is_active else "transparent",
                text_color=COLOR_BG if is_active else COLOR_TEXT,
                hover_color=COLOR_PRIMARY_VARIANT if is_active else COLOR_ELEVATION_3,
                border_width=UI_SETTINGS["border_width"],
                border_color=COLOR_ACCENT if is_active else COLOR_DIVIDER 
            )

        # Update Header Title
        try:
            if hasattr(self, 'header_title_label'):
                self.header_title_label.configure(text=name)
        except Exception: 
            pass

        self._switch_page(page_class, name)


    def _perform_global_search(self, query):
        messagebox.showinfo("Search", f"Searching database for: {query}")


    # --- MONITORING BRIDGE (DELEGATION TO CORELOGIC) ---
    def start_monitoring_thread(self, target: str, mode: str, consumer_page: ctk.CTkFrame):
        if self.is_monitoring: return
        self.monitoring_target = target
        self.monitoring_mode = mode
        self.is_monitoring = True

        self.core_logic.start_monitoring(target, mode, consumer_page)

    def stop_monitoring_thread(self):
        if not self.is_monitoring: return
        self.is_monitoring = False
        self.core_logic.stop()

    # --- UI Loop Cancellation Helper ---
    def _cancel_ui_loops(self):
        if self.notif_job:
            try: self.after_cancel(self.notif_job)
            except Exception: pass
            self.notif_job = None

        if self.health_job:
            try: self.after_cancel(self.health_job)
            except Exception: pass
            self.health_job = None

        self.tk.call('after', 'cancel', 'all')
        self.resize_job = None

    # --- System Control ---
    def on_close(self):
        if messagebox.askokcancel("Quit", "Do you want to quit?"):
            self.stop_monitoring_thread()

            if self.current_page and hasattr(self.current_page, 'stop_threads'):
                try: self.current_page.stop_threads()
                except Exception: pass

            self._cancel_ui_loops()

            DB.close()
            self.destroy()
            sys.exit(0)

    def logout(self):
        if not messagebox.askyesno("Logout", "Are you sure you want to logout?"): return

        self.stop_monitoring_thread()
        if self.current_page and hasattr(self.current_page, 'stop_threads'):
            self.current_page.stop_threads()

        self._cancel_ui_loops()

        DB.log_action("USER_LOGOUT", self.user_info.get('id'), details="Logged out.")
        
        self.destroy()
        
        # Instantiate and run the LoginPage
        login_app = LoginPage()
        login_app.mainloop()
        
          # --- NEW: Bridge Method for Forensics ---
    def analyze_log_in_forensics(self, log_text: str):
        """
        Switches to the AI Forensic page and initiates analysis for the given log text.
        """
        # 1. Switch to the Forensic Page
        self._on_sidebar_click("🧠 AI Forensic")
        
        # 2. Pass data to the page instance
        # We need to wait briefly for the page to initialize if it wasn't already loaded
        self.after(100, lambda: self._pass_log_to_forensics(log_text))
            
    def _pass_log_to_forensics(self, log_text: str):
        """Internal helper to pass data to the active forensic page instance."""
        if isinstance(self.current_page, LLMForensicsPage):
            # Set the mode to 'Local File' (conceptually similar to 'Direct Input') 
            # or we can add a 'Direct Input' mode to LLMForensicsPage.
            # For now, let's save it to a temporary file and load it, or simply 
            # expose a method on LLMForensicsPage to accept raw text.
            
            # Ideally, LLMForensicsPage should have a method like:
            if hasattr(self.current_page, 'load_log_snippet'):
                 self.current_page.load_log_snippet(log_text)
            else:
                 print("Error: LLMForensicsPage missing 'load_log_snippet' method.")
