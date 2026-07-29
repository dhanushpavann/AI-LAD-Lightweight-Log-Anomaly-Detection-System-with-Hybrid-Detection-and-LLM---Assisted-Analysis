import os
import csv
import re
import time
import queue
import threading
import requests
import platform 
from datetime import datetime, timedelta
from collections import deque, Counter
from tkinter import filedialog, messagebox, Canvas
from typing import Optional, List, Dict, Any, Tuple, Set 

import customtkinter as ctk
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import matplotlib.ticker as mticker 
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# Import config, components, and DB access
from src.config import *
from src.ui.components.modern_components import ModernComponents
from src.backend.database_manager import get_db_instance

DB = get_db_instance() 

# --- Constants ---
IP_REGEX = re.compile(r'(?:\d{1,3}\.){3}\d{1,3}')
IP_API_URL = "http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as,query,proxy,mobile,message"
IP_CACHE_TTL = 600 # 10 minutes cache for IP info

# --- Define COLOR_GREEN if it's missing from config.py ---
try:
    COLOR_GREEN = COLOR_SUCCESS
except NameError:
    COLOR_GREEN = "#2ECC71"
# ------------------------------------------------------------------

# --- Custom Color Palette for Matplotlib Categorical Data ---
MATPLOTLIB_COLORS = [
    COLOR_PRIMARY, 
    COLOR_ACCENT, 
    COLOR_WARNING, 
    COLOR_INFO, 
    COLOR_ORANGE, 
    COLOR_RED
]
MATPLOTLIB_COLORS_LEN = len(MATPLOTLIB_COLORS)


# --- Helper Functions ---
def friendly_time_format(dt_obj):
    """Formats datetime object nicely or returns string."""
    if isinstance(dt_obj, datetime):
        return dt_obj.strftime('%Y-%m-%d %H:%M:%S')
    return str(dt_obj) 

def safe_request_get(url, timeout=5):
    """Safely performs a GET request, returns Response or None."""
    try:
        headers = {'User-Agent': 'AI-LogGuard-AlertPage/1.0'}
        response = requests.get(url, timeout=timeout, headers=headers)
        response.raise_for_status() 
        return response
    except requests.exceptions.RequestException as e:
        print(f"Request error for {url}: {e}")
        return None

# --- Main Alerts Page Class ---
class AlertsPage(ctk.CTkFrame):
    """
    Modernized Alerts & Anomalies page focused on analysis.
    Includes thread-safe IP lookup and responsive Matplotlib charts.
    """

    def __init__(self, parent, controller):
        super().__init__(parent, fg_color="transparent")
        self.controller = controller
        self.user_info = controller.user_info 

        # --- State ---
        self.filtered_alerts: List[Dict[str, Any]] = []
        self.live_mode = ctk.BooleanVar(value=True) 
        self.last_refresh_id: Optional[str] = None 
        self.selected_alert_data: Optional[Dict[str, Any]] = None
        self.selected_alert_widget: Optional[ctk.CTkFrame] = None 
        self.is_active = True 

        # IP Reputation Worker State
        self.ip_queue = queue.Queue()
        self.ip_cache: Dict[str, Dict[str, Any]] = {}
        self.ip_worker_running = False
        
        # --- Chart References (Initialize to None) ---
        self.pie_fig = None
        self.ax_pie = None
        self.canvas_pie = None
        self.fig_timeline = None
        self.ax_timeline = None
        self.canvas_timeline = None
        
        # --- Matplotlib figures list for cleanup ---
        self.matplotlib_figures = []

        # References for investigation panel buttons/labels (Initialized for safety)
        self.inv_timestamp: Optional[ctk.CTkLabel] = None
        self.inv_ip: Optional[ctk.CTkLabel] = None
        self.inv_severity: Optional[ctk.CTkLabel] = None
        self.inv_desc: Optional[ctk.CTkTextbox] = None
        self.inv_ack_btn: Optional[ctk.CTkButton] = None
        self.inv_block_btn: Optional[ctk.CTkButton] = None
        self.inv_lookup_btn: Optional[ctk.CTkButton] = None
        
        # Stat Labels 
        self.label_total: Optional[ctk.CTkLabel] = None
        self.label_critical: Optional[ctk.CTkLabel] = None
        self.label_ip: Optional[ctk.CTkLabel] = None


        # --- UI Build ---
        self._build_ui()
        
        # --- CRITICAL FIX: Defer all loading until after UI construction is complete ---
        self.after(50, self._deferred_init_tasks) 
        
        self.bind("<Configure>", self._on_resize)


    def stop_threads(self):
        """Public method called by AiLogGuard to stop background tasks."""
        print("Attempting to stop AlertsPage background tasks...")
        self.is_active = False 
        self.live_mode.set(False) 

        # Cancel scheduled UI refresh
        if self.last_refresh_id:
            try: self.after_cancel(self.last_refresh_id); self.last_refresh_id = None
            except Exception: pass
            print(" - Live update loop cancelled.")

        # Signal IP worker thread to stop
        self.ip_worker_running = False
        try: self.ip_queue.put(None) 
        except Exception: pass
        
        # Close all matplotlib figures to prevent memory leaks
        for fig in self.matplotlib_figures:
            try:
                plt.close(fig)
            except Exception:
                pass
        self.matplotlib_figures.clear()
        
        print("AlertsPage background tasks stop signals sent.")

    # --- CRITICAL FIX: Deferred Initializer ---
    def _deferred_init_tasks(self):
        """Tasks that must run ONLY after all CTk/Matplotlib widgets are created."""
        try:
             self._start_ip_worker()
             self._load_alerts() 
        except Exception as e:
             print(f"Error during deferred init tasks: {e}")

    # =========================================================================
    # Responsiveness and Resize Handlers
    # =========================================================================
    def _on_resize(self, event):
        """
        Handles the resizing of the window to ensure Matplotlib charts update.
        """
        if event.widget is self:
            self.after_idle(lambda: self._update_stats_and_chart(self.filtered_alerts)) 
            
    
    # =========================================================================
    # UI Construction and Layout
    # =========================================================================
    def _build_ui(self):
        """Builds the main UI layout for the Alerts page."""
        container = ctk.CTkFrame(self, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=UI_SETTINGS["spacing"]["sm"], pady=UI_SETTINGS["spacing"]["sm"]) 
        
        container.grid_columnconfigure(0, weight=2) 
        container.grid_columnconfigure(1, weight=1) 
        
        container.grid_rowconfigure(3, weight=4) 

        self._build_header(container).grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, UI_SETTINGS["spacing"]["xs"])) 
        self._build_filter_bar(container).grid(row=1, column=0, columnspan=2, sticky="ew", pady=(0, UI_SETTINGS["spacing"]["xs"])) 
        self._build_stats_chart_ips(container).grid(row=2, column=0, columnspan=2, sticky="ew", pady=(0, UI_SETTINGS["spacing"]["xs"])) 
        
        self._build_alert_table(container).grid(row=3, column=0, sticky="nsew", pady=(0, UI_SETTINGS["spacing"]["xs"]), padx=(0, UI_SETTINGS["spacing"]["xs"])) 
        self._build_investigation_panel(container).grid(row=3, column=1, sticky="nsew", pady=(0, UI_SETTINGS["spacing"]["xs"])) 


    def _build_header(self, parent) -> ctk.CTkFrame:
        """Builds the top header bar with title and controls."""
        header = ModernComponents.create_card(parent)
        header.configure(fg_color=COLOR_ELEVATION_3, height=50) 
        header.pack_propagate(False) 

        ctk.CTkLabel(header, text="🚨 Alerts Analysis Dashboard", font=FONT_HEADING, text_color=COLOR_PRIMARY).pack(
            side="left", padx=UI_SETTINGS["spacing"]["md"], pady=UI_SETTINGS["spacing"]["xs"]
        )
        control_bar = ctk.CTkFrame(header, fg_color="transparent")
        control_bar.pack(side="right", padx=UI_SETTINGS["spacing"]["xs"], pady=UI_SETTINGS["spacing"]["xs"])

        live_switch = ctk.CTkSwitch(
            control_bar, text="Live Update", variable=self.live_mode, command=self._toggle_live,
            font=FONT_BODY_SMALL, progress_color=COLOR_PRIMARY, width=20
        )
        live_switch.pack(side="left", padx=UI_SETTINGS["spacing"]["xs"])

        refresh_btn = ctk.CTkButton(
            control_bar, text="⟳ Refresh", width=70, height=26, font=FONT_BODY_SMALL,
             fg_color=COLOR_ELEVATION_2, hover_color=COLOR_ELEVATION_4, command=self._load_alerts
        )
        refresh_btn.pack(side="left", padx=UI_SETTINGS["spacing"]["xs"])

        export_btn = ctk.CTkButton(
            control_bar, text="⬇ Export CSV", width=100, height=26, font=FONT_BODY_SMALL,
            fg_color=COLOR_ELEVATION_2, hover_color=COLOR_ELEVATION_4, command=self._export_csv
        )
        export_btn.pack(side="left", padx=UI_SETTINGS["spacing"]["xs"])

        return header

    def _build_filter_bar(self, parent) -> ctk.CTkFrame:
        """Builds the filter bar below the header."""
        filter_frame = ModernComponents.create_card(parent)
        filter_frame.configure(fg_color=COLOR_ELEVATION_1) 

        ctk.CTkLabel(filter_frame, text="Filter:", font=FONT_BODY_SMALL, text_color=COLOR_TEXT_SECONDARY).pack(
            side="left", padx=(UI_SETTINGS["spacing"]["md"], UI_SETTINGS["spacing"]["xs"])
        )
        self.date_var = ctk.StringVar(value="All Time")
        date_menu = ctk.CTkOptionMenu(
            filter_frame, variable=self.date_var, values=["All Time", "Last Hour", "Last 24 Hours"],
            font=FONT_BODY_SMALL, dropdown_font=FONT_BODY_SMALL, width=120, height=28,
            fg_color=COLOR_ELEVATION_2, button_color=COLOR_ACCENT, button_hover_color=COLOR_PRIMARY_VARIANT,
            command=lambda *_: self._load_alerts() 
        )
        date_menu.pack(side="left", padx=UI_SETTINGS["spacing"]["xs"], pady=UI_SETTINGS["spacing"]["xs"])

        self.sev_var = ctk.StringVar(value="All Severities")
        sev_menu = ctk.CTkOptionMenu(
            filter_frame, variable=self.sev_var, values=["All Severities"] + SEV_ORDER, 
            font=FONT_BODY_SMALL, dropdown_font=FONT_BODY_SMALL, width=140, height=28,
            fg_color=COLOR_ELEVATION_2, button_color=COLOR_ACCENT, button_hover_color=COLOR_PRIMARY_VARIANT,
            command=lambda *_: self._load_alerts()
        )
        sev_menu.pack(side="left", padx=UI_SETTINGS["spacing"]["xs"])

        self.search_var = ctk.StringVar()
        search_entry = ctk.CTkEntry(
            filter_frame, textvariable=self.search_var, placeholder_text="Search description or IP...",
            font=FONT_BODY_SMALL, height=28, fg_color=COLOR_ELEVATION_2, border_color=COLOR_ELEVATION_3
        )
        search_entry.bind("<KeyRelease>", self._load_alerts)
        search_entry.pack(side="left", fill="x", expand=True, padx=(UI_SETTINGS["spacing"]["xs"], UI_SETTINGS["spacing"]["xs"]), pady=UI_SETTINGS["spacing"]["xs"])

        reset_btn = ctk.CTkButton(
            filter_frame, text="Reset", width=70, height=28, font=FONT_BODY_SMALL,
            fg_color=COLOR_PRIMARY, hover_color=COLOR_PRIMARY_VARIANT, command=self._reset_filters 
        )
        reset_btn.pack(side="right", padx=(UI_SETTINGS["spacing"]["xs"], UI_SETTINGS["spacing"]["md"]), pady=UI_SETTINGS["spacing"]["xs"])

        return filter_frame

    def _build_stats_chart_ips(self, parent) -> ctk.CTkFrame:
        """Builds the row containing Stats Cards, Pie Chart, and Alert Timeline Chart."""
        top_row = ctk.CTkFrame(parent, fg_color="transparent")
        top_row.grid_columnconfigure((0, 1, 2), weight=1)
        top_row.grid_rowconfigure(0, weight=1) 

        # --- Stats Cards ---
        stats_card_frame = ModernComponents.create_card(top_row)
        stats_card_frame.grid(row=0, column=0, sticky="nsew", padx=(0, UI_SETTINGS["spacing"]["xs"]))
        stats_card_frame.grid_columnconfigure(0, weight=1) 
        ctk.CTkLabel(stats_card_frame, text="Summary (Filtered)", font=FONT_BODY_MEDIUM, text_color=COLOR_TEXT_SECONDARY).grid(
            row=0, column=0, sticky="w", padx=10, pady=(5,0)) 

        # Create stat cards and store LABEL references for updates
        frame_total, self.label_total = ModernComponents.create_stat_card(stats_card_frame, "Displayed", "0") 
        frame_total.grid(row=1, column=0, sticky="ew", padx=10, pady=(2, 2))

        frame_critical, self.label_critical = ModernComponents.create_stat_card(stats_card_frame, "Critical/High/Error", "0") 
        frame_critical.grid(row=2, column=0, sticky="ew", padx=10, pady=(0, 5))

        frame_ip, self.label_ip = ModernComponents.create_stat_card(stats_card_frame, "Top Source IP", "N/A") 
        frame_ip.grid(row=3, column=0, sticky="ew", padx=10, pady=(0, 5))


        # --- Pie Chart (Severity Breakdown) ---
        chart_card_pie = ModernComponents.create_card(top_row)
        chart_card_pie.grid(row=0, column=1, sticky="nsew", padx=UI_SETTINGS["spacing"]["xs"])
        ctk.CTkLabel(chart_card_pie, text="Severity Breakdown", font=FONT_BODY_MEDIUM, text_color=COLOR_TEXT_SECONDARY).pack(
            anchor="nw", padx=10, pady=(5, 0)) 

        plt.style.use('dark_background')
        CHART_BG = globals().get('COLOR_ELEVATION_1', '#2d3436') 
        
        # Initialize pie chart figure and axis
        self.pie_fig, self.ax_pie = plt.subplots(figsize=(1, 1), facecolor=COLOR_CARD)
        self.matplotlib_figures.append(self.pie_fig)  # Register for cleanup
        # CRITICAL UI FIX: Adjust subplot layout to make room for the external legend
        self.pie_fig.subplots_adjust(left=0.01, right=0.6, top=0.99, bottom=0.01) 
        self.ax_pie.set_facecolor(CHART_BG) 
        
        self.canvas_pie = FigureCanvasTkAgg(self.pie_fig, master=chart_card_pie)
        canvas_widget_pie = self.canvas_pie.get_tk_widget()
        canvas_widget_pie.configure(bg=COLOR_CARD) 
        canvas_widget_pie.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        
        # Placeholder frame for the custom CTk legend
        self.pie_legend_frame = ctk.CTkFrame(chart_card_pie, fg_color="transparent")
        self.pie_legend_frame.pack(side="right", padx=5, pady=10, fill="y")


        # --- Alert Timeline Chart (NEW) ---
        chart_card_timeline = ModernComponents.create_card(top_row)
        chart_card_timeline.grid(row=0, column=2, sticky="nsew", padx=(UI_SETTINGS["spacing"]["xs"], 0))
        ctk.CTkLabel(chart_card_timeline, text="Alert Timeline (Count/Period)", font=FONT_BODY_MEDIUM, text_color=COLOR_TEXT_SECONDARY).pack(
            anchor="nw", padx=10, pady=(5, 0)) 

        plt.style.use('dark_background')
        # Initialize timeline figure and axis
        self.fig_timeline, self.ax_timeline = plt.subplots(figsize=(1, 1), facecolor=COLOR_CARD)
        self.matplotlib_figures.append(self.fig_timeline)  # Register for cleanup
        self.ax_timeline.set_facecolor(CHART_BG) 
        self.fig_timeline.tight_layout(pad=1.0)
        
        self.canvas_timeline = FigureCanvasTkAgg(self.fig_timeline, master=chart_card_timeline)
        canvas_widget_timeline = self.canvas_timeline.get_tk_widget()
        canvas_widget_timeline.configure(bg=COLOR_CARD) 
        canvas_widget_timeline.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Initialize Axes for Timeline
        self.ax_timeline.tick_params(axis='x', colors=COLOR_TEXT_SECONDARY, labelsize=8)
        self.ax_timeline.tick_params(axis='y', colors=COLOR_TEXT_SECONDARY, labelsize=8)
        self.ax_timeline.spines['top'].set_visible(False); self.ax_timeline.spines['right'].set_visible(False)
        self.ax_timeline.grid(True, axis='y', linestyle=':', linewidth=0.5, color=COLOR_DIVIDER, alpha=0.5)


        return top_row

    def _build_alert_table(self, parent) -> ctk.CTkFrame:
        """Builds the main scrollable list for displaying alerts."""
        table_container = ModernComponents.create_card(parent)
        ctk.CTkLabel(table_container, text="Filtered Alert Feed", font=FONT_BODY_MEDIUM, text_color=COLOR_TEXT_SECONDARY).pack(
            anchor="w", padx=10, pady=(5, 2)) 
        
        # Scrollable frame using themed colors
        self.table_frame = ctk.CTkScrollableFrame(
            table_container, fg_color=COLOR_BG, corner_radius=UI_SETTINGS["corner_radius"]-2,
            border_color=COLOR_ELEVATION_3, border_width=1
        )
        self.table_frame.pack(fill="both", expand=True, padx=10, pady=(0, 5)) 
        return table_container

    def _build_investigation_panel(self, parent) -> ctk.CTkFrame:
        """
        Builds the bottom panel for showing selected alert details and actions.
        """
        panel = ModernComponents.create_card(parent)
        panel.grid_columnconfigure(0, weight=1)
        panel.grid_rowconfigure(2, weight=1) 
        
        ctk.CTkLabel(panel, text="Investigation Panel", font=FONT_HEADING, text_color=COLOR_TEXT).grid(
            row=0, column=0, sticky="w", padx=15, pady=(15, 5)) 

        # Top row for key alert info (Timestamp, IP, Severity)
        info_frame = ctk.CTkFrame(panel, fg_color="transparent")
        info_frame.grid(row=1, column=0, sticky="ew", padx=15, pady=0) 
        info_frame.grid_columnconfigure((0,1,2), weight=1)

        def create_inv_stat(parent, title, initial_value, text_color=COLOR_TEXT_SECONDARY):
            card = ctk.CTkFrame(parent, fg_color=COLOR_ELEVATION_1, corner_radius=UI_SETTINGS["corner_radius"]-2, height=45)
            card.pack_propagate(False)
            ctk.CTkLabel(card, text=title.upper(), font=FONT_CAPTION, text_color=COLOR_TEXT_SECONDARY).pack(pady=(4, 0))
            value_label = ctk.CTkLabel(card, text=initial_value, font=FONT_BODY_MEDIUM, text_color=text_color)
            value_label.pack()
            return card, value_label

        # Key Stat Cards 
        card_ts, self.inv_timestamp = create_inv_stat(info_frame, "Time", "-")
        card_ip, self.inv_ip = create_inv_stat(info_frame, "Source IP", "-")
        card_sev, self.inv_severity = create_inv_stat(info_frame, "Severity", "-", text_color=COLOR_ACCENT)

        card_ts.grid(row=0, column=0, sticky="ew", padx=(0, UI_SETTINGS["spacing"]["xs"]))
        card_ip.grid(row=0, column=1, sticky="ew", padx=UI_SETTINGS["spacing"]["xs"])
        card_sev.grid(row=0, column=2, sticky="ew", padx=(UI_SETTINGS["spacing"]["xs"], 0))

        # Textbox for full alert description
        self.inv_desc = ctk.CTkTextbox(
            panel, height=60, wrap="word", activate_scrollbars=True,
            font=FONT_BODY, fg_color=COLOR_BG, text_color=COLOR_TEXT, 
            border_color=COLOR_DIVIDER, border_width=1
        )
        self.inv_desc.grid(row=2, column=0, sticky="nsew", padx=15, pady=(10, 10))
        self.inv_desc.insert("1.0", "Select an alert from the list above to view its detailed description.")
        self.inv_desc.configure(state="disabled")

        # Action Buttons row at the bottom
        action_frame = ctk.CTkFrame(panel, fg_color="transparent")
        action_frame.grid(row=3, column=0, sticky="ew", padx=15, pady=(0, 15))
        action_frame.grid_columnconfigure((0,1,2), weight=1) 

        # Buttons use proper height/font
        self.inv_ack_btn = ctk.CTkButton(
            action_frame, text="Acknowledge", height=UI_SETTINGS["button_height"], 
            font=FONT_BODY_MEDIUM, fg_color=COLOR_ELEVATION_3, hover_color=COLOR_ELEVATION_4,
            command=self._acknowledge_alert
        )
        self.inv_ack_btn.grid(row=0, column=0, sticky="ew", padx=(0,UI_SETTINGS["spacing"]["xs"]))

        self.inv_lookup_btn = ctk.CTkButton(
            action_frame, text="Lookup IP", height=UI_SETTINGS["button_height"], 
            font=FONT_BODY_MEDIUM, fg_color=COLOR_ACCENT, hover_color=COLOR_PRIMARY_VARIANT,
            command=lambda: self._show_ip_reputation(self.selected_alert_data.get('ip') if self.selected_alert_data else None)
        )
        self.inv_lookup_btn.grid(row=0, column=1, sticky="ew", padx=UI_SETTINGS["spacing"]["xs"])

        # Dynamic Block/Unblock Button
        self.inv_block_btn = ctk.CTkButton(
            action_frame, text="Block IP", height=UI_SETTINGS["button_height"], 
            font=FONT_BODY_MEDIUM, fg_color=COLOR_RED, hover_color=COLOR_ORANGE,
            command=self._block_ip_action
        )
        self.inv_block_btn.grid(row=0, column=2, sticky="ew", padx=(UI_SETTINGS["spacing"]["xs"],0))

        return panel
    
    def _build_investigation_panel(self, parent) -> ctk.CTkFrame:
        """
        Builds the bottom panel for showing selected alert details and actions.
        """
        panel = ModernComponents.create_card(parent)
        panel.grid_columnconfigure(0, weight=1)
        panel.grid_rowconfigure(2, weight=1) 
        
        ctk.CTkLabel(panel, text="Investigation Panel", font=FONT_HEADING, text_color=COLOR_TEXT).grid(
            row=0, column=0, sticky="w", padx=15, pady=(15, 5)) 

        # Top row for key alert info (Timestamp, IP, Severity)
        info_frame = ctk.CTkFrame(panel, fg_color="transparent")
        info_frame.grid(row=1, column=0, sticky="ew", padx=15, pady=0) 
        info_frame.grid_columnconfigure((0,1,2), weight=1)

        def create_inv_stat(parent, title, initial_value, text_color=COLOR_TEXT_SECONDARY):
            card = ctk.CTkFrame(parent, fg_color=COLOR_ELEVATION_1, corner_radius=UI_SETTINGS["corner_radius"]-2, height=45)
            card.pack_propagate(False)
            ctk.CTkLabel(card, text=title.upper(), font=FONT_CAPTION, text_color=COLOR_TEXT_SECONDARY).pack(pady=(4, 0))
            value_label = ctk.CTkLabel(card, text=initial_value, font=FONT_BODY_MEDIUM, text_color=text_color)
            value_label.pack()
            return card, value_label

        # Key Stat Cards 
        card_ts, self.inv_timestamp = create_inv_stat(info_frame, "Time", "-")
        card_ip, self.inv_ip = create_inv_stat(info_frame, "Source IP", "-")
        card_sev, self.inv_severity = create_inv_stat(info_frame, "Severity", "-", text_color=COLOR_ACCENT)

        card_ts.grid(row=0, column=0, sticky="ew", padx=(0, UI_SETTINGS["spacing"]["xs"]))
        card_ip.grid(row=0, column=1, sticky="ew", padx=UI_SETTINGS["spacing"]["xs"])
        card_sev.grid(row=0, column=2, sticky="ew", padx=(UI_SETTINGS["spacing"]["xs"], 0))

        # Textbox for full alert description
        self.inv_desc = ctk.CTkTextbox(
            panel, height=60, wrap="word", activate_scrollbars=True,
            font=FONT_BODY, fg_color=COLOR_BG, text_color=COLOR_TEXT, 
            border_color=COLOR_DIVIDER, border_width=1
        )
        self.inv_desc.grid(row=2, column=0, sticky="nsew", padx=15, pady=(10, 10))
        self.inv_desc.insert("1.0", "Select an alert from the list above to view its detailed description.")
        self.inv_desc.configure(state="disabled")

        # Action Buttons row at the bottom
        action_frame = ctk.CTkFrame(panel, fg_color="transparent")
        action_frame.grid(row=3, column=0, sticky="ew", padx=15, pady=(0, 15))
        action_frame.grid_columnconfigure((0,1,2,3), weight=1) # Updated to 4 columns

        # Buttons use proper height/font
        self.inv_ack_btn = ctk.CTkButton(
            action_frame, text="Acknowledge", height=UI_SETTINGS["button_height"], 
            font=FONT_BODY_MEDIUM, fg_color=COLOR_ELEVATION_3, hover_color=COLOR_ELEVATION_4,
            command=self._acknowledge_alert
        )
        self.inv_ack_btn.grid(row=0, column=0, sticky="ew", padx=(0,UI_SETTINGS["spacing"]["xs"]))

        self.inv_lookup_btn = ctk.CTkButton(
            action_frame, text="Lookup IP", height=UI_SETTINGS["button_height"], 
            font=FONT_BODY_MEDIUM, fg_color=COLOR_ACCENT, hover_color=COLOR_PRIMARY_VARIANT,
            command=lambda: self._show_ip_reputation(self.selected_alert_data.get('ip') if self.selected_alert_data else None)
        )
        self.inv_lookup_btn.grid(row=0, column=1, sticky="ew", padx=UI_SETTINGS["spacing"]["xs"])

        # NEW: Analyze in Forensics Button
        self.inv_analyze_btn = ctk.CTkButton(
            action_frame, text="Analyze (LLM)", height=UI_SETTINGS["button_height"],
            font=FONT_BODY_MEDIUM, fg_color=COLOR_INFO, hover_color=COLOR_PRIMARY,
            command=self._analyze_alert_in_forensics
        )
        self.inv_analyze_btn.grid(row=0, column=2, sticky="ew", padx=UI_SETTINGS["spacing"]["xs"])

        # Dynamic Block/Unblock Button
        self.inv_block_btn = ctk.CTkButton(
            action_frame, text="Block IP", height=UI_SETTINGS["button_height"], 
            font=FONT_BODY_MEDIUM, fg_color=COLOR_RED, hover_color=COLOR_ORANGE,
            command=self._block_ip_action
        )
        self.inv_block_btn.grid(row=0, column=3, sticky="ew", padx=(UI_SETTINGS["spacing"]["xs"],0)) # Moved to col 3

        return panel

    # =========================================================================
    # Data Loading and Filtering
    # =========================================================================
    def _safe_apply_filters_and_render(self):
        """
        Checks if the Matplotlib canvases exist before triggering the rendering chain.
        (CRITICAL FIX for Attribute Error)
        """
        if not hasattr(self, 'canvas_pie') or self.canvas_pie is None:
            if self.is_active:
                self.after(50, self._safe_apply_filters_and_render)
            return
            
        self._apply_filters()
        
    def _toggle_live(self):
        """Handles turning live refresh on or off for the Alerts page."""
        if not self.is_active: return 

        if self.live_mode.get():
            print("Alerts Page: Live update ENABLED.")
            if not self.last_refresh_id:
                 self._load_alerts()
        else:
            print("Alerts Page: Live update DISABLED.")
            if self.last_refresh_id:
                try:
                    self.after_cancel(self.last_refresh_id)
                    self.last_refresh_id = None
                except ValueError:
                    self.last_refresh_id = None


    def _load_alerts(self, _=None):
        """Loads alerts from controller and triggers UI update. Schedules next refresh if live."""
        if not self.is_active: return 

        if self.last_refresh_id:
            try: self.after_cancel(self.last_refresh_id)
            except ValueError: pass 
            self.last_refresh_id = None

        self.after(0, self._safe_apply_filters_and_render) 

        if self.live_mode.get() and self.is_active:
            self.last_refresh_id = self.after(5000, self._load_alerts)


    def _apply_filters(self):
        """Applies all active filters to the global alert list from controller."""
        query = self.search_var.get().lower().strip()
        sev_filter = self.sev_var.get()
        date_filter = self.date_var.get()

        alerts_snapshot = []
        try:
            if hasattr(self.controller, 'get_alert_queue') and callable(self.controller.get_alert_queue):
                 alerts_snapshot = list(self.controller.get_alert_queue())
            else:
                 print("Warning: Controller or get_alert_queue method not found.")
        except Exception:
             pass

        alerts = alerts_snapshot 
        now = datetime.now()
        cutoff = None
        if date_filter == "Last Hour": cutoff = now - timedelta(hours=1)
        elif date_filter == "Last 24 Hours": cutoff = now - timedelta(hours=24)

        if cutoff:
             alerts = [a for a in alerts if isinstance(a.get("timestamp"), datetime) and a["timestamp"] >= cutoff]

        if sev_filter != "All Severities":
             alerts = [a for a in alerts if a.get("severity", "").title() == sev_filter.title()]

        if query:
             alerts = [a for a in alerts if query in a.get("description", "").lower() or query in a.get("ip", "").lower()]

        # Sort newest first
        self.filtered_alerts = sorted(alerts, key=lambda x: x.get('timestamp', datetime.min), reverse=True)

        self._update_stats_and_chart(self.filtered_alerts)
        self._populate_alert_list(self.filtered_alerts)
        
        if self.selected_alert_data and self.selected_alert_data not in self.filtered_alerts:
             self._clear_investigation_panel()


    def _reset_filters(self):
        """Resets all filters to default and reloads alerts."""
        self.search_var.set("")
        self.sev_var.set("All Severities")
        self.date_var.set("All Time")
        self._load_alerts() 


    # =========================================================================
    # UI Update Methods
    # =========================================================================
    def _populate_alert_list(self, alerts: List[Dict]):
        """
        Clears and repopulates the visual alert list in the scrollable frame.
        """
        for widget in list(self.table_frame.winfo_children()): widget.destroy()

        if not alerts:
            ctk.CTkLabel(self.table_frame, text="No alerts match the current filters.", text_color=COLOR_TEXT_SECONDARY, font=FONT_BODY).pack(pady=20)
            return

        for alert in alerts:
            ts_str = friendly_time_format(alert.get("timestamp", ""))
            sev = alert.get("severity", "Info").title() 
            desc = alert.get("description", "")
            ip = alert.get("ip", "N/A")

            sev_color = SEV_COLOR.get(sev, COLOR_TEXT_SECONDARY)

            # Combine all info into a single formatted string for the button text
            display_text = f"[{ts_str}] [{sev.upper()}] {desc} (IP: {ip})"
            
            # Use CTkButton directly for the row element
            btn = ctk.CTkButton(
                 self.table_frame, 
                 text=display_text,
                 fg_color=COLOR_ELEVATION_1, 
                 text_color=COLOR_TEXT, 
                 hover_color=COLOR_ELEVATION_2, 
                 anchor="w", 
                 font=FONT_BODY_SMALL,
                 height=32, 
                 corner_radius=UI_SETTINGS["corner_radius"]-2,
                 border_width=2, 
                 border_color=sev_color 
            )
            
            # Store data on the button and set command
            btn.alert_data = alert 
            btn.configure(command=lambda a=alert, b=btn: self._show_alert_detail(a, b))
            btn.pack(fill="x", padx=5, pady=2)

    def _update_stats_and_chart(self, alerts: List[Dict]):
        """Updates the summary stat cards, pie chart, and alert timeline chart."""
        total = len(alerts)
        critical_high_error = len([a for a in alerts if a.get("severity", "").title() in ("Critical", "High", "Error")])

        ip_counts = Counter([
             a.get("ip") for a in alerts
             if a.get("ip") and a.get("ip") not in ["N/A", "Unknown", None]
        ])
        top_ip = ip_counts.most_common(1)[0][0] if ip_counts else "N/A"

        # Update Stat Labels
        if hasattr(self, 'label_total'): self.label_total.configure(text=str(total))
        if hasattr(self, 'label_critical'):
             self.label_critical.configure(text=str(critical_high_error))
             self.label_critical.configure(text_color=COLOR_RED if critical_high_error > 0 else COLOR_ACCENT)
        if hasattr(self, 'label_ip'): self.label_ip.configure(text=top_ip)

        # Update Pie Chart
        self._refresh_pie_chart(alerts)

        # Update Alert Timeline Chart
        self._refresh_alert_timeline(alerts)

    def _refresh_pie_chart(self, alerts: List[Dict]):
        """Renders the Severity Breakdown Pie Chart."""
        if not hasattr(self, 'ax_pie') or not hasattr(self, 'canvas_pie') or self.canvas_pie is None or not self.canvas_pie.get_tk_widget().winfo_exists(): return
        
        # --- UI Improvement: Clear Pie and Legend ---
        self.ax_pie.clear()
        for w in self.pie_legend_frame.winfo_children(): w.destroy()
        
        CHART_BG = globals().get('COLOR_ELEVATION_1', '#2d3436') 
        self.ax_pie.set_facecolor(CHART_BG) 
        
        counts = Counter(a.get("severity", "Other").title() for a in alerts)
        chart_labels, chart_sizes, chart_colors = [], [], []
        
        for sev in SEV_ORDER:
            count = counts.get(sev)
            if count and count > 0:
                 chart_labels.append(sev)
                 chart_sizes.append(count)
                 chart_colors.append(SEV_COLOR.get(sev, COLOR_TEXT_SECONDARY))

        other_count = counts.get("Other")
        if other_count and other_count > 0 and "Other" not in chart_labels:
             chart_labels.append("Other")
             chart_sizes.append(other_count)
             chart_colors.append(SEV_COLOR.get("Other", COLOR_TEXT_SECONDARY))

        if not chart_sizes:
            self.ax_pie.text(0.5, 0.5, "No Data", ha="center", va="center", color=COLOR_TEXT_SECONDARY, fontsize=10)
        else:
             wedges, texts, autotexts = self.ax_pie.pie(
                 chart_sizes, labels=[''] * len(chart_labels), # Hide labels on the pie itself
                 autopct=lambda p: (f"{p:.0f}%") if p > 3 else "", 
                 colors=chart_colors, textprops={'color': COLOR_TEXT, 'fontsize': 9},
                 startangle=90, pctdistance=0.85, labeldistance=1.1,
                 wedgeprops={'linewidth': 1, 'edgecolor': COLOR_CARD}
             )
             self.ax_pie.add_artist(plt.Circle((0, 0), 0.60, fc=COLOR_CARD))
             
             # --- UI Improvement: Build Custom CTk Legend on the Right ---
             total_sum = sum(chart_sizes)
             for i, label in enumerate(chart_labels):
                 percentage = (chart_sizes[i] / total_sum) * 100
                 color_hex = chart_colors[i]
                 
                 # Small colored square/label
                 color_indicator = ctk.CTkFrame(self.pie_legend_frame, width=10, height=10, fg_color=color_hex, corner_radius=2)
                 color_indicator.pack(side="top", anchor="w", pady=(2, 0), padx=(5, 0))

                 # Label with text and percentage
                 label_text = f"{label} ({chart_sizes[i]})"
                 label_percent = f"{percentage:.1f}%"
                 
                 ctk.CTkLabel(self.pie_legend_frame, text=label_text, font=FONT_BODY_SMALL, text_color=COLOR_TEXT).pack(side="top", anchor="w", padx=(18, 5), pady=(0, 0))
                 ctk.CTkLabel(self.pie_legend_frame, text=label_percent, font=FONT_CAPTION, text_color=COLOR_TEXT_SECONDARY).pack(side="top", anchor="w", padx=(18, 5), pady=(0, 5))
                 
             # Recalculate layout to account for the legend space we reserved
             self.pie_fig.canvas.draw()
             self.pie_fig.canvas.flush_events()


        # Keep circular pie without triggering fixed-limit aspect warnings.
        self.ax_pie.set_aspect('equal', adjustable='box')
        try: self.canvas_pie.draw_idle()
        except Exception: pass
        
        
    def _analyze_alert_in_forensics(self):
        """Navigates to the AI Forensic page and pre-fills it with this alert's data."""
        if not self.selected_alert_data:
            messagebox.showwarning("No Selection", "Please select an alert to analyze.", parent=self)
            return
            
        # Construct a log snippet from the alert
        alert = self.selected_alert_data
        log_snippet = f"[{friendly_time_format(alert.get('timestamp'))}] [{alert.get('severity')}] IP:{alert.get('ip')} - {alert.get('description')}"
        
        # Call the controller to switch page and pass data
        if hasattr(self.controller, 'analyze_log_in_forensics'):
            self.controller.analyze_log_in_forensics(log_snippet)
        else:
            messagebox.showerror("Error", "Controller does not support direct forensic analysis navigation.", parent=self)

    def _refresh_alert_timeline(self, alerts: List[Dict]):
        """
        Renders a bar chart showing the frequency of alerts over the filtered time period.
        """
        if not hasattr(self, 'ax_timeline') or not hasattr(self, 'canvas_timeline') or self.canvas_timeline is None or not self.canvas_timeline.get_tk_widget().winfo_exists():
            return
        
        self.ax_timeline.clear()
        
        CHART_BG = globals().get('COLOR_ELEVATION_1', '#2d3436') 
        self.ax_timeline.set_facecolor(CHART_BG)
        
        # Only use timestamps that are confirmed datetime objects
        timestamps = [a['timestamp'] for a in alerts if isinstance(a.get('timestamp'), datetime)]
        
        if not timestamps:
            self.ax_timeline.text(0.5, 0.5, "No Timeline Data", ha="center", va="center", color=COLOR_TEXT_SECONDARY, fontsize=10, transform=self.ax_timeline.transAxes)
            self.canvas_timeline.draw_idle()
            return

        min_time = min(timestamps)
        max_time = max(timestamps)
        time_diff = max_time - min_time

        # Dynamic Binning based on time difference
        if time_diff < timedelta(hours=1):
            bin_size = timedelta(seconds=10)
            date_format = mdates.DateFormatter('%H:%M:%S')
            title_suffix = " (10 Sec Intervals)"
        elif time_diff < timedelta(days=2):
            bin_size = timedelta(hours=1)
            date_format = mdates.DateFormatter('%H:%M')
            title_suffix = " (Hourly Intervals)"
        else:
            bin_size = timedelta(days=1)
            date_format = mdates.DateFormatter('%m-%d')
            title_suffix = " (Daily Intervals)"
            
        # Create bins
        bins = []
        current_bin = min_time.replace(second=0, microsecond=0) - bin_size
        while current_bin <= max_time + bin_size:
            bins.append(current_bin)
            current_bin += bin_size
            
        # Plot histogram
        n, bins, patches = self.ax_timeline.hist(timestamps, bins=mdates.date2num(bins), color=COLOR_ACCENT, alpha=0.7, rwidth=0.85)

        # Styling
        self.ax_timeline.set_title("Alert Timeline" + title_suffix, color=COLOR_TEXT, fontsize=10)
        self.ax_timeline.xaxis.set_major_formatter(date_format)
        
        self.ax_timeline.tick_params(axis='x', colors=COLOR_TEXT_SECONDARY, labelsize=8)
        self.ax_timeline.tick_params(axis='y', colors=COLOR_TEXT_SECONDARY, labelsize=8)
        
        # Avoid singular transformation: ensure xlim has a range
        bin_min = mdates.date2num(min(bins))
        bin_max = mdates.date2num(max(bins))
        if bin_min == bin_max:
            # Expand by a small margin if min == max
            bin_min -= 0.5
            bin_max += 0.5
        self.ax_timeline.set_xlim(bin_min, bin_max)
        self.ax_timeline.set_ylim(0, max(1, max(n) * 1.15))
        
        self.ax_timeline.figure.autofmt_xdate(rotation=45) 
        self.ax_timeline.grid(True, axis='y', linestyle=':', linewidth=0.5, color=COLOR_DIVIDER, alpha=0.5)

        self.canvas_timeline.draw_idle()

    # --- Investigation Panel Logic (Unchanged) ---
    def _show_alert_detail(self, alert: Dict[str, Any], button_widget: Optional[ctk.CTkFrame]):
        """Updates the investigation panel with details of the selected alert."""
        
        # Reset previous selection highlighting
        if self.selected_alert_widget and self.selected_alert_widget.winfo_exists():
             try: self.selected_alert_widget.configure(fg_color=COLOR_ELEVATION_1, border_color=SEV_COLOR.get(self.selected_alert_data.get('severity', 'Info').title(), COLOR_TEXT_SECONDARY))
             except Exception: pass 

        if button_widget and button_widget.winfo_exists():
            try:
                # Apply highlight to the new selection 
                button_widget.configure(fg_color=COLOR_ELEVATION_3, border_color=COLOR_PRIMARY) 
                self.selected_alert_widget = button_widget
            except Exception: pass

        # Data assignment
        self.selected_alert_data = alert 
        
        ts = alert.get("timestamp", "")
        sev = alert.get("severity", "N/A").title()
        ip = alert.get('ip', 'N/A')

        # Update Info Cards
        self.inv_timestamp.configure(text=friendly_time_format(ts))
        self.inv_ip.configure(text=ip)
        self.inv_severity.configure(text=sev, text_color=SEV_COLOR.get(sev, COLOR_TEXT))

        # Populate description box
        self.inv_desc.configure(state="normal") 
        self.inv_desc.delete("1.0", "end")
        self.inv_desc.insert("1.0", alert.get("description", "No description available."))
        self.inv_desc.configure(state="disabled") 

        # Update action buttons (Block/Unblock state)
        self._update_investigation_panel_actions(ip)

        # Queue IP lookup if data is old/missing
        if ip and ip != "N/A" and ip != "Unknown":
             cached_data = self.ip_cache.get(ip)
             if not cached_data or (time.time() - cached_data.get("checked_at", 0) > IP_CACHE_TTL):
                 self.ip_queue.put(ip)

    def _update_investigation_panel_actions(self, ip: Optional[str]):
        """Dynamically updates the block/unblock button state based on the current blocklist."""
        if not ip or ip in ["N/A", "Unknown", None] or not hasattr(self.controller, 'get_active_blocklist'):
             self.inv_block_btn.configure(text="No IP to Block", state="disabled", fg_color=COLOR_ELEVATION_3, hover_color=COLOR_ELEVATION_3)
             return

        is_blocked = ip in self.controller.get_active_blocklist()

        if is_blocked:
            self.inv_block_btn.configure(
                text="UNBLOCK IP",
                fg_color=COLOR_SUCCESS,
                hover_color=COLOR_GREEN,
                state="normal",
                command=lambda: self._block_ip_action(unblock=True)
            )
        else:
            self.inv_block_btn.configure(
                text="BLOCK IP",
                fg_color=COLOR_RED,
                hover_color=COLOR_ORANGE,
                state="normal",
                command=lambda: self._block_ip_action(unblock=False)
            )
    
    def _block_ip_action(self, unblock: bool = False):
        """Delegates the block/unblock action to the controller."""
        if not self.selected_alert_data:
             messagebox.showwarning("No Selection", "Please select an alert first.", parent=self)
             return

        ip = self.selected_alert_data.get("ip")
        if not ip or ip in ["N/A", "Unknown", None]:
             messagebox.showwarning("Block IP", "No valid IP address found for this alert.", parent=self)
             return
             
        action_verb = "UNBLOCK" if unblock else "BLOCK"
        
        if messagebox.askyesno(f"Confirm {action_verb}", f"{action_verb} IP: {ip}?", icon='warning', parent=self):
            
            success = self.controller.remove_from_blocklist(ip) if unblock else self.controller.add_to_blocklist(ip)
            
            if success:
                messagebox.showinfo(f"IP {action_verb}ED", f"IP {ip} has been {action_verb}ED successfully.", parent=self)
            else:
                 messagebox.showwarning("Status Update", f"IP {ip} was already {'unblocked' if unblock else 'blocked'}.", parent=self)
                 
            self._update_investigation_panel_actions(ip)
            DB.log_action(f"IP_{action_verb}ED", user_id=self.user_info.get('id'), details=f"{action_verb}ED IP: {ip}.")


    def _clear_investigation_panel(self):
        """Resets the investigation panel to its default empty state."""
        self.inv_timestamp.configure(text="-") 
        self.inv_ip.configure(text="-")
        self.inv_severity.configure(text="-", text_color=COLOR_TEXT)

        self.inv_desc.configure(state="normal")
        self.inv_desc.delete("1.0", "end")
        self.inv_desc.insert("1.0", "Select an alert from the list above to view details.")
        self.inv_desc.configure(state="disabled")

        if self.selected_alert_widget and self.selected_alert_widget.winfo_exists():
             try: self.selected_alert_widget.configure(fg_color=COLOR_ELEVATION_1)
             except Exception: pass

        self.selected_alert_data = None
        self.selected_alert_widget = None
        self._update_investigation_panel_actions(None) 


    # --- Actions ---
    def _acknowledge_alert(self):
        """(Simulated) Acknowledges the selected alert, removing it from view and queue."""
        if not self.selected_alert_data:
             messagebox.showwarning("No Selection", "Please select an alert to acknowledge.", parent=self)
             return

        alert_to_remove = self.selected_alert_data
        alert_desc = alert_to_remove.get('description', 'N/A')
        
        # --- CRITICAL DEQUE REMOVAL ---
        try:
             current_queue = getattr(self.controller, 'global_alert_queue', None)
             if current_queue:
                 temp_list = list(current_queue)
                 # Match based on description and timestamp
                 found_index = -1
                 for i, item in enumerate(temp_list):
                     if (item.get('description') == alert_to_remove.get('description') and
                         isinstance(item.get('timestamp'), datetime) and 
                         isinstance(alert_to_remove.get('timestamp'), datetime) and 
                         abs(item.get('timestamp') - alert_to_remove.get('timestamp')) < timedelta(seconds=1)):
                          found_index = i
                          break
                 
                 if found_index != -1:
                      del temp_list[found_index]
                      # Re-assign the queue (must be done this way for shared state)
                      self.controller.global_alert_queue = deque(temp_list, maxlen=current_queue.maxlen)
                 else:
                      print("Alert not found in global queue (already removed or modified?).")

        except Exception as e_queue:
             print(f"Error modifying global_alert_queue: {e_queue}")

        # Update local filtered lists and UI
        self.filtered_alerts = [a for a in self.filtered_alerts if a != alert_to_remove]
        self._update_stats_and_chart(self.filtered_alerts)
        self._populate_alert_list(self.filtered_alerts)
        self._clear_investigation_panel()

        DB.log_action("ALERT_ACKNOWLEDGED", user_id=self.user_info.get('id'), details=f"Acknowledged: {alert_desc[:100]}...")


    # --- Export ---
    def _export_csv(self):
        """Exports the *currently filtered* alerts to a CSV file."""
        if not self.filtered_alerts:
             messagebox.showinfo("Export Empty", "No alerts displayed to export.", parent=self)
             return

        default_filename = f"filtered_alerts_{datetime.now():%Y%m%d_%H%M%S}.csv"
        path = filedialog.asksaveasfilename(initialfile=default_filename, defaultextension=".csv", filetypes=[("CSV Files", "*.csv")])
        if not path: return 

        try:
             alerts_to_export = self.filtered_alerts
             with open(path, "w", newline="", encoding="utf-8") as f:
                 writer = csv.writer(f)
                 headers = ["Timestamp", "Severity", "IP Address", "Description"] 
                 writer.writerow(headers)
                 for a in alerts_to_export:
                      writer.writerow([
                           friendly_time_format(a.get("timestamp", "")), 
                           a.get("severity", "N/A").title(), 
                           a.get("ip", "N/A"),
                           a.get("description", "")
                      ])
             messagebox.showinfo("Export Successful", f"Exported {len(alerts_to_export)} filtered alerts to:\n{os.path.basename(path)}", parent=self)
             DB.log_action("ALERTS_EXPORT_CSV", user_id=self.user_info.get('id'), details=f"Exported {len(alerts_to_export)} filtered alerts.")
        except Exception as e:
             messagebox.showerror("Export Error", f"Failed to export alerts: {e}", parent=self)


    # --- IP Reputation Worker and Display ---
    def _start_ip_worker(self):
        """Starts the IP reputation lookup thread if not already running."""
        if self.ip_worker_running: return
        self.ip_worker_running = True
        threading.Thread(target=self._ip_worker_loop, daemon=True, name="AlertsIPWorker").start()
        print("Alerts Page IP Reputation worker started.")

    def _ip_worker_loop(self):
        """Background thread for IP lookups."""
        while self.ip_worker_running:
            ip_to_check = None
            try:
                ip_to_check = self.ip_queue.get(block=True, timeout=1.0)
                if ip_to_check is None: break

                cached = self.ip_cache.get(ip_to_check, {})
                # Check cache expiry
                if cached and (time.time() - cached.get("checked_at", 0) < IP_CACHE_TTL):
                     time.sleep(0.5)
                     continue 

                info = {"checked_at": time.time()}
                try:
                    response = safe_request_get(IP_API_URL.format(ip=ip_to_check), timeout=5)
                    if response:
                        payload = response.json()
                        if payload.get("status") == "success": 
                            info.update({k: payload.get(k) for k in ("country", "regionName", "city", "isp", "org", "proxy", "mobile") if payload.get(k) is not None})
                        else: info["error"] = f"API Error: {payload.get('message', 'Unknown')}"
                    else: info["error"] = "Request Failed"
                except Exception as req_e: info["error"] = f"Request Exception: {req_e}"

                self.ip_cache[ip_to_check] = info
                
                # Safely signal main thread that cache has been updated
                if self.is_active and self.winfo_exists():
                    self.after(0, self._check_active_ip_after_lookup, ip_to_check)
                
                time.sleep(1.5) 

            except queue.Empty:
                if not self.is_active: break
                continue
            except Exception as e:
                print(f"Alerts IP worker error: {e}")
                if ip_to_check: self.ip_cache[ip_to_check] = {"checked_at": time.time(), "error": f"Worker Exception: {e}"}
                time.sleep(5)
        print("Alerts Page IP Reputation worker finished.")


    def _check_active_ip_after_lookup(self, updated_ip: str):
        """
        Called safely on the main thread after an IP lookup completes.
        Refreshes the IP display if the currently selected alert's IP matches.
        """
        if not self.winfo_exists() or not self.selected_alert_data:
            return
        
        selected_ip = self.selected_alert_data.get('ip')
        if selected_ip == updated_ip:
             # Re-run detail show to update the block/unblock button state based on new lookup data
            self._update_investigation_panel_actions(updated_ip)


    def _show_ip_reputation(self, ip: Optional[str], display_immediately=True):
        """Displays IP reputation info from cache or queues lookup."""
        if not ip or ip in ["N/A", "Unknown", None]:
             if display_immediately:
                  messagebox.showinfo("IP Reputation", "No valid IP address to check.", parent=self)
             return

        info = self.ip_cache.get(ip)
        
        # If cache is old or missing, queue a lookup
        is_fresh = info and (time.time() - info.get("checked_at", 0) < IP_CACHE_TTL)

        if not is_fresh:
            self.ip_queue.put(ip)
            if display_immediately:
                 messagebox.showinfo("IP Reputation", f"Queued lookup/refresh for {ip}.\nPlease check again shortly.", parent=self)
            return

        # If data is fresh, format and display it
        lines = [f"IP Address: {ip}"]
        if "error" in info: lines.append(f"Status: Error - {info['error']}")
        else:
            lines.extend([
                f"Location: {info.get('city', 'N/A')}, {info.get('country', 'N/A')}",
                f"Organization: {info.get('org', 'N/A')}",
                f"ISP: {info.get('isp', 'N/A')}",
                f"Proxy Detected: {'Yes' if info.get('proxy') else 'No'}",
                f"Mobile Network: {'Yes' if info.get('mobile') else 'No'}",
            ])
        lines.append(f"Checked: {friendly_time_format(datetime.fromtimestamp(info['checked_at']))}")
        
        if display_immediately:
            messagebox.showinfo(f"IP Reputation - {ip}", "\n".join(lines), parent=self)
