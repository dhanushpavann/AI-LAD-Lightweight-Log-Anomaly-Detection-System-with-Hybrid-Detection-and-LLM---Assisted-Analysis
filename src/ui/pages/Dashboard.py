import customtkinter as ctk
from tkinter import messagebox, filedialog, Canvas
import os
import re
import csv
import json
from datetime import datetime, timedelta
import threading
import queue
from collections import deque, Counter
from typing import Optional, Dict, Any, Tuple, List, Set

# Safe import for system stats
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import matplotlib.ticker as mticker
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import requests
import time 
import random 

# --- Import theme, components, and DB access (Using REAL IMPORTS) ---
from src.config import *
from src.ui.components.modern_components import ModernComponents # Separated import
from src.backend.database_manager import get_db_instance

# Get the Singleton DB instance (relies on database_manager.py)
DB = get_db_instance() 

# --- Helper: Safe requests wrapper --
def safe_get(url, headers=None, params=None, timeout=6):
    try:
        headers = headers or {'User-Agent': 'AI-LLM-Dashboard/1.0'}
        response = requests.get(url, headers=headers, params=params, timeout=timeout)
        response.raise_for_status()
        return response
    except requests.exceptions.RequestException as e:
        return None

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


# --- Main Dashboard Page Class ---
class DashboardPage(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent, fg_color="transparent")
        self.controller = controller
        self.user_info = controller.user_info 

        # --- Runtime state ---
        self.is_active = True
        self.live_mode = ctk.BooleanVar(value=True)
        # Use shared state variables from the controller 
        self.graph_data = controller.global_graph_data 
        self.pie_counts = controller.global_pie_counts 
        self.top_ips = controller.global_top_ips 	 
        self.geo_counts = controller.global_geo_counts
        self.rule_actions = controller.global_rule_action_counts 
        self.speed_data = controller.global_speed_data 
        
        # IP reputation data is local to the page worker
        self.ip_reputation_cache = {} 
        self.ip_check_queue = queue.Queue()
        self.ip_worker_running = False
        self.alert_widget_list = deque(maxlen=10) # Local UI element for displaying alerts
        self.update_job_id = None
        self.ip_to_block_var = ctk.StringVar()
        
        # --- Matplotlib figure references for cleanup ---
        self.matplotlib_figures = [] 

        # --- Root Scrollable Frame ---
        self.scroll_frame = ctk.CTkScrollableFrame(self, fg_color="transparent")
        self.scroll_frame.pack(fill="both", expand=True, padx=UI_SETTINGS["spacing"]["sm"], pady=UI_SETTINGS["spacing"]["sm"])
        
        container = ctk.CTkFrame(self.scroll_frame, fg_color="transparent")
        container.pack(fill="both", expand=True)
        
        # Configure Grid Layout 
        container.grid_columnconfigure(0, weight=2) 
        container.grid_columnconfigure(1, weight=2) 
        container.grid_columnconfigure(2, weight=1) 
        container.grid_columnconfigure(3, weight=1) 
        
        container.grid_rowconfigure(0, weight=0) # Stats row 
        container.grid_rowconfigure(1, weight=4) # Efficacy Graph + Alerts 
        container.grid_rowconfigure(2, weight=3) # Bottom panels 

        # --- Build UI Sections ---
        self._create_stat_cards(container)
        
        # ROW 1: Efficacy Graph and Alerts Panel
        self._create_efficacy_graph(container).grid(row=1, column=0, columnspan=2, sticky="nsew", padx=(0, UI_SETTINGS["spacing"]["xs"]), pady=UI_SETTINGS["spacing"]["sm"])
        self._create_recent_alerts(container).grid(row=1, column=2, columnspan=2, sticky="nsew", padx=(UI_SETTINGS["spacing"]["xs"], 0), pady=UI_SETTINGS["spacing"]["sm"])
        
        # ROW 2: Summary Charts
        self._create_action_summary_chart(container).grid(row=2, column=0, sticky="nsew", padx=(0, UI_SETTINGS["spacing"]["xs"]), pady=UI_SETTINGS["spacing"]["xs"])
        self._create_pie_chart(container).grid(row=2, column=1, sticky="nsew", padx=(UI_SETTINGS["spacing"]["xs"], UI_SETTINGS["spacing"]["xs"]), pady=UI_SETTINGS["spacing"]["xs"])
        self.top_ips_frame = self._create_geo_map(container)
        self.top_ips_frame.grid(row=2, column=2, columnspan=2, sticky="nsew", padx=(UI_SETTINGS["spacing"]["xs"], 0), pady=UI_SETTINGS["spacing"]["xs"]) 
        

        # --- Start background tasks ---
        self._start_ip_worker()
        self.after(100, self._initial_draw) 
        self._update_ui() 
        


    def stop_threads(self):
        """Stops all background tasks cleanly and closes matplotlib figures."""
        self.is_active = False
        if self.update_job_id:
            try: self.after_cancel(self.update_job_id); self.update_job_id = None
            except Exception: pass
        self.ip_worker_running = False
        try: self.ip_check_queue.put(None)
        except Exception: pass
        
        # Close all matplotlib figures to prevent memory leaks
        for fig in self.matplotlib_figures:
            try:
                plt.close(fig)
            except Exception:
                pass
        self.matplotlib_figures.clear()
        
    def _initial_draw(self):
        """
        Forces initial drawing of charts. Ensures all shared buffers are checked once 
        upon page load to reflect the latest state.
        """
        stats = self.controller.global_stats
        now = datetime.now()
        
        # 1. Initialize graph buffers with current cumulative totals if empty
        if not self.graph_data:
            detected_total = stats.get("anomalies_total", 0)
            blocked_total = stats.get("threats_blocked", 0)
            self.graph_data.append((now, detected_total, blocked_total))
            
        if not self.speed_data:
            speed_value = stats.get("anomalies_this_second", 0)
            self.speed_data.append((now, speed_value))
            
        # 2. Draw all static charts/lists based on existing shared data
        self._refresh_pie()
        self._refresh_action_summary()
        self._refresh_top_ips_display() 
        self._update_efficacy_graph(initial=True) 

    # --- UI Builders ---
    
    def _create_stat_cards(self, parent):
        card_frame_anom, self.label_anom = ModernComponents.create_stat_card(parent, title="Total Anomalies", value="0", icon="🚨")
        card_frame_logs, self.label_logs = ModernComponents.create_stat_card(parent, title="Logs Processed", value="0", icon="🗂️")
        card_frame_threat, self.label_threat = ModernComponents.create_stat_card(parent, title="Threats Blocked", value="0", icon="🛡️")
        card_frame_health, self.label_health = ModernComponents.create_stat_card(parent, title="System Health", value="100%", icon="💚")

        card_frame_anom.grid(row=0, column=0, sticky="nsew", padx=(0, UI_SETTINGS["spacing"]["xs"]), pady=UI_SETTINGS["spacing"]["xs"])
        card_frame_logs.grid(row=0, column=1, sticky="nsew", padx=UI_SETTINGS["spacing"]["xs"], pady=UI_SETTINGS["spacing"]["xs"])
        card_frame_threat.grid(row=0, column=2, sticky="nsew", padx=UI_SETTINGS["spacing"]["xs"], pady=UI_SETTINGS["spacing"]["xs"])
        card_frame_health.grid(row=0, column=3, sticky="nsew", padx=(UI_SETTINGS["spacing"]["xs"], 0), pady=UI_SETTINGS["spacing"]["xs"])

        self.label_anom.configure(text_color=COLOR_RED)
        self.label_threat.configure(text_color=COLOR_ORANGE)
        self.label_health.configure(text_color=COLOR_PRIMARY)
        return card_frame_anom 


    def _create_efficacy_graph(self, parent):
        card = ModernComponents.create_card(parent)
        
        ctk.CTkLabel(card, text="System Efficacy Trend (Detected vs. Blocked)", font=FONT_HEADING, text_color=COLOR_TEXT).pack(anchor="nw", padx=15, pady=(15, 5))

        plt.style.use('dark_background')
        CHART_BG = globals().get('COLOR_ELEVATION_1', '#2d3436') 
        
        self.fig, self.ax = plt.subplots()
        self.fig.patch.set_facecolor(COLOR_CARD)
        self.ax.set_facecolor(CHART_BG) 
        
        # Detected (Threats) line in RED
        self.line_detected, = self.ax.plot([], [], linestyle='--', marker='o', markersize=3, linewidth=1.5, color=COLOR_RED, label="Detected")
        self.fill = None 
        # --- FIX: Blocked (Success) line in ACCENT (High Contrast) ---
        self.line_blocked, = self.ax.plot([], [], linestyle='-', marker='s', markersize=3, linewidth=2, color=COLOR_ACCENT, label="Blocked")
        
        self.ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
        self.ax.tick_params(axis='x', colors=COLOR_TEXT_SECONDARY, labelsize=9)
        self.ax.tick_params(axis='y', colors=COLOR_TEXT_SECONDARY, labelsize=9)
        self.ax.spines['top'].set_visible(False); self.ax.spines['right'].set_visible(False)
        self.ax.spines['bottom'].set_color(COLOR_DIVIDER); self.ax.spines['left'].set_color(COLOR_DIVIDER)
        self.ax.yaxis.set_major_locator(mticker.MaxNLocator(integer=True, nbins=5))
        self.ax.grid(True, axis='y', linestyle=':', linewidth=0.5, color=COLOR_DIVIDER, alpha=0.5)
        self.ax.legend(loc='upper left', frameon=False)

        self.fig.tight_layout(pad=1.0)
        self.canvas = FigureCanvasTkAgg(self.fig, master=card)
        self.canvas.get_tk_widget().configure(bg=COLOR_CARD)
        self.canvas.get_tk_widget().pack(expand=True, fill="both", padx=10, pady=(0, 10))
        
        return card

    def _create_recent_alerts(self, parent):
        card = ModernComponents.create_card(parent)
        
        ctk.CTkLabel(card, text="Recent Alerts", font=FONT_HEADING, text_color=COLOR_TEXT).pack(anchor="nw", padx=15, pady=(15, 6))
        self.alert_list = ctk.CTkScrollableFrame(
            card, fg_color=COLOR_BG, corner_radius=UI_SETTINGS["corner_radius"]-2,
            border_color=COLOR_ELEVATION_3, border_width=0
        )
        self.alert_list.pack(expand=True, fill="both", padx=15, pady=(0, 15))
        
        return card


    def _add_alert_widget(self, description: str, when: str, severity: str = "Info", ip: str = "N/A"):
        """Adds a single, styled alert item to the recent alerts list."""
        if not self.alert_list.winfo_exists(): return
        
        severity_color = SEV_COLOR.get(severity.title(), COLOR_TEXT_SECONDARY)
        BORDER_WIDTH_ALERT = 2 

        item = ctk.CTkFrame(
            self.alert_list, 
            fg_color=COLOR_ELEVATION_1, 
            corner_radius=UI_SETTINGS["corner_radius"],
            border_color=severity_color, 
            border_width=BORDER_WIDTH_ALERT 
        )
        item.pack(side="top", fill="x", pady=UI_SETTINGS["spacing"]["xs"], padx=UI_SETTINGS["spacing"]["xs"])
        item.description = description 
        
        inner_frame = ctk.CTkFrame(item, fg_color="transparent")
        inner_frame.pack(fill="x", padx=UI_SETTINGS["spacing"]["sm"], pady=UI_SETTINGS["spacing"]["sm"])
        inner_frame.grid_columnconfigure(0, weight=1) 
        inner_frame.grid_columnconfigure(1, weight=0) 
        inner_frame.grid_columnconfigure(2, weight=0) 

        ctk.CTkLabel(
            inner_frame, text=description, font=FONT_BODY_MEDIUM, text_color=COLOR_TEXT, 
            wraplength=200, justify="left", anchor="w"
        ).grid(row=0, column=0, sticky="w", padx=(0, UI_SETTINGS["spacing"]["sm"]))
        
        ip_badge = ctk.CTkLabel(
            inner_frame, text=ip, font=FONT_CAPTION, 
            text_color=COLOR_TEXT_SECONDARY, fg_color=COLOR_ELEVATION_2,
            corner_radius=4, padx=6, pady=2
        )
        ip_badge.grid(row=0, column=1, sticky="e", padx=UI_SETTINGS["spacing"]["xs"])
        
        severity_badge = ModernComponents.create_badge(
            inner_frame, text=severity.upper(), badge_type=severity.lower()
        )
        severity_badge.grid(row=0, column=2, sticky="e")
        
        bottom_row = ctk.CTkFrame(item, fg_color="transparent")
        bottom_row.pack(side="bottom", fill="x", padx=UI_SETTINGS["spacing"]["sm"], pady=(0, UI_SETTINGS["spacing"]["sm"]))

        ctk.CTkLabel(
            bottom_row, text=when, font=FONT_CAPTION, text_color=COLOR_TEXT_SECONDARY, anchor="w"
        ).pack(side="left")

        ctk.CTkButton(
            bottom_row, text="View Log", width=70, height=20, font=FONT_CAPTION,
            fg_color=COLOR_ACCENT, hover_color=COLOR_PRIMARY, text_color=COLOR_BG,
            command=lambda d=description: messagebox.showinfo("Log View", f"Details for: {d}") 
        ).pack(side="right")

        self.alert_widget_list.append(item)
        
        # Clean up oldest widget if max size is reached
        if len(self.alert_widget_list) > self.alert_widget_list.maxlen:
            oldest = self.alert_widget_list.popleft()
            if oldest.winfo_exists(): oldest.destroy()


    def _create_pie_chart(self, parent):
        card = ModernComponents.create_card(parent)
        
        ctk.CTkLabel(card, text="Threat Categories", font=FONT_HEADING, text_color=COLOR_TEXT).pack(anchor="nw", padx=15, pady=(15, 6))
        
        plt.style.use('dark_background')
        CHART_BG = globals().get('COLOR_ELEVATION_1', '#2d3436') 
        
        self.pie_fig, self.pie_ax = plt.subplots(figsize=(3, 2.5), facecolor=COLOR_CARD)
        self.matplotlib_figures.append(self.pie_fig)  # Register for cleanup
        self.pie_ax.set_facecolor(CHART_BG) 
        self.pie_fig.subplots_adjust(left=0.05, right=0.95, top=0.95, bottom=0.05)
        
        self.pie_canvas = FigureCanvasTkAgg(self.pie_fig, master=card)
        self.pie_canvas.get_tk_widget().configure(bg=COLOR_CARD)
        self.pie_canvas.get_tk_widget().pack(expand=True, fill="both", padx=10, pady=(0, 10))
        
        return card

        
    def _create_geo_map(self, parent):
        card = ModernComponents.create_card(parent)
        
        ctk.CTkLabel(card, text="Threat Geo-Location", font=FONT_HEADING, text_color=COLOR_TEXT).pack(anchor="nw", padx=15, pady=(15, 6))

        plt.style.use('dark_background')
        CHART_BG = globals().get('COLOR_ELEVATION_1', '#2d3436') 
        
        self.geo_fig, self.geo_ax = plt.subplots(figsize=(3, 2.5), facecolor=COLOR_CARD)
        self.matplotlib_figures.append(self.geo_fig)  # Register for cleanup
        self.geo_ax.set_facecolor(CHART_BG) 
        self.geo_ax.barh([], [], color=COLOR_PRIMARY)
        self.geo_fig.subplots_adjust(left=0.3, right=0.95, top=0.95, bottom=0.1)
        
        self.geo_canvas = FigureCanvasTkAgg(self.geo_fig, master=card)
        self.geo_canvas.get_tk_widget().configure(bg=COLOR_CARD)
        self.geo_canvas.get_tk_widget().pack(expand=True, fill="both", padx=10, pady=(0, 10))
        
        return card


    def _create_action_summary_chart(self, parent):
        card = ModernComponents.create_card(parent)
        
        ctk.CTkLabel(card, text="Automated Response Summary", font=FONT_HEADING, text_color=COLOR_TEXT).pack(anchor="nw", padx=15, pady=(15, 6))

        plt.style.use('dark_background')
        CHART_BG = globals().get('COLOR_ELEVATION_1', '#2d3436') 
        
        # Horizontal Bar Chart
        self.fig_action, self.ax_action = plt.subplots(figsize=(3, 2.5), facecolor=COLOR_CARD)
        self.matplotlib_figures.append(self.fig_action)  # Register for cleanup
        self.ax_action.set_facecolor(CHART_BG) 
        self.fig_action.subplots_adjust(left=0.4, right=0.95, top=0.95, bottom=0.1) 
        
        self.canvas_action = FigureCanvasTkAgg(self.fig_action, master=card)
        self.canvas_action.get_tk_widget().configure(bg=COLOR_CARD)
        self.canvas_action.get_tk_widget().pack(expand=True, fill="both", padx=10, pady=(0, 10))
        
        return card


   # --- Chart Refresh Methods ---
    
    def _update_efficacy_graph(self, initial=False):
        """Updates the Efficacy Trend Graph with thread safety."""
        if not self.graph_data: return
        
        # Create a thread-safe snapshot (Copy) of the deque
        data_snapshot = list(self.graph_data)

        # CRITICAL: Reverse data so plotting is oldest -> newest (fixes time direction)
        data_snapshot.reverse()
        
        if len(data_snapshot) >= 1:
            times, detected_vals, blocked_vals = zip(*data_snapshot)
            
            time_nums = mdates.date2num(times)
            
            self.line_detected.set_data(time_nums, detected_vals)
            self.line_blocked.set_data(time_nums, blocked_vals)

            if hasattr(self, 'fill') and self.fill: self.fill.remove()
            # The fill should correspond to the Detected line (RED)
            self.fill = self.ax.fill_between(time_nums, detected_vals, color=COLOR_RED, alpha=0.2)
            
            max_val = max(detected_vals) if detected_vals else 1
            self.ax.set_ylim(0, max(5, max_val * 1.2))
            
            # X-axis limits (oldest to newest)
            if len(data_snapshot) > 1:
                 self.ax.set_xlim(time_nums[0], time_nums[-1])
            else:
                 self.ax.set_xlim(time_nums[0] - 0.0001, time_nums[0] + 0.0001) 
            
            self.canvas.draw_idle()
            

    def _refresh_action_summary(self):
        """Fetches data from the controller and draws the Automated Response Summary chart."""
        # 1. Get Data from Controller
        action_counts = self.controller.global_rule_action_counts 
        
        # Sort data by count (most frequent actions first)
        sorted_actions = sorted(action_counts.items(), key=lambda item: item[1], reverse=True)
        
        actions = [item[0] for item in sorted_actions]
        counts = [item[1] for item in sorted_actions]

        if not counts:
            # If no data, clear chart and display a placeholder message
            self.ax_action.clear()
            self.ax_action.text(0.5, 0.5, "No Automated Actions Yet", 
                                transform=self.ax_action.transAxes, 
                                ha='center', va='center', color=COLOR_TEXT_SECONDARY)
            self.canvas_action.draw_idle()
            return
            
        # 2. Setup Plotting Environment
        self.ax_action.clear() # CRITICAL: Clear previous bars
        self.ax_action.set_facecolor(globals().get('COLOR_ELEVATION_1', '#2d3436'))
        
        action_colors = {
            "BLOCK": COLOR_RED, "ALERT": COLOR_WARNING, 
            "LOG": COLOR_INFO, "NOTIFY": COLOR_ACCENT, 
        }
        
        colors = [action_colors.get(action.upper().split()[0], COLOR_PRIMARY) for action in actions]

        # 3. Draw the Horizontal Bar Chart
        bars = self.ax_action.barh(actions, counts, color=colors)
        
        # 4. Final Styling
        self.ax_action.invert_yaxis()
        self.ax_action.set_xlim(0, max(counts) * 1.1 + 1)
        
        self.ax_action.spines['right'].set_visible(False)
        self.ax_action.spines['top'].set_visible(False)
        self.ax_action.spines['left'].set_color(COLOR_DIVIDER)
        self.ax_action.spines['bottom'].set_color(COLOR_DIVIDER)
        
        self.ax_action.tick_params(axis='x', colors=COLOR_TEXT_SECONDARY, labelsize=9)
        self.ax_action.tick_params(axis='y', colors=COLOR_TEXT, labelsize=10)
        
        # Add labels to the bars
        for bar in bars:
            width = bar.get_width()
            self.ax_action.text(width + 0.1, bar.get_y() + bar.get_height()/2,
                                f'{int(width)}',
                                va='center', color=COLOR_TEXT, fontsize=9)

        # 5. Update Canvas
        self.canvas_action.draw_idle() # CRITICAL: Tells the UI to redraw the chart
    
    
    
    def _refresh_geo_map(self):
        """Refreshes the Geo-Location horizontal bar chart."""
        if not self.is_active or not hasattr(self, 'geo_ax'): return
        self.geo_ax.clear()
        
        CHART_BG = globals().get('COLOR_ELEVATION_1', '#2d3436') 
        self.geo_ax.set_facecolor(CHART_BG)
        
        if not self.geo_counts:
            self.geo_ax.text(0.5, 0.5, "No Geo Data", ha="center", va="center", color=COLOR_TEXT_SECONDARY, fontsize=10, transform=self.geo_ax.transAxes)
        else:
            countries_counts = self.geo_counts.most_common(5)
            countries, counts = zip(*countries_counts)
            colors = [MATPLOTLIB_COLORS[i % MATPLOTLIB_COLORS_LEN] for i in range(len(countries))]
            
            self.geo_ax.barh(countries, counts, color=colors)
            self.geo_ax.invert_yaxis() 
            
            self.geo_ax.tick_params(axis='x', colors=COLOR_TEXT_SECONDARY, labelsize=9)
            self.geo_ax.tick_params(axis='y', colors=COLOR_TEXT, labelsize=9)
            self.geo_ax.set_xlabel("Attack Count", color=COLOR_TEXT_SECONDARY, fontsize=9)
            self.geo_ax.spines['top'].set_visible(False); self.geo_ax.spines['right'].set_visible(False)
            self.ax.xaxis.set_major_locator(mticker.MaxNLocator(integer=True))
            
        if hasattr(self, 'geo_canvas'): self.geo_canvas.draw_idle()


    def _refresh_pie(self):
        """Refreshes the Threat Categories Donut Chart."""
        if not self.is_active or not hasattr(self, 'pie_ax'): return
        self.pie_ax.clear()
        
        CHART_BG = globals().get('COLOR_ELEVATION_1', '#2d3436') 
        self.pie_ax.set_facecolor(CHART_BG) 
        
        if not self.pie_counts:
            self.pie_ax.text(0.5, 0.5, "No Data", ha="center", va="center", color=COLOR_TEXT_SECONDARY, fontsize=10)
        else:
            labels_sizes = self.pie_counts.most_common(5)
            labels, sizes = zip(*labels_sizes)
            pie_colors = [SEV_COLOR.get(l.title(), COLOR_TEXT_SECONDARY) for l in labels]
            
            self.pie_ax.pie(
                sizes, labels=labels, autopct='%1.0f%%', startangle=90,
                colors=pie_colors, textprops={'color': "white", 'fontsize': 9},
                pctdistance=0.85, wedgeprops={'linewidth': 1, 'edgecolor': COLOR_CARD}
            )
            # Draw center circle to create the donut effect
            self.pie_ax.add_artist(plt.Circle((0, 0), 0.60, fc=COLOR_CARD))
        # Keep circular pie without triggering fixed-limit aspect warnings.
        self.pie_ax.set_aspect('equal', adjustable='box')
        if hasattr(self, 'pie_canvas'): self.pie_canvas.draw_idle()

    def _refresh_top_ips_display(self):
        """
        Feeds new/stale IPs to the background Geo-Location worker and refreshes the map display.
        Uses actual DB calls.
        """
        if not self.top_ips:
            self._refresh_geo_map()
            return

        current_time = time.time()
        
        # Queue IP check if data is missing or stale (TTL 600s)
        for ip, count in self.top_ips.most_common(8):
            cached_data = self.ip_reputation_cache.get(ip, {})

            # Try reading from the actual DB first
            try:
                db_info = DB.get_ip_info(ip) 
                if db_info:
                    # Update local cache with DB info
                    self.ip_reputation_cache[ip] = {
                        'country': db_info.get('country'), 
                        'ts': db_info.get('updated_at'),
                        'status': 'db_cached'
                    }
            except Exception:
                # If DB read fails, proceed to check local cache/queue for API call
                pass

            # Queue API call if data is missing or stale
            if 'status' not in cached_data or cached_data.get('status') == 'failed' or (current_time - cached_data.get("ts", 0) > 600):
                self.ip_check_queue.put(ip)

        # After queuing, refresh the geo map based on current known data
        self._refresh_geo_map() 


    # --- Background Tasks (Worker and Update Loop) ---
    def _start_ip_worker(self):
        if self.ip_worker_running: return
        self.ip_worker_running = True
        threading.Thread(target=self._ip_worker_loop, daemon=True).start()
        
    def _ip_worker_loop(self):
        """Handles asynchronous IP reputation lookups, using the actual DB manager."""
        while self.ip_worker_running:
            try:
                ip = self.ip_check_queue.get(timeout=1)
                if ip is None: break 
                
                # 1. Check Local Memory Cache (quick skip if recently fetched)
                if ip in self.ip_reputation_cache and self.ip_reputation_cache[ip].get('status') != 'failed':
                    if time.time() - self.ip_reputation_cache[ip].get("ts", 0) < 600:
                        continue
                
                # 2. Check Database Cache (Actual DB call)
                db_info = DB.get_ip_info(ip) 
                
                if db_info and (time.time() - float(db_info['updated_at']) < 604800):
                    self.ip_reputation_cache[ip] = dict(db_info) # Use dict(db_info) if row_factory is set
                    if db_info.get('country'):
                        self.geo_counts.update([db_info['country']])
                    continue # Skip API call

                # 3. Call API (Actual Slow Call)
                url = f"http://ip-api.com/json/{ip}?fields=status,country,city,isp,org,proxy"
                resp = safe_get(url)
                
                if resp and resp.status_code == 200:
                    data = resp.json()
                    data['ts'] = time.time()
                    
                    # Update Memory Cache and Global Geo Counters
                    country = data.get('country')
                    if country:
                         self.geo_counts.update([country])
                         
                    self.ip_reputation_cache[ip] = data
                    DB.save_ip_info(ip, data) 
                else:
                    self.ip_reputation_cache[ip] = {"ts": time.time(), "status": "failed"}
                    
                time.sleep(1.5) # Rate limit delay
            except queue.Empty: continue
            except Exception as e: 
                print(f"IP Worker Error: {e}")
                time.sleep(1)


    def _update_ui(self):
        """
        The main UI loop, runs every second to update stat cards and charts with real-time data.
        """
        if not self.is_active: return

        if self.live_mode.get():
            try:
                stats = self.controller.global_stats
                
                # --- 1. Consume Logs & Update Persistent Counters ---
                processed = 0
                while processed < 100 and self.controller.global_log_queue:
                    try:
                        # Pop the oldest log entry for processing (consumes the queue)
                        log = self.controller.global_log_queue.popleft() 
                        processed += 1
                        
                        # Data processing occurs here (updates global counters)
                        # CRITICAL FIX: Increment the total logs processed stat
                        stats['logs_processed'] = stats.get('logs_processed', 0) + 1
                        
                        if log.get("anomaly"):
                            # CRITICAL FIX: Increment the total anomalies stat
                            stats['anomalies_total'] = stats.get('anomalies_total', 0) + 1
                            
                            self.pie_counts.update([log.get("category", "Other").upper()])
                            self.top_ips.update([log.get("ip")])
                            
                            # Check if the anomaly resulted in a block action
                            action = log.get("action")
                            if "BLOCK" in str(action).upper():
                                # CRITICAL FIX: Increment the total blocked threats stat
                                stats['threats_blocked'] = stats.get('threats_blocked', 0) + 1
                                
                        # Update the Recent Alerts list if a new alert exists
                        if len(self.controller.global_alert_queue) > 0:
                            # Use alert queue head for new alert visualization
                            alert = self.controller.global_alert_queue[0] 
                            if not any(w.description == alert['description'] for w in self.alert_widget_list if hasattr(w, 'description')):
                                self._add_alert_widget(
                                    alert.get('description', 'Unknown Alert'), 
                                    alert.get('timestamp', datetime.now()).strftime("%H:%M:%S"), 
                                    alert.get('severity', 'Info'), 
                                    alert.get('ip', 'N/A') 
                                )
                                
                    except IndexError: break

                # --- 2. Update Graph Data & Draw Efficacy Graph ---
                self._update_efficacy_graph()

                # --- 3. Update Stat Cards (Read from the CoreLogic's self.global_stats) ---
                self.label_anom.configure(text=f"{stats.get('anomalies_total', 0):,}")
                self.label_logs.configure(text=f"{stats.get('logs_processed', 0):,}")
                self.label_threat.configure(text=f"{stats.get('threats_blocked', 0):,}")
                
                if PSUTIL_AVAILABLE:
                    try:
                        cpu_percent = psutil.cpu_percent()
                        self.label_health.configure(text=f"{100-cpu_percent:.1f}%")
                    except Exception:
                        self.label_health.configure(text="N/A")
                
                # --- 4. Refresh Charts Periodically (Every 3 seconds) ---
                if int(time.time()) % 3 == 0:
                    self._refresh_pie()
                    self._refresh_action_summary()
                    self._refresh_top_ips_display() 
                    self._refresh_geo_map()
                    try:
                        # We call this every 3 seconds, or whenever your main chart refresh logic runs
                        self._refresh_action_summary() 
                    except Exception as e:
                        print(f"Error updating action summary chart: {e}")
            
            except Exception as e: 
                print(f"Dashboard UI Update Error: {e}")

        # Schedule the next run after 1000ms (1 second)
        self.update_job_id = self.after(1000, self._update_ui)
