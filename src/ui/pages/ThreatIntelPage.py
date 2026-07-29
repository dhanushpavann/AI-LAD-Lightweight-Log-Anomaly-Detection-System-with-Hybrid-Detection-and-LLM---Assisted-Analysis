import customtkinter as ctk
from tkinter import messagebox, filedialog
import threading
import time
import queue
import requests
import re
import json
import os
import csv
from typing import Optional, List, Dict, Any, Set
from datetime import datetime
import random 
from collections import Counter, deque 

# --- Matplotlib/Cartopy Integration ---
# Re-enabling Matplotlib imports
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure 
# Import Matplotlib Navigation Toolbar for full map interactivity
from matplotlib.backends.backend_tkagg import NavigationToolbar2Tk

try:
    import cartopy.crs as ccrs
    import cartopy.feature as cfeature
    CARTOPY_AVAILABLE = True
except ImportError:
    CARTOPY_AVAILABLE = False
    print("WARNING: Cartopy not found. Global Map will use the basic scatter plot projection.")
# --- End Map Integration ---

# Import project modules
from src.config import *
from src.ui.components.modern_components import ModernComponents
from src.backend.database_manager import get_db_instance

# Get DB instance
DB = get_db_instance()

# --- Constants ---
IP_API_URL = "http://ip-api.com/json/{ip}?fields=status,country,regionName,city,lat,lon,isp,org,as,query,proxy,mobile,message"
IP_REGEX = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
IP_CACHE_TTL = 600 # 10 minutes cache for IP info
FEED_POLL_INTERVAL_SECONDS = 300 # 5 minutes for polling simulated external feed

# --- REALISTIC SIMULATION LOGIC ---
def _generate_realistic_threat_ips(alerts: List[Dict[str, Any]]) -> List[str]:
    """
    Generates new simulated threat IPs based on IPs currently present in the alerts.
    This simulates a feed updating with data related to current attackers.
    """
    threat_ips = []
    
    # Collect unique alert IPs excluding local/private range simulation
    live_threat_ips = [a['ip'] for a in alerts if a['ip'] and not a['ip'].startswith('192.168')]
    
    if live_threat_ips and random.random() < 0.7:
        # 70% chance to simulate a burst attack from a known cluster
        base_ip = random.choice(live_threat_ips)
        
        # Mutate the IP slightly (e.g., change the last octet)
        try:
            parts = base_ip.split('.')
            last_octet = int(parts[3])
            
            # Generate up to 3 neighbors (simulating horizontal scan/new IP allocation)
            for _ in range(random.randint(1, 3)):
                new_octet = (last_octet + random.randint(1, 10)) % 255
                if new_octet == 0: new_octet = 1 # Avoid zero or broadcast
                new_ip = f"{parts[0]}.{parts[1]}.{parts[2]}.{new_octet}"
                threat_ips.append(new_ip)
        except Exception:
            # Fallback if IP is malformed (shouldn't happen with IP_REGEX, but safe)
            pass 
    
    if not threat_ips:
        # 30% chance or fallback: Generate generic high-risk IPs
        ip_start = random.choice(["11", "45"])
        threat_ips.append(f"{ip_start}.{random.randint(100, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}")
        
    return threat_ips

# --- Helper Functions ---
def safe_request_get(url, timeout=5):
    """Safely performs a GET request, returns Response or None."""
    try:
        headers = {'User-Agent': 'AI-LogGuard-ThreatIntel/1.0'}
        response = requests.get(url, timeout=timeout, headers=headers)
        response.raise_for_status()
        return response
    except requests.exceptions.RequestException as e:
        print(f"[ThreatIntel] Request error for {url}: {e}")
        return None

def friendly_time_format(dt_obj):
    """Formats datetime object nicely or returns string."""
    if isinstance(dt_obj, datetime):
        return dt_obj.strftime('%Y-%m-%d %H:%M:%S')
    return str(dt_obj)

class ThreatIntelPage(ctk.CTkFrame):
    """
    Page for On-Demand Threat Intelligence Lookup, Blocklist Management,
    and a Global Threat Map, using a 2-panel layout.
    """
    def __init__(self, parent, controller):
        super().__init__(parent, fg_color="transparent")
        self.controller = controller
        self.user_info = controller.user_info

        # --- State ---
        self.is_active = True
        self.ip_queue = queue.Queue()
        self.ip_cache: Dict[str, Dict[str, Any]] = {}
        self.ip_worker_running = False
        self.polling_job = None
        self.map_draw_job = None # Debounce job reference
        # --- UI ---
        container = ctk.CTkFrame(self, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=UI_SETTINGS["spacing"]["md"], pady=UI_SETTINGS["spacing"]["md"])
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=0) # Left panel, fixed width
        container.grid_columnconfigure(1, weight=1) # Right panel, expands

        # Build panels
        self._build_left_panel(container).grid(row=0, column=0, sticky="nsw", padx=(0, UI_SETTINGS["spacing"]["md"]))
        self._build_main_panel(container).grid(row=0, column=1, sticky="nsew")
        
        # Start background workers
        self._start_ip_worker()
        self._start_feed_poller() 
        
        # Initial draw/refresh to load state and show map correctly
        self.after(100, self.refresh_page_content) 

    def stop_threads(self):
        """Called by AiLogGuard when page is switched."""
        print("Stopping ThreatIntelPage threads...")
        self.is_active = False
        self.ip_worker_running = False
        try:
            self.ip_queue.put(None) # Sentinel to stop worker
        except Exception:
            pass
        
        if self.polling_job:
            try: self.after_cancel(self.polling_job)
            except Exception: pass
        if self.map_draw_job:
            try: self.after_cancel(self.map_draw_job)
            except Exception: pass

    def refresh_page_content(self):
        """
        Centralized function to refresh all UI components that depend on 
        external state (Blocklist, Cache, Alerts).
        Called on page entry and after data changes.
        """
        print("ThreatIntelPage: Refreshing UI content.")
        
        # 1. Ensure page is active to process drawing
        self.is_active = True 
        
        # 2. Update Blocklist Tab (Needs fresh data)
        self._refresh_blocklist_ui() 
        
        # 3. Update Map (Forces indicators and map redraw)
        self._draw_map() 


    # --- Feed Polling (Updated to use live alert data) ---
    def _start_feed_poller(self):
        """Starts the periodic task to simulate consuming external threat feeds."""
        self._consume_threat_feed()
        # Update feed status label
        self.feed_status_label.configure(text=f"Last poll: {datetime.now().strftime('%H:%M:%S')}\nInterval: {FEED_POLL_INTERVAL_SECONDS}s")
        self.polling_job = self.after(FEED_POLL_INTERVAL_SECONDS * 1000, self._start_feed_poller)

    def _consume_threat_feed(self):
        """
        Simulates fetching IPs based on live alert data and adding them to the cache/blocklist.
        """
        if not self.is_active: return

        # 1. Get current live alerts for context
        try:
            live_alerts = list(self.controller.global_alert_queue)
        except Exception:
            live_alerts = []

        # 2. Generate new threat IPs based on live data
        new_threat_ips = _generate_realistic_threat_ips(live_alerts)
        count_added = 0
        
        for ip in new_threat_ips:
            # 3. Add to active blocklist (simulating a feed providing blocklist data)
            if self.controller.add_to_blocklist(ip):
                 count_added += 1
            
            # 4. Queue for reputation check/geocoding (if not cached)
            if ip not in self.ip_cache or "lat" not in self.ip_cache.get(ip, {}):
                 self.ip_queue.put(ip)

        if count_added > 0:
            print(f"[ThreatIntel] Automatically added {count_added} IPs from feed to active blocklist.")
            # Trigger full refresh cycle
            self.after(0, self.refresh_page_content)


    # --- Left Panel (Controls) ---
    def _build_left_panel(self, parent) -> ctk.CTkFrame:
        """Builds the left-hand control panel, optimized for less vertical space."""
        panel = ModernComponents.create_card(parent, width=340)
        panel.pack_propagate(False)

        scroll = ctk.CTkScrollableFrame(panel, fg_color="transparent")
        scroll.pack(fill="both", expand=True, padx=5, pady=5)

        ctk.CTkLabel(scroll, text="Threat Intelligence Tools", font=FONT_HEADING, text_color=COLOR_TEXT).pack(
            anchor="nw", padx=UI_SETTINGS["spacing"]["lg"]-5, pady=(UI_SETTINGS["spacing"]["lg"]-5, UI_SETTINGS["spacing"]["sm"])
        )

        # --- Card 1: On-Demand Lookup ---
        lookup_card = ModernComponents.create_card(scroll, fg_color=COLOR_ELEVATION_1)
        lookup_card.pack(fill="x", padx=UI_SETTINGS["spacing"]["xs"], pady=UI_SETTINGS["spacing"]["sm"])
        ctk.CTkLabel(lookup_card, text="🌐 IP Lookup", font=FONT_BODY_MEDIUM).pack(anchor="w", padx=15, pady=(8, 3))
        
        # Lookup frame for better spacing
        lookup_frame = ctk.CTkFrame(lookup_card, fg_color="transparent")
        lookup_frame.pack(fill="x", padx=15, pady=(0, 10))
        lookup_frame.grid_columnconfigure(0, weight=1)
        
        self.lookup_entry = ctk.CTkEntry(
            lookup_frame, placeholder_text="Enter IP (e.g., 8.8.8.8)", font=FONT_BODY,
            height=UI_SETTINGS["button_height"]-10, fg_color=COLOR_ELEVATION_2, border_color=COLOR_ELEVATION_3
        )
        self.lookup_entry.grid(row=0, column=0, sticky="ew", padx=(0, 5))
        self.lookup_entry.bind("<Return>", lambda event: self._on_lookup_click())
        
        lookup_btn = ctk.CTkButton(
            lookup_frame, text="Look Up", font=FONT_BODY_SMALL, height=UI_SETTINGS["button_height"]-10, width=80,
            fg_color=COLOR_PRIMARY, hover_color=COLOR_PRIMARY_VARIANT,
            command=self._on_lookup_click
        )
        lookup_btn.grid(row=0, column=1, sticky="e")

        # --- Card 2: Internal Blocklist ---
        block_card = ModernComponents.create_card(scroll, fg_color=COLOR_ELEVATION_1)
        block_card.pack(fill="x", padx=UI_SETTINGS["spacing"]["xs"], pady=UI_SETTINGS["spacing"]["sm"])
        ctk.CTkLabel(block_card, text="⛔ Active Blocklist Management", font=FONT_BODY_MEDIUM).pack(anchor="w", padx=15, pady=(8, 3))
        
        block_frame = ctk.CTkFrame(block_card, fg_color="transparent")
        block_frame.pack(fill="x", padx=15, pady=(0, 10))
        block_frame.grid_columnconfigure(0, weight=1)
        
        self.blocklist_add_entry = ctk.CTkEntry(
            block_frame, placeholder_text="Enter IP to block...", font=FONT_BODY,
            height=UI_SETTINGS["button_height"]-10, fg_color=COLOR_ELEVATION_2, border_color=COLOR_ELEVATION_3
        )
        self.blocklist_add_entry.grid(row=0, column=0, sticky="ew", padx=(0, 5))
        self.blocklist_add_entry.bind("<Return>", lambda event: self._on_add_to_blocklist())
        
        add_btn = ctk.CTkButton(
            block_frame, text="Block", font=FONT_BODY_SMALL, height=UI_SETTINGS["button_height"]-10, width=80,
            fg_color=COLOR_RED, hover_color=COLOR_ORANGE,
            command=self._on_add_to_blocklist
        )
        add_btn.grid(row=0, column=1, sticky="e")
        
        self.blocklist_status_label = ctk.CTkLabel(block_card, text="Status: Ready", font=FONT_BODY_SMALL, text_color=COLOR_TEXT_SECONDARY)
        self.blocklist_status_label.pack(anchor="w", padx=15, pady=(0, 8))


        # --- Card 3: Threat Feeds (Active Polling Status) ---
        feed_card = ModernComponents.create_card(scroll, fg_color=COLOR_ELEVATION_1)
        feed_card.pack(fill="x", padx=UI_SETTINGS["spacing"]["xs"], pady=UI_SETTINGS["spacing"]["sm"])
        ctk.CTkLabel(feed_card, text="📡 Threat Feeds Status", font=FONT_BODY_MEDIUM).pack(anchor="w", padx=15, pady=(8, 3))
        
        self.feed_status_label = ctk.CTkLabel(
            feed_card, 
            text=f"Last poll: N/A\nInterval: {FEED_POLL_INTERVAL_SECONDS}s", 
            font=FONT_BODY_SMALL, text_color=COLOR_TEXT_SECONDARY, anchor="w", justify="left"
        )
        self.feed_status_label.pack(fill="x", padx=15, pady=(0, 5))

        add_feed_btn = ctk.CTkButton(
            feed_card, text="View Feed Sources (Simulated)", font=FONT_BODY_SMALL, height=UI_SETTINGS["button_height"]-10,
            fg_color=COLOR_ELEVATION_3, hover_color=COLOR_ELEVATION_4,
            command=lambda: messagebox.showinfo("Simulated", "Integration with external feeds is handled by the worker.", parent=self)
        )
        add_feed_btn.pack(fill="x", padx=15, pady=(5, 10))
        
        # --- Card 4: Actions (Consolidated into one frame) ---
        action_card = ModernComponents.create_card(scroll, fg_color=COLOR_ELEVATION_1)
        action_card.pack(fill="x", padx=UI_SETTINGS["spacing"]["xs"], pady=(UI_SETTINGS["spacing"]["sm"]))
        ctk.CTkLabel(action_card, text="⚙️ Tools & Export", font=FONT_BODY_MEDIUM).pack(anchor="w", padx=15, pady=(8, 3))
        
        export_btn = ctk.CTkButton(
            action_card, text="Export Blocklist (CSV)", font=FONT_BODY_SMALL, height=UI_SETTINGS["button_height"]-10,
            fg_color=COLOR_ELEVATION_3, hover_color=COLOR_ELEVATION_4, command=self._export_blocklist
        )
        export_btn.pack(fill="x", padx=15, pady=(5, 5))
        
        clear_cache_btn = ctk.CTkButton(
            action_card, text="Clear IP Reputation Cache", font=FONT_BODY_SMALL, height=UI_SETTINGS["button_height"]-10,
            fg_color=COLOR_ELEVATION_3, hover_color=COLOR_ELEVATION_4, command=self._clear_ip_cache
        )
        clear_cache_btn.pack(fill="x", padx=15, pady=(5, 10))

        return panel

    # --- Main Panel (Content) ---
    def _build_main_panel(self, parent) -> ctk.CTkFrame:
        """Builds the right-hand, tabbed content panel."""
        panel = ModernComponents.create_card(parent)
        panel.grid_rowconfigure(0, weight=1)
        panel.grid_columnconfigure(0, weight=1)

        # Create Tabbed Interface
        self.tab_view = ctk.CTkTabview(
            panel, fg_color=COLOR_ELEVATION_1,
            segmented_button_fg_color=COLOR_ELEVATION_3,
            segmented_button_selected_color=COLOR_PRIMARY,
            segmented_button_selected_hover_color=COLOR_PRIMARY_VARIANT,
            segmented_button_unselected_hover_color=COLOR_ELEVATION_2,
            text_color=COLOR_TEXT,
            border_color=COLOR_DIVIDER, border_width=1
        )
        self.tab_view.grid(row=0, column=0, sticky="nsew", padx=15, pady=15)

        # Add tabs
        self.tab_view.add("Lookup Results")
        self.tab_view.add("Active Blocklist") # Renamed for clarity
        self.tab_view.add("Global Threat Map")
        
        # Build content for each tab
        self._create_lookup_tab_content(self.tab_view.tab("Lookup Results"))
        self._create_blocklist_tab_content(self.tab_view.tab("Active Blocklist"))
        self._create_map_tab_content(self.tab_view.tab("Global Threat Map"))
        
        return panel

    # --- Tab 1: Lookup Results Content ---
    def _create_lookup_tab_content(self, tab):
        tab.grid_rowconfigure(0, weight=1)
        tab.grid_columnconfigure(0, weight=1)
        
        # --- Lookup Results Styling (Requested Update) ---
        self.lookup_results_text = ctk.CTkTextbox(
            tab, 
            font=FONT_HEADING, # Use a larger, bold font for modern look
            fg_color=COLOR_BG, 
            text_color=COLOR_TEXT, # Set text color to white (COLOR_TEXT) as requested
            border_width=1, border_color=COLOR_DIVIDER,
            wrap="word", state="disabled"
        )
        # ----------------------------------------------------
        self.lookup_results_text.grid(row=0, column=0, sticky="nsew", padx=15, pady=15)
        self._update_lookup_results("Enter an IP in the panel on the left and click 'Look Up' to see results here.")
    
    # --- Tab 2: Internal Blocklist Content ---
    def _create_blocklist_tab_content(self, tab):
        tab.grid_rowconfigure(0, weight=1)
        tab.grid_columnconfigure(0, weight=1)
        self.blocklist_scroll_frame = ctk.CTkScrollableFrame(
            tab, fg_color=COLOR_BG, border_width=1, border_color=COLOR_ELEVATION_3,
            corner_radius=UI_SETTINGS["corner_radius"]-2
        )
        self.blocklist_scroll_frame.grid(row=0, column=0, sticky="nsew", padx=15, pady=15)
        self._refresh_blocklist_ui() # Populate list

    # --- Tab 3: Global Threat Map Content ---
    def _create_map_tab_content(self, tab):
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1) # Make map card expand

        # --- Indicator/Header Row ---
        map_header_frame = ctk.CTkFrame(tab, fg_color="transparent")
        map_header_frame.grid(row=0, column=0, sticky="ew", padx=15, pady=(15,0))
        map_header_frame.grid_columnconfigure((0,1,2,3,4), weight=1) # Distribute indicators evenly

        # 1. Indicator for Total Alerts (Need label reference for updates)
        self.indicator_total_alerts, self.label_total_alerts = ModernComponents.create_stat_card(map_header_frame, "Total Alerts", "0", icon="🔔")
        self.indicator_total_alerts.grid(row=0, column=0, sticky="ew", padx=(0, UI_SETTINGS["spacing"]["sm"]))

        # 2. Indicator for Blocked IPs (Need label reference for updates)
        self.indicator_blocked_ips, self.label_blocked_ips = ModernComponents.create_stat_card(map_header_frame, "Blocked IPs", "0", icon="⛔")
        self.indicator_blocked_ips.grid(row=0, column=1, sticky="ew", padx=UI_SETTINGS["spacing"]["sm"])

        # 3. Indicator for Cache Size (Need label reference for updates)
        self.indicator_cache_size, self.label_cache_size = ModernComponents.create_stat_card(map_header_frame, "Cache Size", "0", icon="💾")
        self.indicator_cache_size.grid(row=0, column=2, sticky="ew", padx=UI_SETTINGS["spacing"]["sm"])
        
        # 4. Map Control Frame (Right side)
        map_control_frame = ctk.CTkFrame(map_header_frame, fg_color="transparent")
        map_control_frame.grid(row=0, column=4, sticky="e", padx=(UI_SETTINGS["spacing"]["sm"], 0))
        map_control_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(map_control_frame, text="Global Alert Map", font=FONT_BODY_MEDIUM, text_color=COLOR_TEXT).grid(row=0, column=0, sticky="w", columnspan=3, pady=(0, 5))
        
        # Zoom Out Button
        zoom_out_btn = ctk.CTkButton(
            map_control_frame, text="➖", width=30, height=UI_SETTINGS["button_height"]-10, font=FONT_BODY_MEDIUM,
            fg_color=COLOR_ELEVATION_3, hover_color=COLOR_ELEVATION_4,
            command=lambda: self._adjust_map_zoom(-2)
        )
        zoom_out_btn.grid(row=1, column=0, padx=(0, 5))
        
        # Zoom In Button
        zoom_in_btn = ctk.CTkButton(
            map_control_frame, text="➕", width=30, height=UI_SETTINGS["button_height"]-10, font=FONT_BODY_MEDIUM,
            fg_color=COLOR_ELEVATION_3, hover_color=COLOR_ELEVATION_4,
            command=lambda: self._adjust_map_zoom(2)
        )
        zoom_in_btn.grid(row=1, column=1, padx=(0, 10))
        
        # Refresh Button
        refresh_btn = ctk.CTkButton(
            map_control_frame, text="⟳ Refresh Map", height=UI_SETTINGS["button_height"]-10, font=FONT_BODY_SMALL,
            fg_color=COLOR_ELEVATION_3, hover_color=COLOR_ELEVATION_4,
            command=self._refresh_map_data
        )
        refresh_btn.grid(row=1, column=2)
        
        # --- Map Canvas ---
        map_card = ModernComponents.create_card(tab, fg_color=COLOR_BG)
        map_card.grid(row=1, column=0, sticky="nsew", padx=15, pady=15)
        map_card.grid_rowconfigure(0, weight=1)
        map_card.grid_columnconfigure(0, weight=1)

        self.map_status_label = ctk.CTkLabel(
            map_card, text="Click 'Refresh Map' to load data.",
            font=FONT_BODY, text_color=COLOR_TEXT_SECONDARY
        )
        self.map_status_label.grid(row=0, column=0, sticky="nsew")

        # Setup Matplotlib Figure
        plt.style.use('dark_background')
        
        # --- CARTOPY 2D MAP AXES SETUP (Colorful Continents) ---
        if CARTOPY_AVAILABLE:
            # Use PlateCarree projection for a standard map
            self.map_fig, self.map_ax = plt.subplots(
                facecolor=COLOR_BG, 
                subplot_kw={'projection': ccrs.PlateCarree()},
                figsize=(1,1), # Dummy size, will be overwritten by on_map_resize
                dpi=100
            )
            self.map_ax.set_global() 
            
            # Add stylish, colorful features
            # Land filled with ELEVATION_2, Borders with PRIMARY
            self.map_ax.add_feature(cfeature.LAND, facecolor=COLOR_ELEVATION_2, edgecolor=COLOR_DIVIDER, alpha=0.9) 
            self.map_ax.add_feature(cfeature.COASTLINE, linewidth=0.5, edgecolor=COLOR_TEXT_SECONDARY)
            self.map_ax.add_feature(cfeature.BORDERS, linestyle='-', linewidth=0.3, edgecolor=COLOR_PRIMARY, alpha=0.5) 
            self.map_ax.add_feature(cfeature.OCEAN, facecolor=COLOR_BG) 
            
        else:
            # Fallback to basic 2D scatter plot setup
            self.map_fig, self.map_ax = plt.subplots(facecolor=COLOR_BG)
            self.map_ax.set_xlim(-180, 180); self.map_ax.set_ylim(-90, 90)
            self.map_status_label.configure(text="WARNING: Cartopy not found. Displaying basic coordinate plot.", text_color=COLOR_WARNING)
        # --- END CARTOPY 2D MAP AXES SETUP ---


        self.map_ax.set_facecolor(COLOR_BG)
        self.map_fig.subplots_adjust(left=0.01, right=0.99, top=0.99, bottom=0.01)
        self.map_ax.set_xticks([]); self.map_ax.set_yticks([])
        for spine in self.map_ax.spines.values(): spine.set_edgecolor(COLOR_DIVIDER)
        
        # Initialize the scatter plot, respecting the projection
        self.map_scatter = self.map_ax.scatter([], [], c=COLOR_RED, alpha=0.7, s=30, 
                                                transform=ccrs.PlateCarree() if CARTOPY_AVAILABLE else self.map_ax.transData)
        
        self.map_canvas = FigureCanvasTkAgg(self.map_fig, master=map_card)
        self.map_canvas_widget = self.map_canvas.get_tk_widget()
        self.map_canvas_widget.configure(bg=COLOR_BG)
        
        # --- FIX: Bind widget resize event to Matplotlib redraw ---
        def on_map_resize(event):
            if self.map_canvas_widget.winfo_ismapped():
                width = map_card.winfo_width()
                height = map_card.winfo_height()
                if width > 1 and height > 1:
                    dpi = self.map_fig.dpi
                    self.map_fig.set_size_inches(width/dpi, height/dpi)
                    self.map_canvas.draw_idle()

        map_card.bind('<Configure>', on_map_resize)
        
        # --- INTEGRATE MATPLOTLIB TOOLBAR (For full zoom/pan flexibility) ---
        self.map_toolbar = NavigationToolbar2Tk(self.map_canvas, map_card, pack_toolbar=False)
        self.map_toolbar.update()
        # Place the toolbar just above the map canvas itself (row 0)
        self.map_toolbar.grid(row=0, column=0, sticky="nw") 
        # Hide the default title label on the toolbar
        self.map_toolbar.winfo_children()[0].pack_forget()

        # -----------------------------------------------------------

    def _update_indicators(self, ip_counts: Counter, alert_count: int):
        """Updates the status indicator labels at the top of the map panel."""
        
        # Total Alerts
        self.label_total_alerts.configure(text=str(alert_count))
        
        # Blocked IPs
        blocked_count = len(self.controller.get_active_blocklist())
        self.label_blocked_ips.configure(text=str(blocked_count))
        
        # Cache Size
        cache_count = len(self.ip_cache)
        self.label_cache_size.configure(text=str(cache_count))
        
        # Update styling based on urgency
        if blocked_count > 0:
            self.label_blocked_ips.configure(text_color=COLOR_RED)
        else:
             self.label_blocked_ips.configure(text_color=COLOR_TEXT) # Reset color


    def _adjust_map_zoom(self, step: float):
        """
        [FIXED] Adjusts the Cartopy map zoom level based on the current center and redraws.
        The interactive zoom is primarily handled by the toolbar now. 
        This button logic is simplified to provide discrete zoom steps.
        """
        if not CARTOPY_AVAILABLE or not hasattr(self, 'map_ax'):
            messagebox.showinfo("Map Error", "Cartopy not installed or map not initialized.", parent=self)
            return

        # 1. Get current extent in PlateCarree coordinates
        try:
            min_lon, max_lon, min_lat, max_lat = self.map_ax.get_extent(ccrs.PlateCarree())
        except Exception:
            min_lon, max_lon, min_lat, max_lat = -180, 180, -90, 90

        center_lon = (min_lon + max_lon) / 2
        center_lat = (min_lat + max_lat) / 2
        
        lon_width = max_lon - min_lon
        lat_height = max_lat - min_lat
        
        # 2. Determine Zoom Factor
        zoom_factor = 0.2 * step # Adjust by 20% per click
        
        new_lon_width = lon_width * (1 - zoom_factor)
        new_lat_height = lat_height * (1 - zoom_factor)
        
        # 3. Apply Clamping Logic & Recalculate New Extent
        
        # If zooming out beyond global limits or near global limits, reset to global view
        if new_lon_width >= 350 or new_lat_height >= 170:
            self.map_ax.set_global()
        else:
            # Calculate New Extent centered around the CURRENT center
            new_min_lon = center_lon - new_lon_width / 2
            new_max_lon = center_lon + new_lon_width / 2
            new_min_lat = center_lat - new_lat_height / 2
            new_max_lat = center_lat + new_lat_height / 2
            
            self.map_ax.set_extent([new_min_lon, new_max_lon, new_min_lat, new_max_lat], crs=ccrs.PlateCarree())

        self.map_canvas.draw_idle()


    # --- Left Panel Actions ---
    def _on_lookup_click(self):
        """Handles the 'Look Up' button click."""
        indicator = self.lookup_entry.get().strip()
        if not indicator: return
            
        if not IP_REGEX.fullmatch(indicator):
             self.tab_view.set("Lookup Results") # Switch to results tab
             self._update_lookup_results(f"Invalid Input: '{indicator}'\n\nThis demo only supports IPv4 addresses.")
             return
        
        self.tab_view.set("Lookup Results") # Switch to results tab
        self._update_lookup_results(f"Looking up IP: {indicator}...")
        
        info = self.ip_cache.get(indicator)
        if not info or (time.time() - info.get("checked_at", 0) > IP_CACHE_TTL):
            self.ip_queue.put(indicator)
            self.after(2000, lambda: self._check_lookup_result(indicator)) # Check after 2s
            self.after(5000, lambda: self._check_lookup_result(indicator)) # Check after 5s
        else:
            self.after(10, lambda: self._display_ip_info(indicator, info)) # Display cached info immediately

    def _on_add_to_blocklist(self):
        """Adds an IP to the shared active blocklist via the controller."""
        ip = self.blocklist_add_entry.get().strip()
        if not ip or not IP_REGEX.fullmatch(ip):
             messagebox.showwarning("Invalid IP", f"'{ip}' is not a valid IP address.", parent=self)
             return
        
        if self.controller.add_to_blocklist(ip):
            DB.log_action("BLOCKLIST_ADD", user_id=self.user_info.get('id'), details=f"Active block: {ip}")
            # Trigger full refresh
            self.after(0, self.refresh_page_content) 
            self.blocklist_add_entry.delete(0, "end") # Clear entry
            self.blocklist_status_label.configure(text=f"IP {ip} added to active blocklist.", text_color=COLOR_SUCCESS)
            self.tab_view.set("Active Blocklist")
        else:
            self.blocklist_status_label.configure(text=f"IP {ip} is already blocked.", text_color=COLOR_WARNING)

    def _on_remove_from_blocklist(self, ip: str):
        """Removes an IP from the shared active blocklist via the controller."""
        if messagebox.askyesno("Confirm Removal", f"Are you sure you want to remove '{ip}' from the active blocklist?", parent=self):
            if self.controller.remove_from_blocklist(ip):
                 DB.log_action("BLOCKLIST_REMOVE", user_id=self.user_info.get('id'), details=f"Active unblock: {ip}")
                 # Trigger full refresh
                 self.after(0, self.refresh_page_content) 
                 self.blocklist_status_label.configure(text=f"IP {ip} removed.", text_color=COLOR_INFO)
            else:
                 self.blocklist_status_label.configure(text=f"IP {ip} was not found.", text_color=COLOR_RED)

    def _on_blocklist_check_ip(self, ip: str):
        """Called from button in blocklist, populates and switches to lookup tab."""
        self.tab_view.set("Lookup Results") # Switch tab
        self.lookup_entry.delete(0, 'end')
        self.lookup_entry.insert(0, ip) # Prefill
        self._on_lookup_click() # Run lookup

    def _export_blocklist(self):
        """Exports the active blocklist to CSV."""
        blocklist = list(self.controller.get_active_blocklist())
        
        if not blocklist:
            messagebox.showinfo("Export Empty", "Blocklist is empty.", parent=self)
            return
            
        path = filedialog.asksaveasfilename(initialfile="active_blocklist.csv", defaultextension=".csv", filetypes=[("CSV Files", "*.csv")])
        if not path: return

        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["IP_Address", "Status (Active Block)", "Last_Check_ISP", "Country"])
                for ip in blocklist:
                    info = self.ip_cache.get(ip, {})
                    writer.writerow([ip, "ACTIVE", info.get("isp", "N/A"), info.get("country", "N/A")])
            messagebox.showinfo("Export Success", f"Exported {len(blocklist)} IPs to {os.path.basename(path)}", parent=self)
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export: {e}", parent=self)
            
    def _clear_ip_cache(self):
        """Clears the local IP reputation cache."""
        if messagebox.askyesno("Confirm", "Clear all cached IP reputations? (This will re-fetch data on next lookup)", parent=self):
            self.ip_cache.clear()
            print("IP reputation cache cleared.")
            messagebox.showinfo("Cache Cleared", "IP reputation cache has been cleared.", parent=self)


    # --- Main Panel Actions & Helpers ---
    def _refresh_blocklist_ui(self):
        """Clears and redraws the list of blocked IPs in Tab 2."""
        if not hasattr(self, 'blocklist_scroll_frame') or not self.blocklist_scroll_frame.winfo_exists(): return
        
        for widget in list(self.blocklist_scroll_frame.winfo_children()): widget.destroy()
        
        blocklist = sorted(list(self.controller.get_active_blocklist()))
        
        if not blocklist:
            ctk.CTkLabel(self.blocklist_scroll_frame, text="Active blocklist is empty.",
                         font=FONT_BODY, text_color=COLOR_TEXT_SECONDARY).pack(pady=20)
            return

        for ip in blocklist:
            item_frame = ctk.CTkFrame(self.blocklist_scroll_frame, fg_color=COLOR_ELEVATION_1)
            item_frame.pack(fill="x", pady=UI_SETTINGS["spacing"]["xs"], padx=UI_SETTINGS["spacing"]["xs"])
            item_frame.grid_columnconfigure(0, weight=1) # Label expands
            
            # Label
            ctk.CTkLabel(item_frame, text=f"⛔ {ip}", font=FONT_BODY).grid(row=0, column=0, sticky="w", padx=10, pady=10)
            
            action_frame = ctk.CTkFrame(item_frame, fg_color="transparent")
            action_frame.grid(row=0, column=1, sticky="e", padx=10, pady=5)
            
            check_btn = ctk.CTkButton(
                action_frame, text="Check", width=70, height=28, font=FONT_BODY_SMALL,
                fg_color=COLOR_ELEVATION_3, hover_color=COLOR_ELEVATION_4,
                command=lambda ip=ip: self._on_blocklist_check_ip(ip)
            )
            check_btn.pack(side="left", padx=UI_SETTINGS["spacing"]["xs"])
            
            remove_btn = ctk.CTkButton(
                action_frame, text="Remove", width=70, height=28, font=FONT_BODY_SMALL,
                fg_color=COLOR_RED, hover_color=COLOR_ORANGE,
                command=lambda ip=ip: self._on_remove_from_blocklist(ip)
            )
            remove_btn.pack(side="left", padx=UI_SETTINGS["spacing"]["xs"])


    def _check_lookup_result(self, ip: str):
        """Called by 'after' to update the UI once the worker finishes."""
        if not self.is_active: return # Stop if page is closed
        info = self.ip_cache.get(ip)

        # Check if worker is done (status is no longer "checking...")
        if info and info.get("status") != "checking...":
             self._display_ip_info(ip, info)
             self._schedule_map_draw() # Schedule draw when an IP lookup finishes
        elif info and info.get("status") == "checking...":
             # Still checking, reschedule self for a later time
             self.after(3000, lambda: self._check_lookup_result(ip))
        elif not info:
             # If completely missing (lookup failed/missed), reschedule one more time
             self.after(5000, lambda: self._check_lookup_result(ip))


    def _display_ip_info(self, ip: str, info: Dict[str, Any]):
        """Displays formatted IP reputation information."""
        
        lines = [f"--- IP REPUTATION REPORT ---"]
        
        # Determine status color
        if ip in self.controller.get_active_blocklist():
            status_line = f"⚠️ THREAT STATUS: ACTIVE BLOCKLIST (Proactive Defense)"
            status_color = COLOR_RED
        elif info.get("proxy"):
            status_line = f"🟠 THREAT STATUS: SUSPECT (Proxy/VPN Detected)"
            status_color = COLOR_ORANGE
        elif info.get("error"):
            status_line = f"❌ THREAT STATUS: ERROR - {info['error']}"
            status_color = COLOR_ERROR
        else:
            status_line = f"✅ THREAT STATUS: CLEAN (Routine Traffic)"
            status_color = COLOR_SUCCESS

        lines.append(status_line)
        lines.append("-" * 30 + "\n")
        
        lines.append(f"ADDRESS: \t{ip}")
        lines.append(f"LOCATION: \t{info.get('city', 'N/A')}, {info.get('regionName', 'N/A')}, {info.get('country', 'N/A')}")
        lines.append(f"LAT/LON: \t{info.get('lat', 'N/A')}/{info.get('lon', 'N/A')}")
        lines.append(f"ISP: \t\t{info.get('isp', 'N/A')}")
        lines.append(f"ORGANIZATION: \t{info.get('org', 'N/A')}")
        lines.append(f"PROXY/VPN: \t{'Yes' if info.get('proxy') else 'No'}")
        lines.append(f"MOBILE: \t\t{'Yes' if info.get('mobile') else 'No'}")
        lines.append(f"CHECKED AT: \t{friendly_time_format(datetime.fromtimestamp(info.get('checked_at', time.time())))}\n")
        
        output_text = "\n".join(lines)
        
        # --- Apply colors to the output textbox ---
        if not hasattr(self, 'lookup_results_text') or not self.lookup_results_text.winfo_exists():
            return

        try:
            self.lookup_results_text.configure(state="normal")
            self.lookup_results_text.delete("1.0", "end")
            self.lookup_results_text.insert("1.0", output_text)
            
            # Apply color tagging based on status line (Must be done after inserting text)
            start_index = self.lookup_results_text.search(status_line, "1.0", stopindex="end")
            if start_index:
                end_index = f"{start_index}+{len(status_line)}c"
                self.lookup_results_text.tag_add("status_color", start_index, end_index)
                self.lookup_results_text.tag_config("status_color", foreground=status_color)
            
            # Apply requested overall TEXT color (COLOR_TEXT = White)
            self.lookup_results_text.tag_add("all_text", "1.0", "end")
            self.lookup_results_text.tag_config("all_text", foreground=COLOR_TEXT)
            
            self.lookup_results_text.configure(state="disabled")
        except Exception as e:
            print(f"Error updating lookup results: {e}")

    def _update_lookup_results(self, text: str):
        """Helper to safely write text to the results textbox (used for initial/loading messages)."""
        if not hasattr(self, 'lookup_results_text') or not self.lookup_results_text.winfo_exists():
            return
        try:
            self.lookup_results_text.configure(state="normal")
            self.lookup_results_text.delete("1.0", "end")
            self.lookup_results_text.insert("1.0", text)
            self.lookup_results_text.configure(state="disabled")
        except Exception as e:
            print(f"Error updating lookup results: {e}")

    def _schedule_map_draw(self):
        """Debounces map drawing to avoid locking the UI thread."""
        if self.map_draw_job:
            self.after_cancel(self.map_draw_job)
        # Schedule the heavy draw operation to run in 500ms
        self.map_draw_job = self.after(500, self._draw_map)

    def _refresh_map_data(self):
        """Gathers IPs from global alerts, queues them, and schedules a draw."""
        if not self.is_active: return
        print("Threat Map: Refresh requested...")
        
        self.map_status_label.grid(row=0, column=0, sticky="nsew")
        self.map_status_label.configure(text="Refreshing IP data...")
        self.map_canvas_widget.grid_forget() # Hide map (if Matplotlib)
        self.update_idletasks()
        
        try: alerts = list(self.controller.global_alert_queue)
        except Exception as e: alerts = []; print(f"Error reading global_alert_queue: {e}")

        unique_ips = {a.get("ip") for a in alerts if a.get("ip") and a.get("ip") not in ["N/A", "Unknown", None]}
        
        new_ips_queued = 0
        for ip in unique_ips:
            cached = self.ip_cache.get(ip)
            if not cached or (time.time() - cached.get("checked_at", 0) > IP_CACHE_TTL) or "lat" not in cached:
                 self.ip_queue.put(ip)
                 new_ips_queued += 1
        
        print(f"Threat Map: Found {len(unique_ips)} IPs. Queued {new_ips_queued} new lookups.")
        
        # Schedule draw after a small delay regardless of new lookups
        self._schedule_map_draw()


    def _draw_map(self):
        """Redraws the map scatter plot with data from the IP cache and updates indicators."""
        if not self.is_active or not hasattr(self, 'map_ax'):
             return
             
        if not CARTOPY_AVAILABLE:
            self.map_status_label.grid(row=0, column=0, sticky="nsew")
            self.map_status_label.configure(text="Map library (Cartopy) not available for detailed map.", text_color=COLOR_RED)
            return

        self.map_status_label.grid_forget() # Hide status
        self.map_canvas_widget.grid(row=0, column=0, sticky="nsew", padx=5, pady=5) # Show map
        
        lats, lons, sizes, colors = [], [], [], []
        
        try:
             alert_queue_list = list(self.controller.global_alert_queue)
             ip_counts = Counter([
                 a.get("ip") for a in alert_queue_list
                 if a.get("ip") and a.get("ip") not in ["N/A", "Unknown", None]
             ])
        except Exception:
             ip_counts = {}
        
        # FIX: The crash happens here. We must check if map_scatter has been 
        # initialized *before* trying to remove it. 
        if hasattr(self, 'map_scatter') and self.map_scatter in self.map_ax.collections:
             # Remove the old scatter object only if it exists in the axes' collection list
             self.map_scatter.remove()
            
        for ip, count in ip_counts.items():
            info = self.ip_cache.get(ip)
            if info and "lat" in info and "lon" in info:
                 lats.append(info["lat"])
                 lons.append(info["lon"])
                 # Use size scaling for visibility
                 sizes.append(30 + (count * 10)) 
                 # Requested: Location point color must be RED
                 colors.append(COLOR_RED) 
        
        # --- Update Indicators (Functional Update) ---
        self._update_indicators(ip_counts, len(alert_queue_list))
        # ---------------------------------------------
        
        if not lats:
             print("Threat Map: No geolocated IPs to draw.")
             self.map_canvas_widget.grid_forget()
             self.map_status_label.grid(row=0, column=0, sticky="nsew")
             self.map_status_label.configure(text="No geolocated alert data found.", text_color=COLOR_TEXT_SECONDARY)
             
             # Re-initialize map_scatter as an empty object for future updates
             self.map_scatter = self.map_ax.scatter([], [], c=COLOR_RED, alpha=0.7, s=30, 
                                                     transform=ccrs.PlateCarree() if CARTOPY_AVAILABLE else self.map_ax.transData)
             if hasattr(self, 'map_canvas'): self.map_canvas.draw_idle()
             return

        # Redraw new scatter points
        self.map_scatter = self.map_ax.scatter(lons, lats, c=COLOR_RED, alpha=0.8, s=sizes, 
                                                transform=ccrs.PlateCarree())
        
        if hasattr(self, 'map_canvas'): self.map_canvas.draw_idle()
        print(f"Threat Map: Drawn {len(lats)} IP locations in 2D (Cartopy).")

    # --- IP Worker and Helpers (Copied from LiveMonitor) ---
    def _start_ip_worker(self):
        """Starts the IP reputation lookup thread."""
        if self.ip_worker_running: return
        self.ip_worker_running = True
        threading.Thread(target=self._ip_worker_loop, daemon=True, name="ThreatIntelIPWorker").start()
        print("Threat Intel IP Reputation worker started.")

    def _ip_worker_loop(self):
        """Background thread for IP lookups."""
        while self.ip_worker_running:
            ip_to_check = None
            try:
                 ip_to_check = self.ip_queue.get(block=True, timeout=1.0)
                 if ip_to_check is None: break

                 cached = self.ip_cache.get(ip_to_check, {})
                 if cached and (time.time() - cached.get("checked_at", 0) > IP_CACHE_TTL):
                     continue
                 
                 self.ip_cache[ip_to_check] = {"status": "checking...", "checked_at": time.time()}
                 # print(f"Threat Intel: Looking up IP: {ip_to_check}")

                 info = {"checked_at": time.time()}
                 try:
                     response = safe_request_get(IP_API_URL.format(ip=ip_to_check), timeout=5)
                     if response:
                         payload = response.json()
                         if payload.get("status") == "success":
                             info.update({k: payload.get(k) for k in ("country", "regionName", "city", "lat", "lon", "isp", "org", "proxy", "mobile") if payload.get(k) is not None})
                         else: info["error"] = f"API Error: {payload.get('message', 'Unknown')}"
                     else: info["error"] = "Request Failed"
                 except Exception as req_e: info["error"] = f"Request Exception: {req_e}"

                 self.ip_cache[ip_to_check] = info
                 time.sleep(1.5) # Rate limit
                 
                 # IMPORTANT: Schedule UI update after a successful lookup (debounced)
                 if self.is_active and "lat" in info:
                     # FIX: Call the global refresh, not just the map draw, 
                     # to ensure indicators and blocklist update too.
                     self.after(0, self.refresh_page_content) 

            except queue.Empty:
                 if not self.is_active: break
                 continue
            except Exception as e:
                 print(f"Threat Intel IP worker error: {e}")
                 if ip_to_check: self.ip_cache[ip_to_check] = {"checked_at": time.time(), "error": f"Worker Exception: {e}"}
                 time.sleep(5)
        print("Threat Intel IP Reputation worker finished.")