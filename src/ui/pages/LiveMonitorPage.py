import customtkinter as ctk
from tkinter import filedialog, messagebox, Canvas
import os
import re
from datetime import datetime
from collections import deque, Counter
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import random
import time
import threading

# =========================================================================
# EXTERNAL DEPENDENCIES
# =========================================================================

from src.config import *
from src.ui.components.modern_components import ModernComponents # Assumed available

# --- Utility Function ---
IP_REGEX = re.compile(r'(?:\d{1,3}\.){3}\d{1,3}')
ANSI_ESCAPE = re.compile(r'\x1B\[[0-9;]*[mK]')

def _strip_console_colors(text):
    """Utility function to remove ANSI escape codes from the log line."""
    return ANSI_ESCAPE.sub('', text)

# =========================================================================
# APPLICATION CLASS (The View)
# =========================================================================

class LiveMonitorPage(ctk.CTkFrame):
    """
    The 'View' for the Live Monitor, consuming raw log lines and updating UI/stats.
    """
    def __init__(self, parent, controller):
        super().__init__(parent, fg_color="transparent")
        self.controller = controller
        
        # --- Persistence Fix: Link to Controller's shared buffers ---
        self.log_buffer = deque(maxlen=500) 

        self.selected_file_path = None
        self.auto_scroll = ctk.BooleanVar(value=True)
        self.is_active = True
        self.graph_paused = False
        
        # Data Buffers (Linked to Controller's persistent state)
        self.graph_data = controller.global_speed_data 
        self.pie_counts = controller.global_pie_counts 
        self.top_ips = controller.global_top_ips      

        self.ui_update_job = None
        
        # --- Canvas Rendering State ---
        self.canvas_width = 300 
        self.canvas_height = 400
        self.pie_color_map = {
            'Auth': SEV_COLOR.get('Authentication', COLOR_INFO), 
            'Injection': SEV_COLOR.get('Injection', COLOR_ERROR), 
            'Scan': SEV_COLOR.get('Scan', COLOR_WARNING), 
            'Critical': SEV_COLOR.get('Critical', COLOR_ERROR), 
            'Error': SEV_COLOR.get('Error', COLOR_ERROR), 
            'Warn': SEV_COLOR.get('Warn', COLOR_ORANGE), 
            'Info': SEV_COLOR.get('Info', COLOR_ACCENT), 
            'MLAnomaly': SEV_COLOR.get('ML Anomaly', COLOR_ACCENT),
            'General': COLOR_TEXT_SECONDARY,
            'BlueConsole': globals().get('COLOR_INFO', '#3498db'),
            'RedConsole': globals().get('COLOR_ERROR', '#e74c3c'),
        }
        
        self.FONT_SMALL_TITLE = (FONT_FAMILY, 16, "bold")
        self.FONT_TINY_LABEL = (FONT_FAMILY, 11)
        self.FONT_CARD_HEADER = (FONT_FAMILY, 13, "bold") 

        # --- Build UI ---
        self.grid_columnconfigure(0, weight=0, minsize=300) 
        self.grid_columnconfigure(1, weight=1) 
        self.grid_rowconfigure(0, weight=1)

        self._build_left_panel()
        self._build_main_panel()
        
        self._sync_ui_state() 
        self._setup_matplotlib_lines() # Setup lines after ax/fig are created
        self._start_ui_loop()

        self.after(100, self._initial_render_all)

    def stop_threads(self):
        """Stops ONLY local UI timers and closes matplotlib figures."""
        self.is_active = False
        if self.ui_update_job:
            try: self.after_cancel(self.ui_update_job)
            except Exception: pass
        
        # Close matplotlib figure to prevent memory leaks
        try:
            if hasattr(self, 'fig'):
                plt.close(self.fig)
        except Exception:
            pass

    def _initial_render_all(self):
        """Triggers rendering of the persistent log stream and shared canvas data."""
        self._initial_log_render()
        self._refresh_canvas()
        self._update_graph_display() 
    
    # =========================================================================
    # UI Construction
    # =========================================================================
    def _build_left_panel(self):
        panel = ctk.CTkFrame(self, width=300, fg_color=COLOR_ELEVATION_1, corner_radius=UI_SETTINGS["corner_radius"])
        panel.grid(row=0, column=0, sticky="nsew", padx=(0, UI_SETTINGS['spacing']['md']), pady=UI_SETTINGS['spacing']['sm'])
        panel.pack_propagate(False)
        
        scroll = ctk.CTkScrollableFrame(panel, fg_color="transparent")
        scroll.pack(fill="both", expand=True, padx=UI_SETTINGS['spacing']['xs'], pady=UI_SETTINGS['spacing']['xs'])

        ctk.CTkLabel(scroll, text="MONITOR CONFIGURATION", font=self.FONT_SMALL_TITLE, text_color=COLOR_PRIMARY).pack(
            pady=(UI_SETTINGS['spacing']['lg'], UI_SETTINGS['spacing']['md'])
        )
        
        # --- 1. Data Source Card (Implementation omitted for brevity) ---
        card_src = ModernComponents.create_card(scroll, fg_color=COLOR_ELEVATION_2)
        card_src.pack(fill="x", pady=UI_SETTINGS['spacing']['sm'], padx=UI_SETTINGS['spacing']['xs'])
        ctk.CTkLabel(card_src, text="Data Source Selection", font=FONT_BODY_MEDIUM).pack(anchor="w", padx=UI_SETTINGS['spacing']['sm'], pady=(UI_SETTINGS['spacing']['sm'], UI_SETTINGS['spacing']['xs']))
        
        self.source_var = ctk.StringVar(value="Simulation")
        self.opt_source = ctk.CTkOptionMenu(
            card_src, variable=self.source_var,
            values=["Simulation", "Local File", "Network Stream"],
            command=self._on_source_change, 
            height=30, 
            font=self.FONT_TINY_LABEL,
            fg_color=COLOR_ELEVATION_3, 
            button_color=COLOR_PRIMARY,
            text_color=COLOR_TEXT
        )
        self.opt_source.pack(pady=UI_SETTINGS['spacing']['sm'], padx=UI_SETTINGS['spacing']['sm'], fill="x")

        self.file_btn = ctk.CTkButton(
            card_src, text="📂 Select Log File", 
            fg_color=COLOR_ELEVATION_3, 
            hover_color=COLOR_ELEVATION_4,
            command=self._select_file,
            height=30, 
            font=self.FONT_TINY_LABEL
        )
        self.lbl_file = ctk.CTkLabel(
            card_src, text="No file selected", 
            font=FONT_CAPTION, 
            text_color=COLOR_TEXT_SECONDARY
        )
        input_bg_color = globals().get('COLOR_INPUT_BG', COLOR_ELEVATION_3)
        self.entry_url = ctk.CTkEntry(
            card_src, placeholder_text="Enter Stream URL", 
            fg_color=input_bg_color,
            height=30, 
            font=self.FONT_TINY_LABEL
        )
        
        self.src_label = ctk.CTkLabel(
            card_src, text="Active Source: None", 
            font=FONT_BODY_SMALL, 
            text_color=COLOR_TEXT_SECONDARY
        )
        self.src_label.pack(pady=(UI_SETTINGS['spacing']['sm'], UI_SETTINGS['spacing']['sm']), padx=UI_SETTINGS['spacing']['sm'])
        
        self._on_source_change(self.source_var.get())

        # 2. Controls Card
        card_ctrl = ModernComponents.create_card(scroll, fg_color=COLOR_ELEVATION_2)
        card_ctrl.pack(fill="x", pady=UI_SETTINGS['spacing']['sm'], padx=UI_SETTINGS['spacing']['xs'])
        
        self.btn_start = ctk.CTkButton(
            card_ctrl, text="▶ Start Monitoring", 
            font=self.FONT_SMALL_TITLE, 
            height=40, 
            fg_color=COLOR_PRIMARY, 
            hover_color=COLOR_PRIMARY_VARIANT, 
            text_color=COLOR_BG,
            command=self.toggle_monitoring, 
            corner_radius=UI_SETTINGS["corner_radius"]
        )
        self.btn_start.pack(padx=UI_SETTINGS['spacing']['sm'], pady=(UI_SETTINGS['spacing']['lg'], UI_SETTINGS['spacing']['xs']), fill="x")
        
        self.lbl_status = ctk.CTkLabel(
            card_ctrl, text="Status: Idle", 
            font=FONT_BODY_MEDIUM, 
            text_color=COLOR_TEXT_SECONDARY
        )
        self.lbl_status.pack(pady=(UI_SETTINGS['spacing']['xs'], UI_SETTINGS['spacing']['lg']))

        # 3. AI Engine Card
        card_ai = ModernComponents.create_card(scroll, fg_color=COLOR_ELEVATION_2)
        card_ai.pack(fill="x", pady=UI_SETTINGS['spacing']['sm'], padx=UI_SETTINGS['spacing']['xs'])
        
        ctk.CTkLabel(card_ai, text="AI Engine Management", font=self.FONT_CARD_HEADER).pack(anchor="w", padx=UI_SETTINGS['spacing']['sm'], pady=(UI_SETTINGS['spacing']['sm'], UI_SETTINGS['spacing']['xs']))
        
        # FIX: The label creation was missing the master/parent argument (card_ai)
        self.lbl_ai_status = ctk.CTkLabel(
            card_ai, # Added master/parent
            text=self.controller.core_logic.get_ai_status(), 
            font=FONT_BODY_SMALL, 
            text_color=COLOR_ACCENT
        )
        self.lbl_ai_status.pack(pady=UI_SETTINGS['spacing']['xs'])

        ctk.CTkButton(
            card_ai, text="📥 Load Custom Model", 
            fg_color=COLOR_ELEVATION_3, 
            hover_color=COLOR_ELEVATION_4,
            command=self._load_custom_model, 
            height=30, 
            font=self.FONT_TINY_LABEL
        ).pack(padx=UI_SETTINGS['spacing']['sm'], pady=(UI_SETTINGS['spacing']['sm'], UI_SETTINGS['spacing']['xs']), fill="x")

        ctk.CTkButton(
            card_ai, text="🤖 Analyze Last Log (LLM)", 
            fg_color=COLOR_ACCENT, 
            text_color=COLOR_BG,
            hover_color=COLOR_PRIMARY_VARIANT, 
            command=self._analyze_with_llm, 
            height=30, 
            font=self.FONT_TINY_LABEL
        ).pack(padx=UI_SETTINGS['spacing']['sm'], pady=(UI_SETTINGS['spacing']['xs'], UI_SETTINGS['spacing']['lg']), fill="x")

        # 4. Save Snapshot Button
        ctk.CTkButton(
            scroll, text="📸 Save Snapshot", 
            fg_color=COLOR_ELEVATION_3, 
            command=self._save_snapshot, 
            height=30, 
            font=self.FONT_CARD_HEADER 
        ).pack(pady=(UI_SETTINGS['spacing']['md'], UI_SETTINGS['spacing']['lg']), fill="x", padx=UI_SETTINGS['spacing']['md'])

    def _build_main_panel(self):
        """Right side content area with Graph, Log, and Canvas Stats Panel."""
        main = ctk.CTkFrame(self, fg_color="transparent")
        main.grid(row=0, column=1, sticky="nsew")
        
        main.grid_rowconfigure(0, weight=2) 
        main.grid_rowconfigure(1, weight=3) 
        main.grid_columnconfigure(0, weight=3) 
        main.grid_columnconfigure(1, weight=1) 

        # --- A. Top: Real-time Graph (Row 0, Col 0-1 spanning) ---
        graph_card = ModernComponents.create_card(main)
        graph_card.grid(row=0, column=0, columnspan=2, sticky="nsew", pady=(0, UI_SETTINGS['spacing']['sm']), padx=(0, UI_SETTINGS['spacing']['sm']))
        
        header = ctk.CTkFrame(graph_card, fg_color="transparent")
        header.pack(fill="x", padx=15, pady=5)
        ctk.CTkLabel(header, text="Live Anomaly Rate (Events/Sec)", font=FONT_HEADING).pack(side="left")
        
        self.btn_pause = ctk.CTkButton(header, text="Pause Graph", width=80, height=24, font=FONT_BODY_SMALL, fg_color=COLOR_ELEVATION_3, command=self._toggle_graph_pause)
        self.btn_pause.pack(side="right")

        # Matplotlib setup 
        plt.style.use('dark_background')
        self.fig, self.ax = plt.subplots(figsize=(1, 1), facecolor=COLOR_CARD)
        self.fig.patch.set_facecolor(COLOR_CARD)
        self.ax.set_facecolor(COLOR_BG)
        
        # Initial axis configuration (lines are set in _setup_matplotlib_lines)
        self.ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
        self.ax.set_ylim(0, 1.0) # Set a default y-limit
        
        self.ax.tick_params(axis='x', colors=COLOR_TEXT_SECONDARY, labelsize=8)
        self.ax.tick_params(axis='y', colors=COLOR_TEXT_SECONDARY, labelsize=8)
        self.ax.spines['top'].set_visible(False); self.ax.spines['right'].set_visible(False)
        self.ax.spines['bottom'].set_color(COLOR_DIVIDER); self.ax.spines['left'].set_color(COLOR_DIVIDER)
        self.ax.grid(color=COLOR_DIVIDER, alpha=0.3)
        
        # Placeholder lines before real data update
        self.line = None 
        self.fill = None
        
        self.canvas_mpl = FigureCanvasTkAgg(self.fig, master=graph_card)
        self.canvas_mpl.get_tk_widget().configure(bg=COLOR_CARD)
        self.canvas_mpl.get_tk_widget().pack(fill="both", expand=True, padx=10, pady=(0, 5))

        # --- B. Bottom Left: Log Feed (Row 1, Col 0) ---
        log_card = ModernComponents.create_card(main)
        log_card.grid(row=1, column=0, sticky="nsew", padx=(0, UI_SETTINGS['spacing']['sm']), pady=(0, UI_SETTINGS['spacing']['sm']))
        
        l_header = ctk.CTkFrame(log_card, fg_color="transparent")
        l_header.pack(fill="x", padx=15, pady=10)
        ctk.CTkLabel(l_header, text="Live Log Stream", font=FONT_HEADING).pack(side="left")
        
        ctk.CTkButton(l_header, text="Clear", width=60, height=24, font=FONT_BODY_SMALL, fg_color=COLOR_ELEVATION_3, command=self._clear_logs).pack(side="right", padx=5)
        ctk.CTkCheckBox(l_header, text="Auto-Scroll", variable=self.auto_scroll, onvalue=True, offvalue=False, width=20, text_color=COLOR_TEXT_SECONDARY, font=FONT_BODY_SMALL).pack(side="right", padx=10)

        self.log_box = ctk.CTkTextbox(log_card, font=("Consolas", 12), activate_scrollbars=True, fg_color=COLOR_BG)
        self.log_box.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        
        for tag, color in SEV_COLOR.items():
            self.log_box.tag_config(tag.replace(' ', '').replace('_', ''), foreground=color)
        
        self.log_box.configure(state="disabled") 

        # --- C. Bottom Right: Modern Canvas Stats (Row 1, Col 1) ---
        stats_card = ModernComponents.create_card(main)
        stats_card.grid(row=1, column=1, sticky="nsew", pady=(0, UI_SETTINGS['spacing']['sm']), padx=(0, UI_SETTINGS['spacing']['sm']))
        stats_card.grid_columnconfigure(0, weight=1)
        stats_card.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(stats_card, text="Threat Summary", font=FONT_HEADING).grid(row=0, column=0, pady=(10, 5))

        self.stats_canvas = Canvas(
            stats_card, 
            bg=COLOR_CARD, 
            highlightthickness=0 
        )
        self.stats_canvas.grid(row=1, column=0, sticky="nsew", padx=UI_SETTINGS['spacing']['sm'], pady=UI_SETTINGS['spacing']['sm'])
        
        self.stats_canvas.bind("<Configure>", self._on_canvas_resize)
        
        self._refresh_canvas()

    def _setup_matplotlib_lines(self):
        """Initializes Matplotlib line objects after the figure is created."""
        # This prevents the 'self.line is None' error during _update_graph_display
        self.line, = self.ax.plot([], [], color=COLOR_PRIMARY, linewidth=1.5)
        self.fill = self.ax.fill_between([], [], color=COLOR_PRIMARY, alpha=0.2)
        self.canvas_mpl.draw_idle()

    def _update_graph_display(self):
        """Render the current `graph_data` onto the matplotlib axes.

        This is invoked on initial page load and whenever we need to rehydrate
        the graph from the shared buffer.
        """
        try:
            if not hasattr(self, 'ax') or not self.winfo_exists():
                return
        except Exception:
            return

        try:
            # Ensure line objects exist
            if self.line is None or self.fill is None:
                self._setup_matplotlib_lines()

            if not self.graph_data:
                # Nothing to draw yet: clear axes to show empty state
                self.ax.clear()
                self.ax.set_facecolor(COLOR_BG)
                self.ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
                self.ax.set_ylim(0, 1.0)
                self.ax.spines['top'].set_visible(False); self.ax.spines['right'].set_visible(False)
                self.ax.spines['bottom'].set_color(COLOR_DIVIDER); self.ax.spines['left'].set_color(COLOR_DIVIDER)
                self.ax.grid(color=COLOR_DIVIDER, alpha=0.3)
                self.canvas_mpl.draw_idle()
                return

            # Convert data into plottable arrays
            times, vals = zip(*self.graph_data)
            x = mdates.date2num(times)

            # Update line and filled area
            self.line.set_data(x, vals)
            try:
                # Remove old fill if present
                if hasattr(self.fill, 'remove'):
                    self.fill.remove()
            except Exception:
                pass

            self.fill = self.ax.fill_between(x, vals, color=COLOR_PRIMARY, alpha=0.2)

            # Adjust view limits conservatively
            self.ax.set_xlim(x[0], x[-1])
            self.ax.set_ylim(0, max(1, max(vals) * 1.2))

            self.canvas_mpl.draw_idle()

        except Exception as e:
            print(f"LiveMonitor: _update_graph_display error: {e}")
            pass


    # --- Initial Render on Page Load (Persistence Fix) ---
    def _initial_log_render(self):
        """Renders logs from the local buffer when the page is first loaded."""
        self.log_box.configure(state="normal")
        self.log_box.delete("1.0", "end")
        
        if self.log_buffer:
            for line, tag in self.log_buffer:
                if line.strip():
                    self.log_box.insert("end", line + "\n", tag)
            
        else:
            self.log_box.insert("1.0", f"[{datetime.now().strftime('%H:%M:%S')}] [Info] Log stream ready. Start monitoring to begin receiving data.", "Info")
            
        self.log_box.configure(state="disabled")
        if self.auto_scroll.get(): self.log_box.see("end")

    # =========================================================================
    # Logic & Interaction (omitted for brevity)
    # =========================================================================
    def _on_source_change(self, choice):
        try: self.file_btn.pack_forget()
        except AttributeError: pass
        try: self.lbl_file.pack_forget()
        except AttributeError: pass
        try: self.entry_url.pack_forget()
        except AttributeError: pass
        
        padx = UI_SETTINGS['spacing']['sm']
        pady_input = UI_SETTINGS['spacing']['xs']
        
        if choice == "Local File":
            self.file_btn.pack(fill="x", pady=(pady_input, 0), padx=padx)
            self.lbl_file.pack(pady=pady_input)
        elif choice == "Network Stream":
            self.entry_url.pack(fill="x", pady=pady_input, padx=padx)
        
        self.src_label.pack_forget()
        self.src_label.pack(pady=(UI_SETTINGS['spacing']['sm'], UI_SETTINGS['spacing']['sm']), padx=padx)


    def _select_file(self):
        path = filedialog.askopenfilename()
        if path: 
            self.selected_file_path = path
            self.lbl_file.configure(text=os.path.basename(path), text_color=COLOR_TEXT)

    def _lock_inputs(self, locked):
        state = "disabled" if locked else "normal"
        self.opt_source.configure(state=state)
        if hasattr(self, 'file_btn'):
            self.file_btn.configure(state=state)
        if hasattr(self, 'entry_url'):
            self.entry_url.configure(state=state)

    def _sync_ui_state(self):
        """Synchronizes UI elements with the global monitoring state."""
        is_mon = self.controller.is_monitoring
        
        color_success = globals().get('COLOR_SUCCESS', '#2ecc71')

        if is_mon:
            self.btn_start.configure(text="⏹ Stop Monitoring", fg_color=COLOR_RED, hover_color="#c0392b", text_color=COLOR_BG)
            self.lbl_status.configure(text="Status: Active", text_color=color_success) 
            self._lock_inputs(True)
            t = self.controller.monitoring_target
            self.src_label.configure(text=f"Active: {os.path.basename(t) if t and t != 'Simulation' else 'Simulation'}")
        else:
            self.btn_start.configure(text="▶ Start Monitoring", fg_color=COLOR_PRIMARY, hover_color=COLOR_PRIMARY_VARIANT, text_color=COLOR_BG)
            self.lbl_status.configure(text="Status: Idle", text_color=COLOR_TEXT_SECONDARY)
            self._lock_inputs(False)
            self.src_label.configure(text="Active Source: None")


    def toggle_monitoring(self):
        """Handles the start/stop monitoring command."""
        print("[MONITOR] Toggle Monitoring triggered.")
        
        if not self.controller.is_monitoring:
            source = self.source_var.get()
            target = "Simulation"
            mode = "sim"
            
            if source == "Local File":
                if not self.selected_file_path or not os.path.exists(self.selected_file_path):
                    messagebox.showwarning("Error", "Select a valid file first.")
                    return
                target = self.selected_file_path
                mode = "file"
            
            elif source == "Network Stream":
                target = self.entry_url.get().strip()
                if not target: 
                    messagebox.showwarning("Error", "Enter a stream URL.")
                    return
                mode = "link_stream"
            
            # Reset only local visual components and shared counters
            self._clear_logs(clear_all=True) 
            
            self.controller.start_monitoring_thread(target, mode, self)
        else:
            self.controller.stop_monitoring_thread()
        
        self._sync_ui_state()

    def _load_custom_model(self):
        # Mock file selection for demonstration
        model_path = filedialog.askopenfilename(title="Select Model (.pkl)", filetypes=[("Pickle", "*.pkl")])
        if not model_path: return
        vec_path = filedialog.askopenfilename(title="Select Vectorizer (.pkl)", filetypes=[("Pickle", "*.pkl")])
        if not vec_path: return
        
        success, msg = self.controller.core_logic.load_custom_model(model_path, vec_path)
        if success:
            messagebox.showinfo("Success", msg)
            self.lbl_ai_status.configure(text=self.controller.core_logic.get_ai_status())
        else:
            messagebox.showerror("Error", msg)

    def _analyze_with_llm(self):
        # Use the internal buffer for reliable retrieval
        if self.log_buffer:
            content = self.log_buffer[-1][0].strip() if self.log_buffer[-1][0].strip() else self.log_buffer[-2][0].strip()
        else:
            content = ""
            
        if not content:
            messagebox.showinfo("LLM", "No logs available to analyze.")
            return
            
        response = self.controller.core_logic.analyze_with_llm(content)
        
        dialog = ctk.CTkToplevel(self)
        dialog.title("AI Analysis Result")
        dialog.geometry("500x400")
        dialog.attributes("-topmost", True)
        
        ctk.CTkLabel(dialog, text="Log Analysis", font=FONT_HEADING).pack(pady=10)
        
        box = ctk.CTkTextbox(dialog, font=FONT_BODY)
        box.pack(fill="both", expand=True, padx=20, pady=10)
        box.insert("1.0", f"Log Entry:\n{content}\n\n--- Analysis ---\n{response}")
        box.configure(state="disabled")

    def _clear_logs(self, clear_all=False):
        """
        Clears the log display, the local log buffer, and optionally the shared counters.
        """
        self.log_box.configure(state="normal")
        self.log_box.delete("1.0", "end")
        self.log_box.configure(state="disabled")
        
        self.log_buffer.clear()

        # Only clear shared buffers if starting a new monitoring session
        if clear_all:
            self.pie_counts.clear()
            self.top_ips.clear()
            self.graph_data.clear() 
        
        # Reset Matplotlib
        self.ax.clear()
        self.ax.set_facecolor(COLOR_BG)
        self.ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S')) 
        self.ax.set_ylim(0, None) 
        self.ax.spines['top'].set_visible(False); self.ax.spines['right'].set_visible(False)
        self.ax.spines['bottom'].set_color(COLOR_DIVIDER); self.ax.spines['left'].set_color(COLOR_DIVIDER)
        self.ax.grid(color=COLOR_DIVIDER, alpha=0.3)
        self.line, self.fill = None, None # Reset lines/fill object references
        self._setup_matplotlib_lines() # Re-initialize lines
        self.canvas_mpl.draw_idle()
        
        self._refresh_canvas() 

    def _toggle_graph_pause(self):
        self.graph_paused = not self.graph_paused
        self.btn_pause.configure(text="Resume Graph" if self.graph_paused else "Pause Graph")
        
    def _save_snapshot(self):
        path = filedialog.asksaveasfilename(defaultextension=".txt", title="Save Live Log Snapshot")
        if path:
            try:
                with open(path, "w") as f: f.write(self.log_box.get("1.0", "end-1c"))
                messagebox.showinfo("Success", f"Snapshot saved to:\n{path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save file: {e}")

    # =========================================================================
    # Data Consumer Endpoint (Called by CoreLogic's thread)
    # =========================================================================
    def process_line(self, line):
        """
        Receives processed log lines from the CoreLogic thread and schedules the UI update 
        on the main thread (thread-safe operation).
        """
        try:
            self.after(20, lambda: self._update_log_display(line))
        except RuntimeError:
            pass

    def _update_log_display(self, line):
        """
        [Data Processor] Updates the log display and local statistics on the main thread.
        """
        try:
            if not self.winfo_exists(): return
        except Exception:
            return 

        try:
            clean_line = _strip_console_colors(line)
            line_u = clean_line.upper()

            # --- 1. Determine Tag/Category ---
            tag = "Info"
            cat = "General"
            
            severity_match = re.search(r'\[(CRITICAL|ERROR|WARN|INFO|ML ANOMALY|BLUE_CONSOLE|RED_CONSOLE)\]', line_u)
            
            if severity_match:
                tag_name = severity_match.group(1).title().replace(' ', '').replace('_', '')
                tag = tag_name
                cat = tag_name
            
            if "AUTH" in line_u: cat = "Auth"
            elif "SQL" in line_u or "INJECTION" in line_u: cat = "Injection"
            elif "SCAN" in line_u: cat = "Scan"
            
            # --- 2. Update Log Box (Live Log Stream Display) ---
            if clean_line.strip():
                self.log_box.configure(state="normal")
                self.log_box.insert("end", clean_line + "\n", tag) 
                self.log_buffer.append((clean_line, tag)) # Store in local buffer
            
            current_line_count = int(self.log_box.index('end-1c').split('.')[0])
            if current_line_count > 500:
                 self.log_box.delete("1.0", "2.0") 
            
            if self.auto_scroll.get(): self.log_box.see("end")
            self.log_box.configure(state="disabled")

            # --- 3. Update Local Stats Buffers & Canvas Redraw ---
            ips = IP_REGEX.findall(clean_line)
            if ips: self.top_ips.update(ips)
            self.pie_counts.update([cat])

            # CRITICAL FIX: Ensure the canvas is refreshed immediately upon new data arrival
            self._refresh_canvas()

        except Exception as e:
            print(f"LiveMonitor: Critical UI Update Error (Log: '{line[:50]}...'): {e}")
            pass 

    # =========================================================================
    # Canvas Rendering Logic
    # =========================================================================
    def _on_canvas_resize(self, event):
        self.canvas_width = event.width
        self.canvas_height = event.height
        self._refresh_canvas()

    def _refresh_canvas(self):
        """Redraws the unified stats canvas."""
        canvas = self.stats_canvas
        canvas.delete("all")
        
        try:
            if not self.winfo_exists(): return
        except Exception:
            return 

        w = self.canvas_width
        h = self.canvas_height
        
        if w < 200 or h < 300: 
            canvas.create_text(w/2, h/2, text="Too small to render stats", fill=COLOR_TEXT_SECONDARY)
            return

        pie_height = int(h * 0.45) 
        kpi_start_y = pie_height + UI_SETTINGS['spacing']['md']
        
        self._draw_donut_chart(canvas, 
            x=w/2, 
            y=pie_height/2 + 20, 
            radius=min(w, pie_height) * 0.45
        )
        
        self._draw_kpis_and_ips(canvas, kpi_start_y)
        
    def _draw_donut_chart(self, canvas: Canvas, x: float, y: float, radius: float):
        """Renders the simplified Donut Chart on the canvas."""
        canvas.create_text(x, y - radius - 20, 
            text="Threat Distribution", 
            fill=COLOR_TEXT, 
            font=(FONT_FAMILY, 14, "bold")
        )

        total = sum(self.pie_counts.values())
        if total == 0:
            canvas.create_text(x, y, text="No Data", fill=COLOR_TEXT_SECONDARY, font=(FONT_FAMILY, 14))
            return

        start_angle = 90 
        for i, (label, count) in enumerate(self.pie_counts.most_common(5)):
            if count == 0: continue
            
            extent = (count / total) * 360
            color = self.pie_color_map.get(label, COLOR_TEXT_SECONDARY)
            
            bbox = (x - radius, y - radius, x + radius, y + radius)
            canvas.create_arc(bbox, 
                start=start_angle, 
                extent=-extent,
                fill=color, 
                outline=COLOR_CARD, 
                width=1.5,
                tags=label
            )

            legend_x = x + radius + 15
            legend_y = y + (i - 2) * 20 
            
            canvas.create_oval(legend_x - 10, legend_y - 5, legend_x - 5, legend_y + 0, fill=color, outline=color)
            canvas.create_text(legend_x + 5, legend_y - 2, 
                text=f"{label} ({count})", 
                anchor="w", 
                fill=COLOR_TEXT_SECONDARY, 
                font=FONT_CAPTION
            )

            start_angle -= extent

        hole_radius = radius * 0.6
        canvas.create_oval(x - hole_radius, y - hole_radius, x + hole_radius, y + hole_radius, fill=COLOR_CARD, outline=COLOR_CARD)
        
    def _draw_kpis_and_ips(self, canvas: Canvas, start_y: int):
        """Renders KPIs and Top IP Bar Chart on the canvas."""
        w = self.canvas_width
        
        shared_stats = getattr(self.controller, "core_logic", None)
        shared_stats = getattr(shared_stats, "stats", self.controller.global_stats)

        logs_processed = shared_stats.get('logs_processed', 0)
        anomalies = shared_stats.get('anomalies_total', 0)
        
        kpis = [
            ("Logs Processed", logs_processed, COLOR_ACCENT),
            ("Logs Detected", anomalies, COLOR_ORANGE)
        ]
        
        kpi_x_offset = w / 4
        kpi_y = start_y + UI_SETTINGS['spacing']['sm']
        for i, (label, value, color) in enumerate(kpis):
            x_pos = kpi_x_offset + i * kpi_x_offset * 2
            
            canvas.create_text(x_pos, kpi_y, 
                text=label.upper(), 
                fill=COLOR_TEXT_SECONDARY, 
                font=FONT_CAPTION
            )
            canvas.create_text(x_pos, kpi_y + 20, 
                text=f"{value:,}", 
                fill=color, 
                font=(FONT_FAMILY, 18, "bold")
            )

        bar_start_y = kpi_y + 50
        
        canvas.create_text(w/2, bar_start_y, 
            text="TOP ATTACKING IPS (Last 5)", 
            fill=COLOR_TEXT, 
            font=(FONT_FAMILY, 14, "bold")
        )

        top_ips_data = self.top_ips.most_common(5)
        if not top_ips_data:
            canvas.create_text(w/2, bar_start_y + 40, text="No IPs recorded", fill=COLOR_TEXT_SECONDARY, font=(FONT_FAMILY, 12))
            return

        max_count = max(c for ip, c in top_ips_data)
        
        chart_margin_x = UI_SETTINGS['spacing']['md']
        ip_label_width = 110 
        count_label_width = 30
        bar_area_start_x = chart_margin_x + ip_label_width 
        chart_buffer = 10 
        
        chart_area_w = w - chart_margin_x - ip_label_width - count_label_width - chart_buffer
        
        bar_height = 10 
        bar_spacing = 25 
        
        for i, (ip, count) in enumerate(top_ips_data):
            y_pos = bar_start_y + 25 + i * bar_spacing
            
            bar_w = int((count / max(1, max_count)) * chart_area_w) 
            
            canvas.create_text(chart_margin_x, y_pos, 
                text=ip, 
                anchor="w", 
                fill=COLOR_TEXT_SECONDARY, 
                font=FONT_BODY_SMALL
            )
            
            bar_x1 = bar_area_start_x 
            bar_x2 = bar_x1 + bar_w
            canvas.create_rectangle(bar_x1, y_pos - bar_height/2, bar_x2, y_pos + bar_height/2, 
                fill=COLOR_ORANGE, 
                outline=COLOR_ORANGE, 
                tags="ip_bar"
            )
            
            count_x = bar_x2 + 5
            canvas.create_text(count_x, y_pos, 
                text=str(count), 
                anchor="w", 
                fill=COLOR_TEXT_SECONDARY, 
                font=FONT_CAPTION
            )
            
        

    #=========================================================================
    # UI Loop (Main Thread Updates)
    # =========================================================================
    def _start_ui_loop(self):
        """
        Handles graph and global stats updates. Runs once per second (1000ms).
        CoreLogic now populates self.graph_data, this just renders it.
        """
        if not self.is_active: 
            return
        
        # 1. Update Graph (Every 1s) - CoreLogic populates graph_data, we just render
        if self.controller.is_monitoring:
            # Debug: Print graph data status
            graph_len = len(self.graph_data)
            if graph_len > 0:
                print(f"[LIVEMONITOR] Graph has {graph_len} data points, graph_paused={self.graph_paused}")
            
            if not self.graph_paused and len(self.graph_data) > 0:
                try:
                    # Get current data from CoreLogic's speed_data
                    if len(self.graph_data) > 1:
                        times, vals = zip(*self.graph_data)
                        x = mdates.date2num(times)
                        
                        # Check if lines exist before updating
                        if self.line and self.fill:
                            self.line.set_data(x, vals)
                            
                            # Remove old fill before adding new one
                            self.fill.remove()
                            self.fill = self.ax.fill_between(x, vals, color=COLOR_PRIMARY, alpha=0.2)
                            
                            # Show last 60 seconds of data
                            if len(x) > 2:
                                self.ax.set_xlim(x[-60] if len(x) > 60 else x[0], x[-1])
                            else:
                                self.ax.set_xlim(x[0], x[-1])
                            
                            # Dynamic y-axis with at least 1 unit height
                            max_val = max(vals) if vals else 1
                            self.ax.set_ylim(0, max(5, max_val * 1.2))
                            
                            self.canvas_mpl.draw_idle()
                            print(f"[LIVEMONITOR] Updated graph with {len(vals)} data points")
                except Exception as e: 
                    print(f"Live Monitor Graph Update Error: {e}")
        else:
            # Clear graph display when monitoring stops
            if len(self.graph_data) > 0:
                self.graph_data.clear()
                self.ax.clear()
                # Re-setup the axes appearance
                self.ax.set_facecolor(COLOR_BG)
                self.ax.spines['top'].set_visible(False); self.ax.spines['right'].set_visible(False)
                self.ax.spines['bottom'].set_color(COLOR_DIVIDER); self.ax.spines['left'].set_color(COLOR_DIVIDER)
                self.ax.grid(color=COLOR_DIVIDER, alpha=0.3)
                
                # Re-initialize the line objects
                self.line, self.fill = None, None
                self._setup_matplotlib_lines()
                self.canvas_mpl.draw_idle()

        # 2. Update Stats Widgets (Ensure global KPIs refresh)
        self._refresh_canvas()
            
        self.ui_update_job = self.after(1000, self._start_ui_loop)
