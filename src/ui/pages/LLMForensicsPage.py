# import customtkinter as ctk
# from tkinter import messagebox, filedialog, Canvas, simpledialog
# import os
# import threading
# import time
# import json
# from datetime import datetime, timedelta
# from typing import Optional, List, Dict
# from pydantic import BaseModel, Field
# # CRITICAL FIX: Import Enum
# from enum import Enum 

# # --- Import project modules ---
# from database_manager import get_db_instance
# from config import *
# from modern_components import ModernComponents

# # Assuming llm_service.py is correctly set up to export these structures
# try:
#     from llm_service import (
#         get_llm_service, 
#         LogAnalysis, 
#         WebSecurityEvent, 
#         WebTrafficPattern, 
#         SeverityLevel, 
#         AttackType,
#         LogID,
#         IPAddress,
#         ResponseCode
#     )
# except ImportError:
#     # --- Mock Service (Fallback) ---
#     class SeverityLevel(str, Enum): CRITICAL, HIGH, MEDIUM, LOW, INFO = "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
#     class AttackType(str, Enum): SQL_INJECTION, UNKNOWN = "SQL_INJECTION", "UNKNOWN"
#     class LogID(BaseModel): log_id: str = "N/A"
#     class IPAddress(BaseModel): ip_address: str = "N/A"
#     class ResponseCode(BaseModel): response_code: str = "N/A"
#     class WebTrafficPattern(BaseModel): url_path: str = "/default"; http_method: str = "GET"; hits_count: int = 0; response_codes: Dict[str, int] = {}; unique_ips: int = 0
#     class WebSecurityEvent(BaseModel): 
#         severity: SeverityLevel = SeverityLevel.INFO; event_type: str = "Unknown"; confidence_score: float = 0.0; url_pattern: str = ""; http_method: str = ""; possible_attack_patterns: List = []; recommended_actions: List = []; reasoning: str = ""
#         relevant_log_entry_ids: List = []; source_ips: List = []
#     class LogAnalysis(BaseModel): 
#         summary: str = "MOCK ANALYSIS: Service not found."; observations: List[str] = []; planning: List[str] = []; events: List[WebSecurityEvent] = []; traffic_patterns: List[WebTrafficPattern] = []; highest_severity: Optional[SeverityLevel] = SeverityLevel.INFO; requires_immediate_attention: bool = False
    
#     class MockAnalyzer:
#         def analyze_logs(self, logs: List[str]) -> LogAnalysis:
#             time.sleep(1)
#             return LogAnalysis()
            
#     class LLMService:
#         def get_analyzer(self): return MockAnalyzer()
    
#     def get_llm_service(): return LLMService()
#     # --- End Mock Service ---

# # DB
# DB = get_db_instance()

# # --- Material-like, accessible layout constants (8px grid) ---
# G = 8 
# INPUT_HEIGHT = 36
# BTN_HEIGHT = 40
# CARD_PAD = G*1.5

# class LLMForensicsPage(ctk.CTkFrame):
#     """
#     Implements the AI Forensic Page UI, handling input, threading the LLM analysis,
#     and displaying the structured Pydantic output.
#     """
#     def __init__(self, parent, controller):
#         super().__init__(parent, fg_color='transparent')
#         self.controller = controller
#         self.user_info = getattr(controller, 'user_info', {'id': None})

#         # core services
#         self.llm_service = get_llm_service()
#         self.analyzer = self.llm_service.get_analyzer() 
#         self.current_analysis: Optional[LogAnalysis] = None
#         self.analysis_history: List[Dict] = []

#         # state
#         self.log_limit = ctk.StringVar(value='500') 
#         self.start_date = ctk.StringVar(value=datetime.now().strftime('%Y-%m-%d'))
#         self.end_date = ctk.StringVar(value=datetime.now().strftime('%Y-%m-%d'))
#         self.source_type = ctk.StringVar(value='Historical DB Logs')
#         self.file_path = ctk.StringVar(value='')
#         self.file_limit = ctk.StringVar(value='500') 

#         # fonts (use config tokens)
#         self.H1 = (FONT_FAMILY, 20, 'bold')
#         self.H2 = (FONT_FAMILY, 16, 'bold') 
#         self.BODY = (FONT_FAMILY, 14) 
#         self.STATUS_COLORS = {
#             'info': COLOR_TEXT_SECONDARY,
#             'success': COLOR_SUCCESS,
#             'error': COLOR_RED,
#         }

#         # main layout: left controls (narrow), right report (flex)
#         outer = ctk.CTkFrame(self, fg_color='transparent')
#         outer.pack(fill='both', expand=True, padx=G*2, pady=G*2)
#         outer.grid_columnconfigure(0, weight=1, minsize=360)
#         outer.grid_columnconfigure(1, weight=3)
#         outer.grid_rowconfigure(0, weight=1)

#         self._build_left_panel(outer).grid(row=0, column=0, sticky='nsew', padx=(0,G*2))
#         self._build_right_panel(outer).grid(row=0, column=1, sticky='nsew')

#         # small progress bar (subtle) under the panels
#         self.progress = ctk.CTkProgressBar(self, mode='indeterminate')
#         self.progress.pack(fill='x', padx=G*2, pady=(0,G*2))
#         self.progress.stop()

#         # initial load
#         self._load_analysis_history()

#     def stop_threads(self):
#         """Stops any background timers."""
#         pass

#     # ------------------ Left: Controls ------------------
#     def _build_left_panel(self, parent):
#         panel = ModernComponents.create_card(parent, fg_color=COLOR_ELEVATION_1)
#         panel.grid_columnconfigure(0, weight=1)

#         header = ctk.CTkLabel(panel, text='Forensic Controls', font=self.H1, text_color=COLOR_TEXT)
#         header.grid(row=0, column=0, sticky='w', padx=G*2, pady=(G*2, G))

#         # Source selector (group)
#         group = ctk.CTkFrame(panel, fg_color='transparent')
#         group.grid(row=1, column=0, sticky='ew', padx=G*2, pady=(0,G))
#         group.grid_columnconfigure(1, weight=1)

#         ctk.CTkLabel(group, text='Log Source:', font=self.H2).grid(row=0, column=0, sticky='w')
#         self.source_menu = ctk.CTkOptionMenu(group, values=['Historical DB Logs','Local File'], variable=self.source_type, command=self._on_source_change, height=INPUT_HEIGHT, font=self.BODY, fg_color=COLOR_ELEVATION_2)
#         self.source_menu.grid(row=0, column=1, sticky='ew', padx=(G,0))

#         # dynamic input card
#         self.input_card = ctk.CTkFrame(panel, fg_color=COLOR_BG, corner_radius=UI_SETTINGS['corner_radius'])
#         self.input_card.grid(row=2, column=0, sticky='ew', padx=G*2, pady=(0,G*2))
#         self.input_card.grid_columnconfigure(0, weight=1)

#         self._on_source_change(self.source_type.get()) # Initialize card content

#         # history title
#         ctk.CTkLabel(panel, text='Recent Analyses', font=self.H2, text_color=COLOR_TEXT).grid(row=3, column=0, sticky='w', padx=G*2, pady=(0,G))
        
#         # --- FIX: Corrected variable name 'self.history_frame' instead of 'selftk' ---
#         self.history_frame = ctk.CTkScrollableFrame(panel, fg_color='transparent', corner_radius=UI_SETTINGS['corner_radius']-4)
#         self.history_frame.grid(row=4, column=0, sticky='nsew', padx=G*2, pady=(0,G*2))
        
#         # --- FIX: Changed 'card' to 'panel' ---
#         panel.grid_rowconfigure(4, weight=1)

#         return panel

#     def _on_source_change(self, choice):
#         # reset card
#         for w in self.input_card.winfo_children(): w.destroy()

#         if choice == 'Historical DB Logs':
#             # Row 0: Last N Logs (Full Width)
#             limit_frame = ctk.CTkFrame(self.input_card, fg_color='transparent')
#             limit_frame.grid(row=0, column=0, sticky='ew', padx=G, pady=G)
#             limit_frame.grid_columnconfigure(1, weight=1)

#             ctk.CTkLabel(limit_frame, text='Last N logs:', font=self.BODY).grid(row=0, column=0, sticky='w')
#             self.limit_entry = ctk.CTkEntry(limit_frame, textvariable=self.log_limit, height=INPUT_HEIGHT, font=self.BODY, placeholder_text='Analyze last N lines')
#             self.limit_entry.grid(row=0, column=1, sticky='ew', padx=(G,0))

#             # Row 1: Date range row
#             dr = ctk.CTkFrame(self.input_card, fg_color='transparent')
#             dr.grid(row=1, column=0, sticky='ew', padx=G, pady=(0,G))
#             dr.grid_columnconfigure((0, 1), weight=1)

#             self.start_date_btn = ctk.CTkButton(
#                 dr, text=self.start_date.get() or "Start Date (YYYY-MM-DD)", height=INPUT_HEIGHT, font=self.BODY,
#                 fg_color=COLOR_ELEVATION_2, text_color=COLOR_TEXT_SECONDARY,
#                 hover_color=COLOR_ELEVATION_3,
#                 command=lambda: self._open_date_input(self.start_date, self.start_date_btn)
#             )
#             self.start_date_btn.grid(row=0, column=0, sticky='ew', padx=(0, G))
            
#             self.end_date_btn = ctk.CTkButton(
#                 dr, text=self.end_date.get() or "End Date (YYYY-MM-DD)", height=INPUT_HEIGHT, font=self.BODY,
#                 fg_color=COLOR_ELEVATION_2, text_color=COLOR_TEXT_SECONDARY,
#                 hover_color=COLOR_ELEVATION_3,
#                 command=lambda: self._open_date_input(self.end_date, self.end_date_btn)
#             )
#             self.end_date_btn.grid(row=0, column=1, sticky='ew', padx=(G, 0))
            
#             # Actions row (primary only)
#             actions = ctk.CTkFrame(self.input_card, fg_color='transparent')
#             actions.grid(row=2, column=0, sticky='ew', padx=G, pady=(0,G))
#             actions.grid_columnconfigure(0, weight=1)

#             self.run_btn = ctk.CTkButton(actions, text='Run Analysis (DB) 🚀', height=BTN_HEIGHT, font=self.BODY, fg_color=COLOR_PRIMARY, hover_color=COLOR_PRIMARY_VARIANT, command=self._run_analysis_threaded)
#             self.run_btn.grid(row=0, column=0, sticky='ew')

#         else:
#             # File drop area with clear affordance
#             ctk.CTkLabel(self.input_card, text='Analyze Local File:', font=self.BODY).grid(row=0, column=0, sticky='w', padx=G, pady=(G,0))

#             # Row 1: File Limit (Full Width)
#             limit_frame = ctk.CTkFrame(self.input_card, fg_color='transparent')
#             limit_frame.grid(row=1, column=0, sticky='ew', padx=G, pady=G)
#             limit_frame.grid_columnconfigure(1, weight=1)

#             ctk.CTkLabel(limit_frame, text='Last N lines:', font=self.BODY).grid(row=0, column=0, sticky='w')
#             self.file_limit_entry = ctk.CTkEntry(limit_frame, textvariable=self.file_limit, height=INPUT_HEIGHT, font=self.BODY, placeholder_text='Default 500 lines')
#             self.file_limit_entry.grid(row=0, column=1, sticky='ew', padx=(G,0))
            
#             # Row 2: Drop Zone
#             drop = ctk.CTkFrame(self.input_card, fg_color=COLOR_ELEVATION_2, corner_radius=UI_SETTINGS['corner_radius'])
#             drop.grid(row=2, column=0, sticky='ew', padx=G, pady=(G,0))
#             drop.grid_columnconfigure(0, weight=1)
#             drop.grid_rowconfigure(0, weight=1)

#             self.drop_canvas = Canvas(drop, height=96, bg=COLOR_ELEVATION_2, highlightthickness=0)
#             self.drop_canvas.grid(row=0, column=0, sticky='nsew')
#             self.drop_canvas.bind('<Button-1>', lambda e: self._select_local_file())
#             self._update_drop_canvas_label()

#             # Actions row (primary only)
#             file_actions = ctk.CTkFrame(self.input_card, fg_color='transparent')
#             file_actions.grid(row=3, column=0, sticky='ew', padx=G, pady=(G, G))
#             file_actions.grid_columnconfigure(0, weight=1)

#             self.run_btn = ctk.CTkButton(file_actions, text='Run Analysis (File) 💾', height=BTN_HEIGHT, font=self.BODY, fg_color=COLOR_PRIMARY, hover_color=COLOR_PRIMARY_VARIANT, command=self._run_analysis_threaded)
#             self.run_btn.grid(row=0, column=0, sticky='ew')

#         # small status beneath inputs
#         self.status_label = ctk.CTkLabel(self.input_card, text='Status: Ready', font=self.BODY, text_color=COLOR_TEXT_SECONDARY)
#         status_row = 3 if choice == 'Local File' else 4
#         self.status_label.grid(row=status_row, column=0, sticky='w', padx=G, pady=(G,G))

#     def _open_date_input(self, date_var, date_btn):
#         """Simulates opening a calendar picker using a simple dialog for date input."""
#         current_date = date_var.get()
#         new_date = simpledialog.askstring("Date Input", "Enter date (YYYY-MM-DD):", initialvalue=current_date, parent=self)
        
#         if new_date:
#             try:
#                 datetime.strptime(new_date, '%Y-%m-%d')
#                 date_var.set(new_date)
#                 date_btn.configure(text=new_date, text_color=COLOR_TEXT)
#             except ValueError:
#                 messagebox.showerror("Error", "Invalid date format. Use YYYY-MM-DD.", parent=self)


#     def _update_drop_canvas_label(self):
#         if not hasattr(self, 'drop_canvas'): return
#         self.drop_canvas.delete('all')
#         w = self.drop_canvas.winfo_reqwidth() or 420
#         h = self.drop_canvas.winfo_reqheight() or 96
#         filename = os.path.basename(self.file_path.get())
#         if filename:
#             self.drop_canvas.create_text(w/2, h/3, text='File selected', font=self.H2, fill=COLOR_TEXT)
#             self.drop_canvas.create_text(w/2, h*2/3, text=filename, font=self.BODY, fill=COLOR_TEXT_SECONDARY)
#         else:
#             self.drop_canvas.create_text(w/2, h/3, text='Click to choose file', font=self.H2, fill=COLOR_TEXT_SECONDARY)
#             self.drop_canvas.create_text(w/2, h*2/3, text='Note: Large files may take time', font=self.BODY, fill=COLOR_TEXT_SECONDARY)

#     def _select_local_file(self):
#         path = filedialog.askopenfilename(title='Select log file', filetypes=[('Log','*.log *.txt'),('All','*.*')])
#         if path:
#             self.file_path.set(path)
#             self._update_drop_canvas_label()

#     # ------------------ Right: Report ------------------
#     def _build_right_panel(self, parent):
#         # We use a wrapper card that contains the header, tabs, and the footer
#         wrapper_card = ModernComponents.create_card(parent, fg_color=COLOR_ELEVATION_1)
#         wrapper_card.grid_columnconfigure(0, weight=1)
#         wrapper_card.grid_rowconfigure(1, weight=1) # Tabs area expands
        
#         # --- 1. Header (Title + Badge) ---
#         summary_header = ctk.CTkFrame(wrapper_card, fg_color='transparent')
#         summary_header.grid(row=0, column=0, sticky='ew', padx=G*2, pady=G*2)
#         summary_header.grid_columnconfigure(0, weight=1)

#         self.title_label = ctk.CTkLabel(summary_header, text='LLM Forensics Report', font=self.H1, text_color=COLOR_TEXT)
#         self.title_label.grid(row=0, column=0, sticky='w')

#         # Severity badge (prominent)
#         self.severity_badge = ModernComponents.create_badge(summary_header, text='N/A', badge_type='info')
#         self.severity_badge.grid(row=0, column=1, sticky='e')
        
#         # --- 2. Main Tabbed Output Console ---
#         self.report_tabview = ctk.CTkTabview(
#             wrapper_card, fg_color=COLOR_BG # Tabs background is slightly darker
#         )
#         # IMPORTANT: Row 1 handles the expanding report view
#         self.report_tabview.grid(row=1, column=0, sticky="nsew", padx=G*3, pady=(0, G*2))
        
#         self.tab_summary = self.report_tabview.add('📋 Summary')
#         self.tab_events = self.report_tabview.add('🚨 Events')
#         self.tab_traffic = self.report_tabview.add('📈 Traffic')
        
#         self._build_summary_tab(self.tab_summary)
#         self._build_events_tab(self.tab_events)
#         self._build_traffic_tab(self.tab_traffic)
        
#         # --- 3. Footer (Action Buttons) ---
#         self._build_report_footer(wrapper_card).grid(row=2, column=0, sticky='ew', padx=G*2, pady=(0, G*2))

#         return wrapper_card

#     def _build_report_footer(self, parent):
#         """Creates the dedicated, prominent footer bar for actions."""
#         footer_frame = ctk.CTkFrame(parent, fg_color=COLOR_ELEVATION_3)
#         footer_frame.grid_columnconfigure((0,1,2,3), weight=1)
        
#         btn_font = (FONT_FAMILY, 14)
        
#         self.btn_export = ctk.CTkButton(footer_frame, text='💾 Export (JSON)', height=BTN_HEIGHT - 4, font=btn_font, command=self._export_current_report_json)
#         self.btn_export.grid(row=0, column=0, sticky='ew', padx=(G*2, G), pady=G)
        
#         self.btn_copy = ctk.CTkButton(footer_frame, text='📋 Copy Summary', height=BTN_HEIGHT - 4, font=btn_font, command=self._copy_summary)
#         self.btn_copy.grid(row=0, column=1, sticky='ew', padx=G, pady=G)
        
#         self.btn_filter = ctk.CTkButton(footer_frame, text='⚙️ Filter Events', height=BTN_HEIGHT - 4, font=btn_font, command=self._open_filter_dialog)
#         self.btn_filter.grid(row=0, column=2, sticky='ew', padx=G, pady=G)
        
#         self.btn_refresh = ctk.CTkButton(footer_frame, text='🔄 Refresh History', height=BTN_HEIGHT - 4, font=btn_font, command=self._load_analysis_history)
#         self.btn_refresh.grid(row=0, column=3, sticky='ew', padx=(G, G*2), pady=G)
        
#         return footer_frame


#     def _build_summary_tab(self, tab):
#         tab.grid_columnconfigure(0, weight=1)
#         tab.grid_rowconfigure(2, weight=1)
#         tab.grid_rowconfigure(4, weight=1)

#         # 1. Analysis Summary Text
#         ctk.CTkLabel(tab, text="Analysis Summary:", font=self.H2, text_color=COLOR_TEXT).grid(row=0, column=0, sticky="w", padx=G, pady=(G, G/2))
#         summary_card = ModernComponents.create_card(tab, fg_color=COLOR_ELEVATION_2, corner_radius=UI_SETTINGS['corner_radius']-4)
#         summary_card.grid(row=1, column=0, sticky="nsew", padx=G, pady=(0, G))
        
#         self.summary_box = ctk.CTkTextbox(summary_card, height=120, font=self.BODY, fg_color=COLOR_BG, corner_radius=UI_SETTINGS['corner_radius']-4) 
#         self.summary_box.pack(fill='both', expand=True, padx=G, pady=G)
#         self.summary_box.insert('1.0', 'Run an analysis to view summary')
#         self.summary_box.configure(state='disabled')
        
#         # 2. Key Performance Indicators (KPI Grid)
#         self.kpi_frame = ctk.CTkFrame(tab, fg_color=COLOR_ELEVATION_2, corner_radius=UI_SETTINGS['corner_radius']-4)
#         self.kpi_frame.grid(row=2, column=0, sticky="ew", padx=G, pady=G)
#         self.kpi_frame.grid_columnconfigure((0,1,2,3), weight=1)
        
#         self.lbl_events_count = self._create_kpi(self.kpi_frame, 'TOTAL EVENTS', '0', 0, COLOR_PRIMARY)
#         self.lbl_unique_ips = self._create_kpi(self.kpi_frame, 'UNIQUE IPs', '0', 1, COLOR_PRIMARY)
#         self.lbl_review_required = self._create_kpi(self.kpi_frame, 'HUMAN REVIEW', 'NO', 2, COLOR_SUCCESS)
#         self.lbl_highest_sev = self._create_kpi(self.kpi_frame, 'HIGHEST SEVERITY', 'INFO', 3, COLOR_INFO)


#         # 3. Planning & Observations Box
#         ctk.CTkLabel(tab, text="Planning & Observations:", font=self.H2, text_color=COLOR_TEXT).grid(row=3, column=0, sticky="w", padx=G, pady=(G/2, G/2))
#         obs_card = ModernComponents.create_card(tab, fg_color=COLOR_ELEVATION_2, corner_radius=UI_SETTINGS['corner_radius']-4)
#         obs_card.grid(row=4, column=0, sticky="nsew", padx=G, pady=(0, G))
        
#         self.obs_box = ctk.CTkTextbox(obs_card, height=150, font=self.BODY, fg_color=COLOR_BG, corner_radius=UI_SETTINGS['corner_radius']-4) 
#         self.obs_box.pack(fill='both', expand=True, padx=G, pady=G)
#         self.obs_box.configure(state='disabled')

#     def _create_kpi(self, parent, title: str, value: str, column: int, color: str):
#         frame = ctk.CTkFrame(parent, fg_color="transparent")
#         frame.grid(row=0, column=column, sticky='nsew', padx=G, pady=G)
        
#         ctk.CTkLabel(frame, text=title, font=self.BODY, text_color=COLOR_TEXT_SECONDARY).pack(pady=(G, 0), anchor='center')
#         lbl_value = ctk.CTkLabel(frame, text=value, font=self.H1, text_color=color)
#         lbl_value.pack(pady=(0, G), anchor='center')
        
#         return lbl_value
    
#     def _build_events_tab(self, tab):
#         tab.grid_columnconfigure(0, weight=1)
#         tab.grid_rowconfigure(0, weight=1)
        
#         self.events_scroll = ctk.CTkScrollableFrame(tab, fg_color='transparent', corner_radius=UI_SETTINGS['corner_radius']-4)
#         self.events_scroll.grid(row=0, column=0, sticky="nsew")
#         ctk.CTkLabel(self.events_scroll, text="No Security Events Found.", text_color=COLOR_TEXT_SECONDARY).pack(pady=G*2)
        
#     def _build_traffic_tab(self, tab):
#         tab.grid_columnconfigure(0, weight=1)
#         tab.grid_rowconfigure(0, weight=1)
        
#         self.traffic_scroll = ctk.CTkScrollableFrame(tab, fg_color='transparent', corner_radius=UI_SETTINGS['corner_radius']-4)
#         self.traffic_scroll.grid(row=0, column=0, sticky="nsew")
#         ctk.CTkLabel(self.traffic_scroll, text="No Traffic Patterns Identified.", text_color=COLOR_TEXT_SECONDARY).pack(pady=G*2)


#     # --- Analysis Execution ---
#     def _run_analysis_threaded(self):
#         logs_to_analyze: List[str] = []
#         log_reference = ""
#         start_dt, end_dt = None, None
        
#         if self.source_type.get() == "Historical DB Logs":
#             try:
#                 limit = int(self.log_limit.get() or "500")
#                 if limit <= 0 or limit > 5000: raise ValueError("Limit must be between 1 and 5000.") 
                
#                 start_dt = datetime.strptime(self.start_date.get(), '%Y-%m-%d') if self.start_date.get() else None
#                 end_dt_raw = datetime.strptime(self.end_date.get(), '%Y-%m-%d') if self.end_date.get() else None
#                 if end_dt_raw: end_dt = end_dt_raw + timedelta(days=1)
                
#                 logs_to_analyze = DB.fetch_logs_for_analysis(limit=limit, start_date=start_dt, end_date=end_dt)
#                 log_reference = f"Last {len(logs_to_analyze)} DB Logs"
#             except ValueError as e:
#                 messagebox.showwarning("Input Error", str(e), parent=self); return
        
#         elif self.source_type.get() == "Local File":
#             path = self.file_path.get()
#             if not path or not os.path.exists(path):
#                  messagebox.showwarning("File Error", "Selected file does not exist.", parent=self); return
            
#             try:
#                 limit = int(self.file_limit.get() or "500")
#                 if limit <= 0: raise ValueError('Limit must be a positive number.')
                
#                 with open(path, 'r', encoding='utf-8', errors='ignore') as f:
#                     all_lines = [l.strip() for l in f.readlines() if l.strip()]
                    
#                     if len(all_lines) > limit:
#                         logs_to_analyze = all_lines[-limit:] 
#                     else:
#                          logs_to_analyze = all_lines
                         
#                 log_reference = os.path.basename(path)

#             except ValueError as e:
#                  messagebox.showwarning("Input Error", f"File limit error: {e}", parent=self); return
#             except Exception as e:
#                 messagebox.showerror("File Error", f"Could not read file: {e}", parent=self); return

#         if not logs_to_analyze:
#              messagebox.showinfo("No Data", "No logs available to analyze.", parent=self); return
             
#         self._set_loading_state(True, f"Running analysis on {len(logs_to_analyze)} entries...")
        
#         threading.Thread(target=self._analysis_worker, args=(logs_to_analyze, log_reference), daemon=True).start()

#     def _analysis_worker(self, raw_logs: List[str], log_reference: str):
#         """Worker thread to run the LLM analysis."""
#         try:
#             analyzer = self.llm_service.get_analyzer()
#             analysis_result = analyzer.analyze_logs(raw_logs)

#             # --- SAFE RECOMMENDATION EXTRACTION ---
#             # Collect recommendations from all events (since they don't exist at top level)
#             all_recommendations = []
#             if analysis_result.events:
#                 for event in analysis_result.events:
#                     all_recommendations.extend(event.recommended_actions)
            
#             # Create string for DB
#             rec_text = "; ".join(all_recommendations) if all_recommendations else "No actions suggested."

#             # Save to DB
#             user_id = self.user_info.get('id')
#             db_id = DB.insert_forensic_analysis(
#                 log_snippet="\n".join(raw_logs[:5]), 
#                 summary=analysis_result.summary,
#                 recommendation=rec_text,
#                 log_reference=log_reference,
#                 user_id=user_id
#             )
            
#             # Update UI
#             self.after(0, lambda: self._handle_analysis_complete(db_id, analysis_result))

#         except Exception as e:
#             self.after(0, lambda: self._set_loading_state(False, f"Analysis failed: {e}", status="error"))
#             print(f"LLM FORENSICS CRITICAL ERROR: {e}")

#     def _handle_analysis_complete(self, db_id: int, analysis: LogAnalysis):
#         self.progress.stop()
#         self.current_analysis = analysis
#         status = f'Report #{db_id} saved' if db_id!=-1 else 'Analysis complete (not saved)'
#         self._set_loading_state(False, status, status='success')
#         self._update_report_display(analysis)
#         self._load_analysis_history()

#     # ------------------ Report Rendering ------------------
#     def _update_report_display(self, analysis: LogAnalysis):
#         sev = analysis.highest_severity.value if analysis.highest_severity else 'INFO'
        
#         self.title_label.configure(text=f'LLM Forensics — {sev}')
#         self.severity_badge.configure(text=sev, fg_color=SEV_COLOR.get(sev, COLOR_INFO))

#         # 1. Update Summary Tab
#         self._set_textbox(self.summary_box, analysis.summary)
#         obs_text = 'OBSERVATIONS:\n' + '\n'.join(f'• {o}' for o in analysis.observations)
#         plan_text = '\n\nPLANNING:\n' + '\n'.join(f'• {p}' for p in analysis.planning)
#         self._set_textbox(self.obs_box, obs_text + plan_text)
        
#         event_count = len(analysis.events)
#         unique_ips = sum(len(p.source_ips) for p in analysis.events) 
#         review_required = analysis.requires_immediate_attention
#         review_color = COLOR_ERROR if review_required else COLOR_SUCCESS
#         sev_color = SEV_COLOR.get(sev, COLOR_INFO)
        
#         self.lbl_events_count.configure(text=str(event_count), text_color=COLOR_PRIMARY)
#         self.lbl_unique_ips.configure(text=str(unique_ips), text_color=COLOR_PRIMARY)
#         self.lbl_review_required.configure(text='YES' if review_required else 'NO', text_color=review_color)
#         self.lbl_highest_sev.configure(text=sev, text_color=sev_color)

#         # 2. Events Tab
#         for w in list(self.events_scroll.winfo_children()): w.destroy()
#         if not analysis.events:
#             ctk.CTkLabel(self.events_scroll, text='No security events detected', text_color=COLOR_TEXT_SECONDARY).pack(pady=G)
#         else:
#             for i,e in enumerate(analysis.events, start=1):
#                 self._render_event_card(self.events_scroll, e, i)

#         # 3. Traffic Tab
#         for w in list(self.traffic_scroll.winfo_children()): w.destroy()
#         if not analysis.traffic_patterns:
#             ctk.CTkLabel(self.traffic_scroll, text='No traffic patterns', text_color=COLOR_TEXT_SECONDARY).pack(pady=G)
#         else:
#             for p in analysis.traffic_patterns:
#                 self._render_traffic_card(self.traffic_scroll, p)

#     def _set_textbox(self, box, text):
#         box.configure(state='normal')
#         box.delete('1.0', 'end')
#         box.insert('1.0', text)
#         box.configure(state='disabled')

#     def _render_event_card(self, parent, event: WebSecurityEvent, idx: int):
#         sev_color = SEV_COLOR.get(event.severity.value, COLOR_WARNING)
        
#         card_wrapper = ctk.CTkFrame(parent, fg_color='transparent')
#         card_wrapper.pack(fill='x', padx=G, pady=(0,G))

#         card = ModernComponents.create_card(card_wrapper, fg_color=COLOR_ELEVATION_2)
#         card.pack(fill='both', expand=True)
#         card.grid_columnconfigure(1, weight=1)
        
#         sev_bar = ctk.CTkFrame(card, fg_color=sev_color, width=6, corner_radius=0)
#         sev_bar.grid(row=0, column=0, rowspan=4, sticky='ns')

#         content_frame = ctk.CTkFrame(card, fg_color='transparent')
#         content_frame.grid(row=0, column=1, rowspan=4, sticky='nsew', padx=G, pady=G)
#         content_frame.grid_columnconfigure(0, weight=1)

#         header = ctk.CTkFrame(content_frame, fg_color='transparent')
#         header.grid(row=0, column=0, sticky='ew', pady=(G, G/2))
#         header.grid_columnconfigure(1, weight=1)

#         icon = '🚨' if event.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH] else '⚠️'
#         ctk.CTkLabel(header, text=f'{icon} Event #{idx}', font=self.H2, text_color=COLOR_TEXT_SECONDARY).grid(row=0, column=0, sticky='w')
#         ctk.CTkLabel(header, text=event.event_type, font=self.H2, text_color=sev_color).grid(row=0, column=1, sticky='w', padx=G)
        
#         ctk.CTkLabel(header, text=event.severity.value, font=self.BODY, fg_color=sev_color, text_color=COLOR_BG, corner_radius=6, padx=8, pady=4).grid(row=0, column=2, sticky='e')

#         meta = ctk.CTkFrame(content_frame, fg_color='transparent')
#         meta.grid(row=1, column=0, sticky='ew', pady=G/2)
#         meta.grid_columnconfigure((0,2), weight=1)
#         meta.grid_columnconfigure((1,3), weight=2)

#         def add_detail(key, value, row, col):
#              ctk.CTkLabel(meta, text=key+':', font=self.BODY, text_color=COLOR_TEXT_SECONDARY).grid(row=row, column=col, sticky='w', padx=G/2, pady=1)
#              ctk.CTkLabel(meta, text=str(value), font=self.BODY).grid(row=row, column=col+1, sticky='w', padx=(G,0), pady=1)

#         add_detail('Confidence', f'{event.confidence_score*100:.0f}%', 0, 0)
#         add_detail('URL', event.url_pattern, 0, 2)
#         add_detail('Method', event.http_method, 1, 0)
#         add_detail('Attacks', ', '.join([a.value for a in event.possible_attack_patterns]) or 'N/A', 1, 2)

#         ctk.CTkLabel(content_frame, text='Reasoning:', font=self.H2, text_color=COLOR_TEXT_SECONDARY).grid(row=2, column=0, sticky='w', pady=(G, 0))
#         ctk.CTkLabel(content_frame, text=event.reasoning, font=self.BODY, wraplength=700, justify='left').grid(row=3, column=0, sticky='ew', pady=(0, G))

#         actions = ctk.CTkFrame(content_frame, fg_color=COLOR_BG)
#         actions.grid(row=4, column=0, sticky='ew', pady=(G, G/2))

#         ctk.CTkLabel(actions, text='Recommended Actions', font=self.BODY, text_color=COLOR_TEXT_SECONDARY).pack(side='left', padx=(G, G*2), pady=G/2)
        
#         for a in event.recommended_actions:
#             icon = '🛑' if 'block' in a.lower() else '⚙️'
#             b = ctk.CTkButton(actions, text=f'{icon} {a}', height=32, font=self.BODY, fg_color=COLOR_PRIMARY, hover_color=COLOR_PRIMARY_VARIANT, command=lambda act=a: messagebox.showinfo('Action', f'Execute: {act}', parent=self))
#             b.pack(side='left', padx=(0,G), pady=G/2)

#     def _render_traffic_card(self, parent, pattern: WebTrafficPattern):
#         card_wrapper = ctk.CTkFrame(parent, fg_color='transparent')
#         card_wrapper.pack(fill='x', padx=G, pady=(0,G))

#         card = ModernComponents.create_card(card_wrapper, fg_color=COLOR_ELEVATION_2)
#         card.pack(fill='x', expand=True, padx=G/2, pady=G/2)
#         card.grid_columnconfigure(0, weight=1)
        
#         header = ctk.CTkFrame(card, fg_color='transparent')
#         header.grid(row=0, column=0, sticky='ew', padx=G, pady=G)
#         header.grid_columnconfigure(0, weight=1)
#         header.grid_columnconfigure(2, weight=1)

#         ctk.CTkLabel(header, text=f'URL: {pattern.url_path}', font=self.H2, text_color=COLOR_TEXT).grid(row=0, column=0, sticky='w', padx=G, pady=(G, 0))
#         ctk.CTkLabel(header, text=f'Method: {pattern.http_method}', font=self.BODY, text_color=COLOR_TEXT_SECONDARY).grid(row=0, column=1, sticky='w', padx=G, pady=(G, 0))
#         ctk.CTkLabel(header, text=f'Total Hits: {pattern.hits_count:,}', font=self.H2, text_color=COLOR_PRIMARY).grid(row=0, column=2, sticky='e', padx=G, pady=(G, 0))

#         ctk.CTkLabel(header, text=f'Unique IPs: {pattern.unique_ips:,}', font=self.BODY, text_color=COLOR_TEXT_SECONDARY).grid(row=1, column=0, columnspan=3, sticky='w', padx=G)
        
#         chart_frame = ctk.CTkFrame(card, fg_color=COLOR_BG, corner_radius=UI_SETTINGS['corner_radius']-4, height=40)
#         chart_frame.grid(row=1, column=0, sticky='ew', padx=G, pady=(G, G))
#         chart_frame.grid_columnconfigure(0, weight=1)
        
#         chart_canvas = Canvas(chart_frame, bg=COLOR_BG, highlightthickness=0, height=40)
#         chart_canvas.grid(row=0, column=0, sticky='nsew', padx=G, pady=G)
        
#         total_codes = sum(pattern.response_codes.values())
#         success_count = pattern.response_codes.get('200', 0)
#         failure_count = total_codes - success_count
        
#         chart_canvas.bind('<Configure>', lambda e, c=chart_canvas, s=success_count, f=failure_count, t=total_codes: self._draw_response_chart(c, s, f, t))

#     def _draw_response_chart(self, canvas, success_count, failure_count, total_codes):
#         if not canvas.winfo_exists(): return

#         canvas.delete("all")
#         w = canvas.winfo_width()
#         h = canvas.winfo_height()
#         bar_height = h - 10
        
#         if total_codes == 0: return

#         chart_w = w - 120
        
#         success_w = int((success_count / total_codes) * chart_w) 
#         failure_w = chart_w - success_w
        
#         x_start = 5
        
#         if success_w > 0:
#             canvas.create_rectangle(x_start, 5, x_start + success_w, 5 + bar_height, 
#                                      fill=COLOR_SUCCESS if 'COLOR_SUCCESS' in globals() else '#2ecc71', outline='')
#             x_start += success_w

#         if failure_w > 0:
#             canvas.create_rectangle(x_start, 5, x_start + failure_w, 5 + bar_height, 
#                                      fill=COLOR_ERROR if 'COLOR_ERROR' in globals() else '#e74c3c', outline='')
#             x_start += failure_w

#         text_x = chart_w + 10 
        
#         success_pct = f"{success_count/total_codes:.0%}"
#         failure_pct = f"{failure_count/total_codes:.0%}"
        
#         canvas.create_text(text_x, h/2, text=f"✅ {success_pct}", 
#                             fill=COLOR_SUCCESS if 'COLOR_SUCCESS' in globals() else '#2ecc71', anchor='w', font=self.BODY)
        
#         canvas.create_text(text_x + 50, h/2, text=f"❌ {failure_pct}", 
#                             fill=COLOR_ERROR if 'COLOR_ERROR' in globals() else '#e74c3c', anchor='w', font=self.BODY)


#     # ------------------ History ------------------
#     def _load_analysis_history(self):
#         for w in list(self.history_frame.winfo_children()): w.destroy()
        
#         try:
#             self.analysis_history = DB.fetch_forensic_analysis(limit=20)
#         except Exception as e:
#             ctk.CTkLabel(self.history_frame, text='Failed to load history.', text_color=COLOR_RED).pack(pady=G)
#             return

#         if not self.analysis_history:
#             ctk.CTkLabel(self.history_frame, text='No history yet — run your first analysis', text_color=COLOR_TEXT_SECONDARY).pack(pady=G)
#             return
            
#         for it in self.analysis_history:
#             self._history_item(it)

#     def _history_item(self, it: Dict):
#         row = ModernComponents.create_card(self.history_frame, fg_color=COLOR_ELEVATION_2)
#         row.pack(fill='x', padx=G, pady=(0,G))
        
#         row.grid_columnconfigure(0, weight=1)
#         row.grid_columnconfigure((1, 2), weight=0, minsize=40)

#         ts = it.get('timestamp', '')
#         try:
#             ts = datetime.fromisoformat(ts).strftime('%Y-%m-%d %H:%M')
#         except Exception:
#             pass
#         title = f"{ts} — {it.get('log_reference','Unknown')}"
        
#         summary_text = it.get('summary', 'No summary available')
#         recommendation_text = it.get('recommendation', 'N/A')
        
#         severity = recommendation_text.split(' ')[0].replace('.', '')
#         sev_color = SEV_COLOR.get(severity, COLOR_ACCENT)
        
#         ctk.CTkLabel(row, text=title, font=self.H2).grid(row=0, column=0, sticky='w', padx=G, pady=(G,0))
#         ctk.CTkLabel(row, text=summary_text[:60] + '...', font=self.BODY, text_color=COLOR_TEXT_SECONDARY).grid(row=1, column=0, sticky='w', padx=G, pady=(0,G))

#         btn_view = ctk.CTkButton(row, text='View', height=30, width=60, font=self.BODY, 
#                                  fg_color=COLOR_ACCENT, hover_color=COLOR_PRIMARY_VARIANT, 
#                                  command=lambda i=it: self._view_history_report(i))
#         btn_view.grid(row=0, column=1, rowspan=2, sticky='e', padx=(G, 0), pady=G)

#         btn_delete = ctk.CTkButton(row, text='❌', height=30, width=30, font=self.BODY, 
#                                 fg_color=COLOR_RED, hover_color=COLOR_ORANGE, 
#                                 text_color=COLOR_BG,
#                                 command=lambda report_id=it.get('id'): self._confirm_delete_report(report_id))
#         btn_delete.grid(row=0, column=2, rowspan=2, sticky='e', padx=G, pady=G)


#     def _confirm_delete_report(self, report_id):
#         if not report_id:
#             messagebox.showerror("Error", "Report ID not found.", parent=self)
#             return
            
#         if messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete report #{report_id}?", parent=self):
#             self._delete_report(report_id)

#     def _delete_report(self, report_id):
#         try:
#             DB.delete_forensic_analysis(report_id)
#             self._set_loading_state(False, f"Report #{report_id} deleted.", status='info')
#             self._load_analysis_history()
#         except Exception as e:
#             messagebox.showerror("DB Error", f"Failed to delete report: {e}", parent=self)
#             print(f"DB Error deleting forensic analysis: {e}")


#     def _view_history_report(self, item: Dict):
#         summary_text = item.get('summary', 'No summary available')
#         recommendation_text = item.get('recommendation', 'N/A')
#         log_snippet = item.get('log_snippet', 'N/A')
        
#         self.title_label.configure(text=f"Historical Report #{item['id']}")
        
#         self._set_textbox(self.summary_box, summary_text)
#         self._set_textbox(self.obs_box, f"RECOMMENDATIONS:\n{recommendation_text}\n\nLOG SNIPPET:\n{log_snippet}")

#         self.severity_badge.configure(text='AUDIT', fg_color=COLOR_INFO)

#     # ------------------ Utilities ------------------
#     def _set_loading_state(self, is_loading: bool, message: str, status: str='info'):
#         try:
#             if is_loading:
#                 self.run_btn.configure(text='Analyzing...', fg_color=COLOR_WARNING, hover_color=COLOR_WARNING, state='disabled')
#                 self.progress.start()
#             else:
#                 self.run_btn.configure(text='Run Analysis (DB) 🚀' if self.source_type.get() == 'Historical DB Logs' else 'Run Analysis (File) 💾', fg_color=COLOR_PRIMARY, hover_color=COLOR_PRIMARY_VARIANT, state='normal')
#                 self.progress.stop()

#             col = self.STATUS_COLORS.get(status, COLOR_TEXT_SECONDARY)
#             self.status_label.configure(text=message, text_color=col)
            
#         except Exception:
#             pass
            
#     def _export_current_report_json(self):
#         if not self.current_analysis:
#             messagebox.showinfo('No report', 'No report to export', parent=self); return
#         p = filedialog.asksaveasfilename(defaultextension='.json', filetypes=[('JSON','*.json')])
#         if not p: return
#         try:
#             with open(p,'w',encoding='utf-8') as f:
#                 json.dump(self.current_analysis.dict(), f, default=str, indent=2)
#             messagebox.showinfo('Exported', f'Exported to {p}', parent=self)
#         except Exception as e:
#             messagebox.showerror('Export failed', str(e), parent=self)

#     def _copy_summary(self):
#         if not self.current_analysis:
#             messagebox.showinfo('No summary', 'No summary to copy', parent=self); return
#         try:
#             self.clipboard_clear(); self.clipboard_append(self.current_analysis.summary)
#             messagebox.showinfo('Copied', 'Summary copied to clipboard', parent=self)
#         except Exception as e:
#             messagebox.showerror('Copy failed', str(e), parent=self)

#     def _open_filter_dialog(self):
#         if not self.current_analysis or not self.current_analysis.events:
#             messagebox.showinfo('No events', 'No events to filter', parent=self); return
#         top = ctk.CTkToplevel(self)
#         top.title('Filter Events')
#         top.geometry('360x180')
#         ctk.CTkLabel(top, text='Minimum Severity', font=self.BODY).pack(pady=G)
#         menu = ctk.CTkOptionMenu(top, values=[s.value for s in SeverityLevel], command=lambda v: self._filter_events_by_severity(v, top))
#         menu.pack(pady=G)
#         ctk.CTkButton(top, text='Close', command=top.destroy).pack(pady=G)

#     def _filter_events_by_severity(self, level: str, window=None):
#         try:
#             lvl_index = [l.value for l in SeverityLevel].index(level)
#         except ValueError:
#             lvl_index = 0
#         filtered = [e for e in self.current_analysis.events if list(SeverityLevel).index(e.severity) <= lvl_index]
#         for w in list(self.events_scroll.winfo_children()): w.destroy()
#         if not filtered:
#             ctk.CTkLabel(self.events_scroll, text='No events match filter', text_color=COLOR_TEXT_SECONDARY).pack(pady=G)
#         else:
#             for i,e in enumerate(filtered, start=1):
#                 self._render_event_card(self.events_scroll, e, i)
#         if window: window.destroy()

#  # --- NEW: Direct Input Handler ---
#     def load_log_snippet(self, log_text: str):
#         """
#         Called by the controller to load a specific log snippet (e.g. from Alerts page).
#         Sets up the UI to analyze this snippet as a 'Local File' (conceptually).
#         """
#         # 1. Switch Source to Local File (to hide DB controls)
#         self.source_type.set('Local File')
#         self._on_source_change('Local File')
        
#         # 2. Create a temporary file for this snippet (since our worker expects a file/list)
#         # Ideally, we refactor _run_analysis_threaded to take text directly, but temp file is safer/easier
#         try:
#             temp_path = os.path.join(os.path.dirname(__file__), "temp_alert_analysis.log")
#             with open(temp_path, "w", encoding="utf-8") as f:
#                 f.write(log_text)
            
#             self.file_path.set(temp_path)
#             self._update_drop_canvas_label()
            
#             # 3. Auto-start analysis
#             # We use a small delay to let the UI update
#             self.after(500, self._run_analysis_threaded)
            
#         except Exception as e:
#             messagebox.showerror("Error", f"Failed to load alert data: {e}")



import customtkinter as ctk
from tkinter import messagebox, filedialog, Canvas, simpledialog
import os
import threading
import time
import json
from datetime import datetime, timedelta
from typing import Optional, List, Dict
from pydantic import BaseModel, Field
# CRITICAL FIX: Import Enum
from enum import Enum 

# --- Import project modules ---
from src.backend.database_manager import get_db_instance
from src.config import *
from src.ui.components.modern_components import ModernComponents

# Assuming llm_service.py is correctly set up to export these structures
try:
    from src.backend.llm_service import (
        get_llm_service, 
        LogAnalysis, 
        WebSecurityEvent, 
        WebTrafficPattern, 
        SeverityLevel, 
        AttackType,
        LogID,
        IPAddress,
        ResponseCode
    )
except ImportError:
    # --- Mock Service (Fallback) ---
    class SeverityLevel(str, Enum): CRITICAL, HIGH, MEDIUM, LOW, INFO = "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
    class AttackType(str, Enum): SQL_INJECTION, UNKNOWN = "SQL_INJECTION", "UNKNOWN"
    class LogID(BaseModel): log_id: str = "N/A"
    class IPAddress(BaseModel): ip_address: str = "N/A"
    class ResponseCode(BaseModel): response_code: str = "N/A"
    class WebTrafficPattern(BaseModel): url_path: str = "/default"; http_method: str = "GET"; hits_count: int = 0; response_codes: Dict[str, int] = {}; unique_ips: int = 0
    class WebSecurityEvent(BaseModel): 
        severity: SeverityLevel = SeverityLevel.INFO; event_type: str = "Unknown"; confidence_score: float = 0.0; url_pattern: str = ""; http_method: str = ""; possible_attack_patterns: List = []; recommended_actions: List = []; reasoning: str = ""
        relevant_log_entry_ids: List = []; source_ips: List = []
    class LogAnalysis(BaseModel): 
        summary: str = "MOCK ANALYSIS: Service not found."; observations: List[str] = []; planning: List[str] = []; events: List[WebSecurityEvent] = []; traffic_patterns: List[WebTrafficPattern] = []; highest_severity: Optional[SeverityLevel] = SeverityLevel.INFO; requires_immediate_attention: bool = False
    
    class MockAnalyzer:
        def analyze_logs(self, logs: List[str]) -> LogAnalysis:
            time.sleep(1)
            return LogAnalysis()
            
    class LLMService:
        def get_analyzer(self): return MockAnalyzer()
    
    def get_llm_service(): return LLMService()
    # --- End Mock Service ---

# DB
DB = get_db_instance()

# --- Material-like, accessible layout constants (8px grid) ---
G = 8 
INPUT_HEIGHT = 36
BTN_HEIGHT = 40
CARD_PAD = G*1.5
TEMP_LOG_FILE = os.path.join(os.path.dirname(__file__), "temp_alert_analysis.log")

class LLMForensicsPage(ctk.CTkFrame):
    """
    Implements the AI Forensic Page UI, handling input, threading the LLM analysis,
    and displaying the structured Pydantic output.
    """
    def __init__(self, parent, controller):
        super().__init__(parent, fg_color='transparent')
        self.controller = controller
        self.user_info = getattr(controller, 'user_info', {'id': None})

        # core services
        self.llm_service = get_llm_service()
        self.analyzer = self.llm_service.get_analyzer() 
        self.current_analysis: Optional[LogAnalysis] = None
        self.analysis_history: List[Dict] = []

        # state
        self.log_limit = ctk.StringVar(value='500') 
        self.start_date = ctk.StringVar(value=datetime.now().strftime('%Y-%m-%d'))
        self.end_date = ctk.StringVar(value=datetime.now().strftime('%Y-%m-%d'))
        self.source_type = ctk.StringVar(value='Historical DB Logs')
        self.file_path = ctk.StringVar(value='')
        self.file_limit = ctk.StringVar(value='500') 

        # fonts (use config tokens)
        self.H1 = (FONT_FAMILY, 20, 'bold')
        self.H2 = (FONT_FAMILY, 16, 'bold') 
        self.BODY = (FONT_FAMILY, 14) 
        self.STATUS_COLORS = {
            'info': COLOR_TEXT_SECONDARY,
            'success': COLOR_SUCCESS,
            'error': COLOR_RED,
        }

        # main layout: left controls (narrow), right report (flex)
        outer = ctk.CTkFrame(self, fg_color='transparent')
        outer.pack(fill='both', expand=True, padx=G*2, pady=G*2)
        outer.grid_columnconfigure(0, weight=1, minsize=360)
        outer.grid_columnconfigure(1, weight=3)
        outer.grid_rowconfigure(0, weight=1)

        self._build_left_panel(outer).grid(row=0, column=0, sticky='nsew', padx=(0,G*2))
        self._build_right_panel(outer).grid(row=0, column=1, sticky='nsew')

        # small progress bar (subtle) under the panels
        self.progress = ctk.CTkProgressBar(self, mode='indeterminate')
        self.progress.pack(fill='x', padx=G*2, pady=(0,G*2))
        self.progress.stop()

        # initial load
        self._load_analysis_history()

    def stop_threads(self):
        """Stops any background timers and cleans up temporary files."""
        # Clean up temporary log file if it exists and was used for direct input
        if os.path.exists(TEMP_LOG_FILE):
             try:
                 os.remove(TEMP_LOG_FILE)
                 print(f"Cleaned up temporary log file: {TEMP_LOG_FILE}")
             except Exception as e:
                 print(f"Warning: Failed to delete temp log file: {e}")
        pass

    # ------------------ Left: Controls ------------------
    def _build_left_panel(self, parent):
        panel = ModernComponents.create_card(parent, fg_color=COLOR_ELEVATION_1)
        panel.grid_columnconfigure(0, weight=1)

        header = ctk.CTkLabel(panel, text='Forensic Controls', font=self.H1, text_color=COLOR_TEXT)
        header.grid(row=0, column=0, sticky='w', padx=G*2, pady=(G*2, G))

        # Source selector (group)
        group = ctk.CTkFrame(panel, fg_color='transparent')
        group.grid(row=1, column=0, sticky='ew', padx=G*2, pady=(0,G))
        group.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(group, text='Log Source:', font=self.H2).grid(row=0, column=0, sticky='w')
        self.source_menu = ctk.CTkOptionMenu(group, values=['Historical DB Logs','Local File'], variable=self.source_type, command=self._on_source_change, height=INPUT_HEIGHT, font=self.BODY, fg_color=COLOR_ELEVATION_2)
        self.source_menu.grid(row=0, column=1, sticky='ew', padx=(G,0))

        # dynamic input card
        self.input_card = ctk.CTkFrame(panel, fg_color=COLOR_BG, corner_radius=UI_SETTINGS['corner_radius'])
        self.input_card.grid(row=2, column=0, sticky='ew', padx=G*2, pady=(0,G*2))
        self.input_card.grid_columnconfigure(0, weight=1)

        self._on_source_change(self.source_type.get()) # Initialize card content

        # history title
        ctk.CTkLabel(panel, text='Recent Analyses', font=self.H2, text_color=COLOR_TEXT).grid(row=3, column=0, sticky='w', padx=G*2, pady=(0,G))
        
        # --- FIX: Corrected variable name 'self.history_frame' instead of 'selftk' ---
        self.history_frame = ctk.CTkScrollableFrame(panel, fg_color='transparent', corner_radius=UI_SETTINGS['corner_radius']-4)
        self.history_frame.grid(row=4, column=0, sticky='nsew', padx=G*2, pady=(0,G*2))
        
        # --- FIX: Changed 'card' to 'panel' ---
        panel.grid_rowconfigure(4, weight=1)

        return panel

    def _on_source_change(self, choice):
        # reset card
        for w in self.input_card.winfo_children(): w.destroy()

        if choice == 'Historical DB Logs':
            # Row 0: Last N Logs (Full Width)
            limit_frame = ctk.CTkFrame(self.input_card, fg_color='transparent')
            limit_frame.grid(row=0, column=0, sticky='ew', padx=G, pady=G)
            limit_frame.grid_columnconfigure(1, weight=1)

            ctk.CTkLabel(limit_frame, text='Last N logs:', font=self.BODY).grid(row=0, column=0, sticky='w')
            self.limit_entry = ctk.CTkEntry(limit_frame, textvariable=self.log_limit, height=INPUT_HEIGHT, font=self.BODY, placeholder_text='Analyze last N lines')
            self.limit_entry.grid(row=0, column=1, sticky='ew', padx=(G,0))

            # Row 1: Date range row
            dr = ctk.CTkFrame(self.input_card, fg_color='transparent')
            dr.grid(row=1, column=0, sticky='ew', padx=G, pady=(0,G))
            dr.grid_columnconfigure((0, 1), weight=1)

            self.start_date_btn = ctk.CTkButton(
                dr, text=self.start_date.get() or "Start Date (YYYY-MM-DD)", height=INPUT_HEIGHT, font=self.BODY,
                fg_color=COLOR_ELEVATION_2, text_color=COLOR_TEXT_SECONDARY,
                hover_color=COLOR_ELEVATION_3,
                command=lambda: self._open_date_input(self.start_date, self.start_date_btn)
            )
            self.start_date_btn.grid(row=0, column=0, sticky='ew', padx=(0, G))
            
            self.end_date_btn = ctk.CTkButton(
                dr, text=self.end_date.get() or "End Date (YYYY-MM-DD)", height=INPUT_HEIGHT, font=self.BODY,
                fg_color=COLOR_ELEVATION_2, text_color=COLOR_TEXT_SECONDARY,
                hover_color=COLOR_ELEVATION_3,
                command=lambda: self._open_date_input(self.end_date, self.end_date_btn)
            )
            self.end_date_btn.grid(row=0, column=1, sticky='ew', padx=(G, 0))
            
            # Actions row (primary only)
            actions = ctk.CTkFrame(self.input_card, fg_color='transparent')
            actions.grid(row=2, column=0, sticky='ew', padx=G, pady=(0,G))
            actions.grid_columnconfigure(0, weight=1)

            self.run_btn = ctk.CTkButton(actions, text='Run Analysis (DB) 🚀', height=BTN_HEIGHT, font=self.BODY, fg_color=COLOR_PRIMARY, hover_color=COLOR_PRIMARY_VARIANT, command=self._run_analysis_threaded)
            self.run_btn.grid(row=0, column=0, sticky='ew')

        else:
            # File drop area with clear affordance
            ctk.CTkLabel(self.input_card, text='Analyze Local File:', font=self.BODY).grid(row=0, column=0, sticky='w', padx=G, pady=(G,0))

            # Row 1: File Limit (Full Width)
            limit_frame = ctk.CTkFrame(self.input_card, fg_color='transparent')
            limit_frame.grid(row=1, column=0, sticky='ew', padx=G, pady=G)
            limit_frame.grid_columnconfigure(1, weight=1)

            ctk.CTkLabel(limit_frame, text='Last N lines:', font=self.BODY).grid(row=0, column=0, sticky='w')
            self.file_limit_entry = ctk.CTkEntry(limit_frame, textvariable=self.file_limit, height=INPUT_HEIGHT, font=self.BODY, placeholder_text='Default 500 lines')
            self.file_limit_entry.grid(row=0, column=1, sticky='ew', padx=(G,0))
            
            # Row 2: Drop Zone
            drop = ctk.CTkFrame(self.input_card, fg_color=COLOR_ELEVATION_2, corner_radius=UI_SETTINGS['corner_radius'])
            drop.grid(row=2, column=0, sticky='ew', padx=G, pady=(G,0))
            drop.grid_columnconfigure(0, weight=1)
            drop.grid_rowconfigure(0, weight=1)

            self.drop_canvas = Canvas(drop, height=96, bg=COLOR_ELEVATION_2, highlightthickness=0)
            self.drop_canvas.grid(row=0, column=0, sticky='nsew')
            self.drop_canvas.bind('<Button-1>', lambda e: self._select_local_file())
            self._update_drop_canvas_label()

            # Actions row (primary only)
            file_actions = ctk.CTkFrame(self.input_card, fg_color='transparent')
            file_actions.grid(row=3, column=0, sticky='ew', padx=G, pady=(G, G))
            file_actions.grid_columnconfigure(0, weight=1)

            self.run_btn = ctk.CTkButton(file_actions, text='Run Analysis (File) 💾', height=BTN_HEIGHT, font=self.BODY, fg_color=COLOR_PRIMARY, hover_color=COLOR_PRIMARY_VARIANT, command=self._run_analysis_threaded)
            self.run_btn.grid(row=0, column=0, sticky='ew')

        # small status beneath inputs
        self.status_label = ctk.CTkLabel(self.input_card, text='Status: Ready', font=self.BODY, text_color=COLOR_TEXT_SECONDARY)
        status_row = 3 if choice == 'Local File' else 4
        self.status_label.grid(row=status_row, column=0, sticky='w', padx=G, pady=(G,G))

    def _open_date_input(self, date_var, date_btn):
        """Simulates opening a calendar picker using a simple dialog for date input."""
        current_date = date_var.get()
        new_date = simpledialog.askstring("Date Input", "Enter date (YYYY-MM-DD):", initialvalue=current_date, parent=self)
        
        if new_date:
            try:
                datetime.strptime(new_date, '%Y-%m-%d')
                date_var.set(new_date)
                date_btn.configure(text=new_date, text_color=COLOR_TEXT)
            except ValueError:
                messagebox.showerror("Error", "Invalid date format. Use YYYY-MM-DD.", parent=self)


    def _update_drop_canvas_label(self):
        if not hasattr(self, 'drop_canvas'): return
        self.drop_canvas.delete('all')
        w = self.drop_canvas.winfo_reqwidth() or 420
        h = self.drop_canvas.winfo_reqheight() or 96
        filename = os.path.basename(self.file_path.get())
        if filename:
            self.drop_canvas.create_text(w/2, h/3, text='File selected', font=self.H2, fill=COLOR_TEXT)
            self.drop_canvas.create_text(w/2, h*2/3, text=filename, font=self.BODY, fill=COLOR_TEXT_SECONDARY)
        else:
            self.drop_canvas.create_text(w/2, h/3, text='Click to choose file', font=self.H2, fill=COLOR_TEXT_SECONDARY)
            self.drop_canvas.create_text(w/2, h*2/3, text='Note: Large files may take time', font=self.BODY, fill=COLOR_TEXT_SECONDARY)

    def _select_local_file(self):
        path = filedialog.askopenfilename(title='Select log file', filetypes=[('Log','*.log *.txt'),('All','*.*')])
        if path:
            self.file_path.set(path)
            self._update_drop_canvas_label()

    # ------------------ Right: Report ------------------
    def _build_right_panel(self, parent):
        # We use a wrapper card that contains the header, tabs, and the footer
        wrapper_card = ModernComponents.create_card(parent, fg_color=COLOR_ELEVATION_1)
        wrapper_card.grid_columnconfigure(0, weight=1)
        wrapper_card.grid_rowconfigure(1, weight=1) # Tabs area expands
        
        # --- 1. Header (Title + Badge) ---
        summary_header = ctk.CTkFrame(wrapper_card, fg_color='transparent')
        summary_header.grid(row=0, column=0, sticky='ew', padx=G*2, pady=G*2)
        summary_header.grid_columnconfigure(0, weight=1)

        self.title_label = ctk.CTkLabel(summary_header, text='LLM Forensics Report', font=self.H1, text_color=COLOR_TEXT)
        self.title_label.grid(row=0, column=0, sticky='w')

        # Severity badge (prominent)
        self.severity_badge = ModernComponents.create_badge(summary_header, text='N/A', badge_type='info')
        self.severity_badge.grid(row=0, column=1, sticky='e')
        
        # --- 2. Main Tabbed Output Console ---
        self.report_tabview = ctk.CTkTabview(
            wrapper_card, fg_color=COLOR_BG # Tabs background is slightly darker
        )
        # IMPORTANT: Row 1 handles the expanding report view
        self.report_tabview.grid(row=1, column=0, sticky="nsew", padx=G*3, pady=(0, G*2))
        
        self.tab_summary = self.report_tabview.add('📋 Summary')
        self.tab_events = self.report_tabview.add('🚨 Events')
        self.tab_traffic = self.report_tabview.add('📈 Traffic')
        
        self._build_summary_tab(self.tab_summary)
        self._build_events_tab(self.tab_events)
        self._build_traffic_tab(self.tab_traffic)
        
        # --- 3. Footer (Action Buttons) ---
        self._build_report_footer(wrapper_card).grid(row=2, column=0, sticky='ew', padx=G*2, pady=(0, G*2))

        return wrapper_card

    def _build_report_footer(self, parent):
        """Creates the dedicated, prominent footer bar for actions."""
        footer_frame = ctk.CTkFrame(parent, fg_color=COLOR_ELEVATION_3)
        footer_frame.grid_columnconfigure((0,1,2,3), weight=1)
        
        btn_font = (FONT_FAMILY, 14)
        
        self.btn_export = ctk.CTkButton(footer_frame, text='💾 Export (JSON)', height=BTN_HEIGHT - 4, font=btn_font, command=self._export_current_report_json)
        self.btn_export.grid(row=0, column=0, sticky='ew', padx=(G*2, G), pady=G)
        
        self.btn_copy = ctk.CTkButton(footer_frame, text='📋 Copy Summary', height=BTN_HEIGHT - 4, font=btn_font, command=self._copy_summary)
        self.btn_copy.grid(row=0, column=1, sticky='ew', padx=G, pady=G)
        
        self.btn_filter = ctk.CTkButton(footer_frame, text='⚙️ Filter Events', height=BTN_HEIGHT - 4, font=btn_font, command=self._open_filter_dialog)
        self.btn_filter.grid(row=0, column=2, sticky='ew', padx=G, pady=G)
        
        self.btn_refresh = ctk.CTkButton(footer_frame, text='🔄 Refresh History', height=BTN_HEIGHT - 4, font=btn_font, command=self._load_analysis_history)
        self.btn_refresh.grid(row=0, column=3, sticky='ew', padx=(G, G*2), pady=G)
        
        return footer_frame


    def _build_summary_tab(self, tab):
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(2, weight=1)
        tab.grid_rowconfigure(4, weight=1)

        # 1. Analysis Summary Text
        ctk.CTkLabel(tab, text="Analysis Summary:", font=self.H2, text_color=COLOR_TEXT).grid(row=0, column=0, sticky="w", padx=G, pady=(G, G/2))
        summary_card = ModernComponents.create_card(tab, fg_color=COLOR_ELEVATION_2, corner_radius=UI_SETTINGS['corner_radius']-4)
        summary_card.grid(row=1, column=0, sticky="nsew", padx=G, pady=(0, G))
        
        self.summary_box = ctk.CTkTextbox(summary_card, height=120, font=self.BODY, fg_color=COLOR_BG, corner_radius=UI_SETTINGS['corner_radius']-4) 
        self.summary_box.pack(fill='both', expand=True, padx=G, pady=G)
        self.summary_box.insert('1.0', 'Run an analysis to view summary')
        self.summary_box.configure(state='disabled')
        
        # 2. Key Performance Indicators (KPI Grid)
        self.kpi_frame = ctk.CTkFrame(tab, fg_color=COLOR_ELEVATION_2, corner_radius=UI_SETTINGS['corner_radius']-4)
        self.kpi_frame.grid(row=2, column=0, sticky="ew", padx=G, pady=G)
        self.kpi_frame.grid_columnconfigure((0,1,2,3), weight=1)
        
        self.lbl_events_count = self._create_kpi(self.kpi_frame, 'TOTAL EVENTS', '0', 0, COLOR_PRIMARY)
        self.lbl_unique_ips = self._create_kpi(self.kpi_frame, 'UNIQUE IPs', '0', 1, COLOR_PRIMARY)
        self.lbl_review_required = self._create_kpi(self.kpi_frame, 'HUMAN REVIEW', 'NO', 2, COLOR_SUCCESS)
        self.lbl_highest_sev = self._create_kpi(self.kpi_frame, 'HIGHEST SEVERITY', 'INFO', 3, COLOR_INFO)


        # 3. Planning & Observations Box
        ctk.CTkLabel(tab, text="Planning & Observations:", font=self.H2, text_color=COLOR_TEXT).grid(row=3, column=0, sticky="w", padx=G, pady=(G/2, G/2))
        obs_card = ModernComponents.create_card(tab, fg_color=COLOR_ELEVATION_2, corner_radius=UI_SETTINGS['corner_radius']-4)
        obs_card.grid(row=4, column=0, sticky="nsew", padx=G, pady=(0, G))
        
        self.obs_box = ctk.CTkTextbox(obs_card, height=150, font=self.BODY, fg_color=COLOR_BG, corner_radius=UI_SETTINGS['corner_radius']-4) 
        self.obs_box.pack(fill='both', expand=True, padx=G, pady=G)
        self.obs_box.configure(state='disabled')

    def _create_kpi(self, parent, title: str, value: str, column: int, color: str):
        frame = ctk.CTkFrame(parent, fg_color="transparent")
        frame.grid(row=0, column=column, sticky='nsew', padx=G, pady=G)
        
        ctk.CTkLabel(frame, text=title, font=self.BODY, text_color=COLOR_TEXT_SECONDARY).pack(pady=(G, 0), anchor='center')
        lbl_value = ctk.CTkLabel(frame, text=value, font=self.H1, text_color=color)
        lbl_value.pack(pady=(0, G), anchor='center')
        
        return lbl_value
    
    def _build_events_tab(self, tab):
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(0, weight=1)
        
        self.events_scroll = ctk.CTkScrollableFrame(tab, fg_color='transparent', corner_radius=UI_SETTINGS['corner_radius']-4)
        self.events_scroll.grid(row=0, column=0, sticky="nsew")
        ctk.CTkLabel(self.events_scroll, text="No Security Events Found.", text_color=COLOR_TEXT_SECONDARY).pack(pady=G*2)
        
    def _build_traffic_tab(self, tab):
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(0, weight=1)
        
        self.traffic_scroll = ctk.CTkScrollableFrame(tab, fg_color='transparent', corner_radius=UI_SETTINGS['corner_radius']-4)
        self.traffic_scroll.grid(row=0, column=0, sticky="nsew")
        ctk.CTkLabel(self.traffic_scroll, text="No Traffic Patterns Identified.", text_color=COLOR_TEXT_SECONDARY).pack(pady=G*2)


    # --- Analysis Execution ---
    def _run_analysis_threaded(self):
        logs_to_analyze: List[str] = []
        log_reference = ""
        start_dt, end_dt = None, None
        
        if self.source_type.get() == "Historical DB Logs":
            try:
                limit = int(self.log_limit.get() or "500")
                if limit <= 0 or limit > 5000: raise ValueError("Limit must be between 1 and 5000.") 
                
                start_dt = datetime.strptime(self.start_date.get(), '%Y-%m-%d') if self.start_date.get() else None
                end_dt_raw = datetime.strptime(self.end_date.get(), '%Y-%m-%d') if self.end_date.get() else None
                # CRITICAL FIX: Ensure end_dt is exclusive (end of the selected day)
                if end_dt_raw: end_dt = end_dt_raw + timedelta(days=1) 
                
                logs_to_analyze = DB.fetch_logs_for_analysis(limit=limit, start_date=start_dt, end_date=end_dt)
                log_reference = f"Last {len(logs_to_analyze)} DB Logs"
            except ValueError as e:
                messagebox.showwarning("Input Error", str(e), parent=self); return
        
        elif self.source_type.get() == "Local File":
            path = self.file_path.get()
            if not path or not os.path.exists(path):
                 messagebox.showwarning("File Error", "Selected file does not exist.", parent=self); return
            
            # CRITICAL FIX: Handle potential cleanup of temp file if it's the source
            if path == TEMP_LOG_FILE:
                 # It's a temporary log from the Alerts page. Reference is the alert itself.
                 log_reference = "Alert Snippet Analysis" 
            else:
                 log_reference = os.path.basename(path)

            try:
                limit = int(self.file_limit.get() or "500")
                if limit <= 0: raise ValueError('Limit must be a positive number.')
                
                # Reading file content
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    all_lines = [l.strip() for l in f.readlines() if l.strip()]
                    
                    if len(all_lines) > limit:
                        logs_to_analyze = all_lines[-limit:] 
                    else:
                         logs_to_analyze = all_lines
                         
            except ValueError as e:
                 messagebox.showwarning("Input Error", f"File limit error: {e}", parent=self); return
            except Exception as e:
                messagebox.showerror("File Error", f"Could not read file: {e}", parent=self); return

        if not logs_to_analyze:
             messagebox.showinfo("No Data", "No logs available to analyze.", parent=self); return
             
        self._set_loading_state(True, f"Running analysis on {len(logs_to_analyze)} entries...")
        
        threading.Thread(target=self._analysis_worker, args=(logs_to_analyze, log_reference), daemon=True).start()

    def _analysis_worker(self, raw_logs: List[str], log_reference: str):
        """Worker thread to run the LLM analysis."""
        try:
            analyzer = self.llm_service.get_analyzer()
            analysis_result = analyzer.analyze_logs(raw_logs)

            # --- SAFE RECOMMENDATION EXTRACTION ---
            # Collect recommendations from all events (since they don't exist at top level)
            all_recommendations = []
            if analysis_result.events:
                for event in analysis_result.events:
                    all_recommendations.extend(event.recommended_actions)
            
            # Create string for DB
            rec_text = "; ".join(all_recommendations) if all_recommendations else "No actions suggested."

            # Save to DB
            user_id = self.user_info.get('id')
            db_id = DB.insert_forensic_analysis(
                # CRITICAL FIX: Save only a snippet of the logs, not the whole chunk
                log_snippet="\n".join(raw_logs[:5]), 
                summary=analysis_result.summary,
                recommendation=rec_text,
                log_reference=log_reference,
                user_id=user_id
            )
            
            # Update UI
            self.after(0, lambda: self._handle_analysis_complete(db_id, analysis_result))

        except Exception as e:
            self.after(0, lambda: self._set_loading_state(False, f"Analysis failed: {e}", status="error"))
            print(f"LLM FORENSICS CRITICAL ERROR: {e}")

    def _handle_analysis_complete(self, db_id: int, analysis: LogAnalysis):
        self.progress.stop()
        self.current_analysis = analysis
        status = f'Report #{db_id} saved' if db_id!=-1 else 'Analysis complete (not saved)'
        self._set_loading_state(False, status, status='success')
        self._update_report_display(analysis)
        self._load_analysis_history()

    # ------------------ Report Rendering ------------------
    def _update_report_display(self, analysis: LogAnalysis):
        sev = analysis.highest_severity.value if analysis.highest_severity else 'INFO'
        
        self.title_label.configure(text=f'LLM Forensics — {sev}')
        self.severity_badge.configure(text=sev, fg_color=SEV_COLOR.get(sev, COLOR_INFO))

        # 1. Update Summary Tab
        self._set_textbox(self.summary_box, analysis.summary)
        obs_text = 'OBSERVATIONS:\n' + '\n'.join(f'• {o}' for o in analysis.observations)
        plan_text = '\n\nPLANNING:\n' + '\n'.join(f'• {p}' for p in analysis.planning)
        self._set_textbox(self.obs_box, obs_text + plan_text)
        
        event_count = len(analysis.events)
        # CRITICAL FIX: Correctly calculate unique IPs from the nested list of IPAddress objects
        all_ips = set()
        for event in analysis.events:
            for ip_obj in event.source_ips:
                 all_ips.add(ip_obj.ip_address)
        unique_ips = len(all_ips) 
        
        review_required = analysis.requires_immediate_attention
        review_color = COLOR_ERROR if review_required else COLOR_SUCCESS
        sev_color = SEV_COLOR.get(sev, COLOR_INFO)
        
        self.lbl_events_count.configure(text=str(event_count), text_color=COLOR_PRIMARY)
        self.lbl_unique_ips.configure(text=str(unique_ips), text_color=COLOR_PRIMARY)
        self.lbl_review_required.configure(text='YES' if review_required else 'NO', text_color=review_color)
        self.lbl_highest_sev.configure(text=sev, text_color=sev_color)

        # 2. Events Tab
        for w in list(self.events_scroll.winfo_children()): w.destroy()
        if not analysis.events:
            ctk.CTkLabel(self.events_scroll, text='No security events detected', text_color=COLOR_TEXT_SECONDARY).pack(pady=G)
        else:
            for i,e in enumerate(analysis.events, start=1):
                self._render_event_card(self.events_scroll, e, i)

        # 3. Traffic Tab
        for w in list(self.traffic_scroll.winfo_children()): w.destroy()
        if not analysis.traffic_patterns:
            ctk.CTkLabel(self.traffic_scroll, text='No traffic patterns identified.', text_color=COLOR_TEXT_SECONDARY).pack(pady=G)
        else:
            for p in analysis.traffic_patterns:
                self._render_traffic_card(self.traffic_scroll, p)

    def _set_textbox(self, box, text):
        box.configure(state='normal')
        box.delete('1.0', 'end')
        box.insert('1.0', text)
        box.configure(state='disabled')

    def _render_event_card(self, parent, event: WebSecurityEvent, idx: int):
        sev_color = SEV_COLOR.get(event.severity.value, COLOR_WARNING)
        
        card_wrapper = ctk.CTkFrame(parent, fg_color='transparent')
        card_wrapper.pack(fill='x', padx=G, pady=(0,G))

        card = ModernComponents.create_card(card_wrapper, fg_color=COLOR_ELEVATION_2)
        card.pack(fill='both', expand=True)
        card.grid_columnconfigure(1, weight=1)
        
        sev_bar = ctk.CTkFrame(card, fg_color=sev_color, width=6, corner_radius=0)
        sev_bar.grid(row=0, column=0, rowspan=4, sticky='ns')

        content_frame = ctk.CTkFrame(card, fg_color='transparent')
        content_frame.grid(row=0, column=1, rowspan=4, sticky='nsew', padx=G, pady=G)
        content_frame.grid_columnconfigure(0, weight=1)

        header = ctk.CTkFrame(content_frame, fg_color='transparent')
        header.grid(row=0, column=0, sticky='ew', pady=(G, G/2))
        header.grid_columnconfigure(1, weight=1)

        icon = '🚨' if event.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH] else '⚠️'
        ctk.CTkLabel(header, text=f'{icon} Event #{idx}', font=self.H2, text_color=COLOR_TEXT_SECONDARY).grid(row=0, column=0, sticky='w')
        ctk.CTkLabel(header, text=event.event_type, font=self.H2, text_color=sev_color).grid(row=0, column=1, sticky='w', padx=G)
        
        ctk.CTkLabel(header, text=event.severity.value, font=self.BODY, fg_color=sev_color, text_color=COLOR_BG, corner_radius=6, padx=8, pady=4).grid(row=0, column=2, sticky='e')

        meta = ctk.CTkFrame(content_frame, fg_color='transparent')
        meta.grid(row=1, column=0, sticky='ew', pady=G/2)
        meta.grid_columnconfigure((0,2), weight=1)
        meta.grid_columnconfigure((1,3), weight=2)

        def add_detail(key, value, row, col):
             ctk.CTkLabel(meta, text=key+':', font=self.BODY, text_color=COLOR_TEXT_SECONDARY).grid(row=row, column=col, sticky='w', padx=G/2, pady=1)
             ctk.CTkLabel(meta, text=str(value), font=self.BODY).grid(row=row, column=col+1, sticky='w', padx=(G,0), pady=1)

        add_detail('Confidence', f'{event.confidence_score*100:.0f}%', 0, 0)
        add_detail('URL', event.url_pattern, 0, 2)
        add_detail('Method', event.http_method, 1, 0)
        
        # CRITICAL FIX: Convert AttackType enums to string list
        attack_patterns_str = ', '.join([a.value for a in event.possible_attack_patterns]) if event.possible_attack_patterns else 'N/A'
        
        add_detail('Attacks', attack_patterns_str, 1, 2)

        ctk.CTkLabel(content_frame, text='Reasoning:', font=self.H2, text_color=COLOR_TEXT_SECONDARY).grid(row=2, column=0, sticky='w', pady=(G, 0))
        ctk.CTkLabel(content_frame, text=event.reasoning, font=self.BODY, wraplength=700, justify='left').grid(row=3, column=0, sticky='ew', pady=(0, G))

        actions = ctk.CTkFrame(content_frame, fg_color=COLOR_BG)
        actions.grid(row=4, column=0, sticky='ew', pady=(G, G/2))

        ctk.CTkLabel(actions, text='Recommended Actions', font=self.BODY, text_color=COLOR_TEXT_SECONDARY).pack(side='left', padx=(G, G*2), pady=G/2)
        
        for a in event.recommended_actions:
            icon = '🛑' if 'block' in a.lower() else '⚙️'
            b = ctk.CTkButton(actions, text=f'{icon} {a}', height=32, font=self.BODY, fg_color=COLOR_PRIMARY, hover_color=COLOR_PRIMARY_VARIANT, command=lambda act=a: messagebox.showinfo('Action', f'Execute: {act}', parent=self))
            b.pack(side='left', padx=(0,G), pady=G/2)

    def _render_traffic_card(self, parent, pattern: WebTrafficPattern):
        card_wrapper = ctk.CTkFrame(parent, fg_color='transparent')
        card_wrapper.pack(fill='x', padx=G, pady=(0,G))

        card = ModernComponents.create_card(card_wrapper, fg_color=COLOR_ELEVATION_2)
        card.pack(fill='x', expand=True, padx=G/2, pady=G/2)
        card.grid_columnconfigure(0, weight=1)
        
        header = ctk.CTkFrame(card, fg_color='transparent')
        header.grid(row=0, column=0, sticky='ew', padx=G, pady=G)
        header.grid_columnconfigure(0, weight=1)
        header.grid_columnconfigure(2, weight=1)

        ctk.CTkLabel(header, text=f'URL: {pattern.url_path}', font=self.H2, text_color=COLOR_TEXT).grid(row=0, column=0, sticky='w', padx=G, pady=(G, 0))
        ctk.CTkLabel(header, text=f'Method: {pattern.http_method}', font=self.BODY, text_color=COLOR_TEXT_SECONDARY).grid(row=0, column=1, sticky='w', padx=G, pady=(G, 0))
        ctk.CTkLabel(header, text=f'Total Hits: {pattern.hits_count:,}', font=self.H2, text_color=COLOR_PRIMARY).grid(row=0, column=2, sticky='e', padx=G, pady=(G, 0))

        ctk.CTkLabel(header, text=f'Unique IPs: {pattern.unique_ips:,}', font=self.BODY, text_color=COLOR_TEXT_SECONDARY).grid(row=1, column=0, columnspan=3, sticky='w', padx=G)
        
        chart_frame = ctk.CTkFrame(card, fg_color=COLOR_BG, corner_radius=UI_SETTINGS['corner_radius']-4, height=40)
        chart_frame.grid(row=1, column=0, sticky='ew', padx=G, pady=(G, G))
        chart_frame.grid_columnconfigure(0, weight=1)
        
        chart_canvas = Canvas(chart_frame, bg=COLOR_BG, highlightthickness=0, height=40)
        chart_canvas.grid(row=0, column=0, sticky='nsew', padx=G, pady=G)
        
        total_codes = sum(pattern.response_codes.values())
        success_count = pattern.response_codes.get('200', 0) + pattern.response_codes.get('300', 0)
        failure_count = total_codes - success_count
        
        chart_canvas.bind('<Configure>', lambda e, c=chart_canvas, s=success_count, f=failure_count, t=total_codes: self._draw_response_chart(c, s, f, t))

    def _draw_response_chart(self, canvas, success_count, failure_count, total_codes):
        if not canvas.winfo_exists(): return

        canvas.delete("all")
        w = canvas.winfo_width()
        h = canvas.winfo_height()
        bar_height = h - 10
        
        if total_codes == 0: return

        chart_w = w - 120
        
        success_w = int((success_count / total_codes) * chart_w) 
        failure_w = chart_w - success_w
        
        x_start = 5
        
        if success_w > 0:
            canvas.create_rectangle(x_start, 5, x_start + success_w, 5 + bar_height, 
                                     fill=COLOR_SUCCESS if 'COLOR_SUCCESS' in globals() else '#2ecc71', outline='')
            x_start += success_w

        if failure_w > 0:
            canvas.create_rectangle(x_start, 5, x_start + failure_w, 5 + bar_height, 
                                     fill=COLOR_ERROR if 'COLOR_ERROR' in globals() else '#e74c3c', outline='')
            x_start += failure_w

        text_x = chart_w + 10 
        
        success_pct = f"{success_count/total_codes:.0%}"
        failure_pct = f"{failure_count/total_codes:.0%}"
        
        canvas.create_text(text_x, h/2, text=f"✅ {success_pct}", 
                            fill=COLOR_SUCCESS if 'COLOR_SUCCESS' in globals() else '#2ecc71', anchor='w', font=self.BODY)
        
        canvas.create_text(text_x + 50, h/2, text=f"❌ {failure_pct}", 
                            fill=COLOR_ERROR if 'COLOR_ERROR' in globals() else '#e74c3c', anchor='w', font=self.BODY)


    # ------------------ History ------------------
    def _load_analysis_history(self):
        for w in list(self.history_frame.winfo_children()): w.destroy()
        
        try:
            self.analysis_history = DB.fetch_forensic_analysis(limit=20)
        except Exception as e:
            ctk.CTkLabel(self.history_frame, text='Failed to load history.', text_color=COLOR_RED).pack(pady=G)
            return

        if not self.analysis_history:
            ctk.CTkLabel(self.history_frame, text='No history yet — run your first analysis', text_color=COLOR_TEXT_SECONDARY).pack(pady=G)
            return
            
        for it in self.analysis_history:
            self._history_item(it)

    def _history_item(self, it: Dict):
        row = ModernComponents.create_card(self.history_frame, fg_color=COLOR_ELEVATION_2)
        row.pack(fill='x', padx=G, pady=(0,G))
        
        row.grid_columnconfigure(0, weight=1)
        row.grid_columnconfigure((1, 2), weight=0, minsize=40)

        ts = it.get('timestamp', '')
        try:
            ts = datetime.fromisoformat(ts).strftime('%Y-%m-%d %H:%M')
        except Exception:
            pass
        title = f"{ts} — {it.get('log_reference','Unknown')}"
        
        summary_text = it.get('summary', 'No summary available')
        recommendation_text = it.get('recommendation', 'N/A')
        
        severity = recommendation_text.split(' ')[0].replace('.', '')
        sev_color = SEV_COLOR.get(severity, COLOR_ACCENT)
        
        ctk.CTkLabel(row, text=title, font=self.H2).grid(row=0, column=0, sticky='w', padx=G, pady=(G,0))
        ctk.CTkLabel(row, text=summary_text[:60] + '...', font=self.BODY, text_color=COLOR_TEXT_SECONDARY).grid(row=1, column=0, sticky='w', padx=G, pady=(0,G))

        btn_view = ctk.CTkButton(row, text='View', height=30, width=60, font=self.BODY, 
                                 fg_color=COLOR_ACCENT, hover_color=COLOR_PRIMARY_VARIANT, 
                                 command=lambda i=it: self._view_history_report(i))
        btn_view.grid(row=0, column=1, rowspan=2, sticky='e', padx=(G, 0), pady=G)

        btn_delete = ctk.CTkButton(row, text='❌', height=30, width=30, font=self.BODY, 
                                fg_color=COLOR_RED, hover_color=COLOR_ORANGE, 
                                text_color=COLOR_BG,
                                command=lambda report_id=it.get('id'): self._confirm_delete_report(report_id))
        btn_delete.grid(row=0, column=2, rowspan=2, sticky='e', padx=G, pady=G)


    def _confirm_delete_report(self, report_id):
        if not report_id:
            messagebox.showerror("Error", "Report ID not found.", parent=self)
            return
            
        if messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete report #{report_id}?", parent=self):
            self._delete_report(report_id)

    def _delete_report(self, report_id):
        try:
            DB.delete_forensic_analysis(report_id)
            self._set_loading_state(False, f"Report #{report_id} deleted.", status='info')
            self._load_analysis_history()
        except Exception as e:
            messagebox.showerror("DB Error", f"Failed to delete report: {e}", parent=self)
            print(f"DB Error deleting forensic analysis: {e}")


    def _view_history_report(self, item: Dict):
        summary_text = item.get('summary', 'No summary available')
        recommendation_text = item.get('recommendation', 'N/A')
        log_snippet = item.get('log_snippet', 'N/A')
        
        self.title_label.configure(text=f"Historical Report #{item['id']}")
        
        self._set_textbox(self.summary_box, summary_text)
        self._set_textbox(self.obs_box, f"RECOMMENDATIONS:\n{recommendation_text}\n\nLOG SNIPPET:\n{log_snippet}")

        self.severity_badge.configure(text='AUDIT', fg_color=COLOR_INFO)

    # ------------------ Utilities ------------------
    def _set_loading_state(self, is_loading: bool, message: str, status: str='info'):
        try:
            if is_loading:
                self.run_btn.configure(text='Analyzing...', fg_color=COLOR_WARNING, hover_color=COLOR_WARNING, state='disabled')
                self.progress.start()
            else:
                self.run_btn.configure(text='Run Analysis (DB) 🚀' if self.source_type.get() == 'Historical DB Logs' else 'Run Analysis (File) 💾', fg_color=COLOR_PRIMARY, hover_color=COLOR_PRIMARY_VARIANT, state='normal')
                self.progress.stop()

            col = self.STATUS_COLORS.get(status, COLOR_TEXT_SECONDARY)
            self.status_label.configure(text=message, text_color=col)
            
        except Exception:
            pass
            
    def _export_current_report_json(self):
        if not self.current_analysis:
            messagebox.showinfo('No report', 'No report to export', parent=self); return
        p = filedialog.asksaveasfilename(defaultextension='.json', filetypes=[('JSON','*.json')])
        if not p: return
        try:
            with open(p,'w',encoding='utf-8') as f:
                # CRITICAL FIX: Use model_dump for Pydantic V2 compatibility
                json.dump(self.current_analysis.model_dump(), f, default=str, indent=2)
            messagebox.showinfo('Exported', f'Exported to {p}', parent=self)
        except Exception as e:
            messagebox.showerror('Export failed', str(e), parent=self)

    def _copy_summary(self):
        if not self.current_analysis:
            messagebox.showinfo('No summary', 'No summary to copy', parent=self); return
        try:
            self.clipboard_clear(); self.clipboard_append(self.current_analysis.summary)
            messagebox.showinfo('Copied', 'Summary copied to clipboard', parent=self)
        except Exception as e:
            messagebox.showerror('Copy failed', str(e), parent=self)

    def _open_filter_dialog(self):
        if not self.current_analysis or not self.current_analysis.events:
            messagebox.showinfo('No events', 'No events to filter', parent=self); return
        top = ctk.CTkToplevel(self)
        top.title('Filter Events')
        top.geometry('360x180')
        ctk.CTkLabel(top, text='Minimum Severity', font=self.BODY).pack(pady=G)
        menu = ctk.CTkOptionMenu(top, values=[s.value for s in SeverityLevel], command=lambda v: self._filter_events_by_severity(v, top))
        menu.pack(pady=G)
        ctk.CTkButton(top, text='Close', command=top.destroy).pack(pady=G)

    def _filter_events_by_severity(self, level: str, window=None):
        try:
            lvl_index = [l.value for l in SeverityLevel].index(level)
        except ValueError:
            lvl_index = 0
        
        # CRITICAL FIX: Filter based on SeverityLevel enum value indices
        filtered = [e for e in self.current_analysis.events if list(SeverityLevel).index(e.severity) <= lvl_index]
        for w in list(self.events_scroll.winfo_children()): w.destroy()
        if not filtered:
            ctk.CTkLabel(self.events_scroll, text='No events match filter', text_color=COLOR_TEXT_SECONDARY).pack(pady=G)
        else:
            for i,e in enumerate(filtered, start=1):
                self._render_event_card(self.events_scroll, e, i)
        if window: window.destroy()

 # --- NEW: Direct Input Handler ---
    def load_log_snippet(self, log_text: str):
        """
        Called by the controller to load a specific log snippet (e.g. from Alerts page).
        Sets up the UI to analyze this snippet as a 'Local File' (conceptually).
        """
        # 1. Switch Source to Local File (to hide DB controls)
        self.source_type.set('Local File')
        self._on_source_change('Local File')
        
        # 2. Create a temporary file for this snippet 
        try:
            # Use the global constant for the temporary file path
            with open(TEMP_LOG_FILE, "w", encoding="utf-8") as f:
                f.write(log_text)
            
            self.file_path.set(TEMP_LOG_FILE)
            self._update_drop_canvas_label()
            
            # 3. Auto-start analysis
            self.after(500, self._run_analysis_threaded)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load alert data: {e}")
