import os
import csv
import subprocess
import sys
from datetime import datetime, timedelta, timezone 
from collections import Counter
import sqlite3
import json
from typing import Optional, List, Dict, Any

import customtkinter as ctk
from tkinter import messagebox, filedialog

# Attempt PDF library import
try:
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib import colors as reportlab_colors
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False
    print("Warning: reportlab not found (pip install reportlab). PDF export will be simulated.")

# Import project modules
from src.backend.database_manager import get_db_instance
from src.config import *
from src.ui.components.modern_components import ModernComponents

# Get DB instance
DB = get_db_instance()
# NOTE: Assuming APP_DIR is defined in config.py or imported context
try: APP_DIR = APP_DIR 
except NameError: APP_DIR = os.path.dirname(os.path.abspath(__file__))

REPORTS_DIR = os.path.join(APP_DIR, "reports") # Store reports in subdir relative to app

class ReportsPage(ctk.CTkFrame):
    """Page for generating and managing historical reports."""
    def __init__(self, parent, controller):
        super().__init__(parent, fg_color="transparent")
        self.controller = controller
        self.user_info = controller.user_info # Store user info for logging
        self.status_label_job = None
        self.reports: List[Dict] = [] # Stores report metadata from DB
        self.sort_key = ctk.StringVar(value="Date (Newest)") # For history sorting

        os.makedirs(REPORTS_DIR, exist_ok=True) # Ensure reports directory exists
        self._build_ui()
        self._load_reports() # Initial load of history

    def stop_threads(self):
        """Placeholder in case future versions add background tasks."""
        print("ReportsPage stopping (No active threads to stop).")
        # Cancel any pending self.after jobs if necessary
        if self.status_label_job:
             try: self.after_cancel(self.status_label_job)
             except ValueError: pass
             self.status_label_job = None

    def _build_ui(self):
        """Builds the main two-panel layout."""
        container = ctk.CTkFrame(self, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=UI_SETTINGS["spacing"]["md"], pady=UI_SETTINGS["spacing"]["md"])

        # Configure grid: 
        # FIX: Reduced minsize to 280 for a more compact generation panel.
        container.grid_columnconfigure(0, weight=1, minsize=280) # Generation Panel min width
        container.grid_columnconfigure(1, weight=2) # History Panel
        container.grid_rowconfigure(0, weight=1) # Single row

        # Create and place panels
        self.left_panel = self._create_generation_panel(container)
        self.right_panel = self._create_history_panel(container)

        self.left_panel.grid(row=0, column=0, sticky="nsew", padx=(0, UI_SETTINGS["spacing"]["md"]))
        self.right_panel.grid(row=0, column=1, sticky="nsew")

    def _create_generation_panel(self, parent) -> ctk.CTkFrame:
        """Builds the left panel for configuring and generating reports."""
        panel = ModernComponents.create_card(parent)
        
        ctk.CTkLabel(panel, text="Report Generation", font=FONT_HEADING, text_color=COLOR_PRIMARY).pack(
            anchor="nw", padx=UI_SETTINGS["spacing"]["lg"], pady=(UI_SETTINGS["spacing"]["lg"], UI_SETTINGS["spacing"]["sm"])
        )

        # --- Report Type ---
        ctk.CTkLabel(panel, text="Report Type:", font=FONT_BODY_MEDIUM).pack(anchor="w", padx=UI_SETTINGS["spacing"]["lg"], pady=(UI_SETTINGS["spacing"]["sm"], UI_SETTINGS["spacing"]["xs"]))
        self.report_type = ctk.CTkOptionMenu(
            panel, values=["Anomaly Details", "User Activity", "Security Audit", "Executive Summary"], 
            font=FONT_BODY, dropdown_font=FONT_BODY, height=UI_SETTINGS["button_height"]-5
        )
        self.report_type.pack(fill="x", padx=UI_SETTINGS["spacing"]["lg"], pady=(UI_SETTINGS["spacing"]["xs"], UI_SETTINGS["spacing"]["md"]))
        self.report_type.set("Anomaly Details")

        # --- Date Range ---
        ctk.CTkLabel(panel, text="Date Range:", font=FONT_BODY_MEDIUM).pack(anchor="w", padx=UI_SETTINGS["spacing"]["lg"], pady=(UI_SETTINGS["spacing"]["sm"], UI_SETTINGS["spacing"]["xs"]))
        
        # Frame for preset buttons
        preset_frame = ctk.CTkFrame(panel, fg_color="transparent")
        preset_frame.pack(fill="x", padx=UI_SETTINGS["spacing"]["lg"] - 5, pady=UI_SETTINGS["spacing"]["xs"])
        presets = ["Today", "Last 7 Days", "Last 30 Days"]
        for i, text in enumerate(presets):
             btn = ctk.CTkButton(
                 preset_frame, text=text, font=FONT_BODY_SMALL, height=28, width=100,
                 fg_color=COLOR_ELEVATION_3, hover_color=COLOR_ELEVATION_4,
                 command=lambda preset=text: self._set_date_preset(preset)
             )
             btn.grid(row=0, column=i, padx=5, sticky="ew")
        preset_frame.grid_columnconfigure((0,1,2), weight=1)

        # Frame for start/end date entries
        date_frame = ctk.CTkFrame(panel, fg_color="transparent")
        date_frame.pack(fill="x", padx=UI_SETTINGS["spacing"]["lg"], pady=(UI_SETTINGS["spacing"]["xs"], UI_SETTINGS["spacing"]["md"]))
        self.start_date_entry = ctk.CTkEntry(date_frame, placeholder_text="YYYY-MM-DD (Start)", font=FONT_BODY, height=UI_SETTINGS["button_height"]-5)
        self.end_date_entry = ctk.CTkEntry(date_frame, placeholder_text="YYYY-MM-DD (End)", font=FONT_BODY, height=UI_SETTINGS["button_height"]-5)
        self.start_date_entry.pack(side="left", fill="x", expand=True, padx=(0, UI_SETTINGS["spacing"]["xs"]))
        self.end_date_entry.pack(side="left", fill="x", expand=True, padx=(UI_SETTINGS["spacing"]["xs"], 0))
        self._set_date_preset("Last 7 Days") # Default selection

        # --- Export Format ---
        ctk.CTkLabel(panel, text="Export Format:", font=FONT_BODY_MEDIUM).pack(anchor="w", padx=UI_SETTINGS["spacing"]["lg"], pady=(UI_SETTINGS["spacing"]["sm"], UI_SETTINGS["spacing"]["xs"]))
        
        format_options = ["CSV (Database Query)"]
        if REPORTLAB_AVAILABLE: format_options.append("PDF (Basic)")
        else: format_options.append("PDF (Simulated)")
        format_options.append("JSON (Simulated)")

        self.export_format = ctk.CTkOptionMenu(
            panel, values=format_options, font=FONT_BODY, dropdown_font=FONT_BODY,
            height=UI_SETTINGS["button_height"]-5
        )
        self.export_format.pack(fill="x", padx=UI_SETTINGS["spacing"]["lg"], pady=(UI_SETTINGS["spacing"]["xs"], UI_SETTINGS["spacing"]["lg"]))
        self.export_format.set(format_options[0]) # Default to CSV

        # --- Action Buttons (at bottom) ---
        spacer = ctk.CTkFrame(panel, fg_color="transparent")
        spacer.pack(fill="y", expand=True)

        button_frame = ctk.CTkFrame(panel, fg_color="transparent")
        button_frame.pack(fill="x", padx=UI_SETTINGS["spacing"]["lg"], pady=(UI_SETTINGS["spacing"]["lg"], UI_SETTINGS["spacing"]["lg"]), side="bottom")

        self.generate_btn = ctk.CTkButton(
            button_frame, text="Generate Report", font=FONT_SIDEBAR, height=UI_SETTINGS["button_height"],
            fg_color=COLOR_PRIMARY, hover_color=COLOR_ACCENT, command=self._generate_report
        )
        self.generate_btn.pack(fill="x", pady=(0, UI_SETTINGS["spacing"]["sm"]))

        open_folder_btn = ctk.CTkButton(
            button_frame, text="Open Reports Folder", font=FONT_BODY, height=UI_SETTINGS["button_height"],
            fg_color=COLOR_ELEVATION_3, hover_color=COLOR_ELEVATION_4, command=self._open_reports_folder
        )
        open_folder_btn.pack(fill="x")

        # --- Status Label ---
        self.status_label = ctk.CTkLabel(panel, text="", font=FONT_BODY_SMALL, text_color=COLOR_TEXT_SECONDARY)
        self.status_label.pack(side="bottom", fill="x", padx=UI_SETTINGS["spacing"]["lg"], pady=(0, UI_SETTINGS["spacing"]["sm"]))

        return panel
    
    def _create_history_panel(self, parent) -> ctk.CTkFrame:
        """Builds the right panel displaying report history and stats."""
        panel = ModernComponents.create_card(parent)
        panel.grid_rowconfigure(3, weight=1) # Make scroll_frame expand
        panel.grid_columnconfigure(0, weight=1)

        # --- Header and Sort Controls ---
        header_frame = ctk.CTkFrame(panel, fg_color="transparent")
        header_frame.grid(row=0, column=0, sticky="ew", padx=UI_SETTINGS["spacing"]["lg"], pady=(UI_SETTINGS["spacing"]["lg"], 0))

        ctk.CTkLabel(header_frame, text="Generated Reports History", font=FONT_HEADING, text_color=COLOR_TEXT).pack(side="left")

        sort_label = ctk.CTkLabel(header_frame, text="Sort by:", font=FONT_BODY_SMALL, text_color=COLOR_TEXT_SECONDARY)
        sort_label.pack(side="right", padx=(0, UI_SETTINGS["spacing"]["xs"]))
        sort_menu = ctk.CTkOptionMenu(
             header_frame, variable=self.sort_key,
             values=["Date (Newest)", "Date (Oldest)", "Type (A-Z)", "Format (A-Z)"],
             font=FONT_BODY_SMALL, dropdown_font=FONT_BODY_SMALL, width=140, height=28,
             command=lambda *_: self._sort_and_render_reports() # Trigger sort on change
        )
        sort_menu.pack(side="right", pady=3)


        # --- Summary Stats ---
        stats_frame = ctk.CTkFrame(panel, fg_color=COLOR_ELEVATION_1, corner_radius=UI_SETTINGS["corner_radius"])
        stats_frame.grid(row=1, column=0, sticky="ew", padx=UI_SETTINGS["spacing"]["lg"], pady=UI_SETTINGS["spacing"]["sm"])
        stats_frame.grid_columnconfigure((0,1), weight=1) # Equal weight for stats

        self.total_reports_label = self._create_stat_item(stats_frame, 0, "Total Reports")
        self.top_format_label = self._create_stat_item(stats_frame, 1, "Top Format")

        # --- Report List Header ---
        # Add headers above the scrollable list
        list_header_frame = ctk.CTkFrame(panel, fg_color="transparent")
        list_header_frame.grid(row=2, column=0, sticky="ew", padx=UI_SETTINGS["spacing"]["lg"]+15, pady=(UI_SETTINGS["spacing"]["xs"], 0)) # Align with scroll list padding
        list_header_frame.grid_columnconfigure(1, weight=1) # Allow Name/Date to expand
        ctk.CTkLabel(list_header_frame, text="", width=40).grid(row=0, column=0) # Spacer for icon
        ctk.CTkLabel(list_header_frame, text="Name / Date", anchor="w", font=FONT_BODY_SMALL, text_color=COLOR_TEXT_SECONDARY).grid(row=0, column=1, sticky="w")
        ctk.CTkLabel(list_header_frame, text="Actions", anchor="e", font=FONT_BODY_SMALL, text_color=COLOR_TEXT_SECONDARY).grid(row=0, column=2, sticky="e", padx=10)


        # --- Report Scrollable List ---
        self.scroll_frame = ctk.CTkScrollableFrame(
            panel, fg_color=COLOR_BG, corner_radius=UI_SETTINGS["corner_radius"],
            border_color=COLOR_ELEVATION_3, border_width=1
        )
        self.scroll_frame.grid(row=3, column=0, sticky="nsew", padx=UI_SETTINGS["spacing"]["lg"], pady=(0, UI_SETTINGS["spacing"]["lg"]))

        return panel

    def _create_stat_item(self, parent, col, title):
        """Helper to create a small stat display item."""
        frame = ctk.CTkFrame(parent, fg_color="transparent")
        frame.grid(row=0, column=col, sticky="w", padx=UI_SETTINGS["spacing"]["md"], pady=UI_SETTINGS["spacing"]["sm"])
        ctk.CTkLabel(frame, text=title, font=FONT_BODY_SMALL, text_color=COLOR_TEXT_SECONDARY).pack(anchor="w")
        value_label = ctk.CTkLabel(frame, text="-", font=FONT_HEADING, text_color=COLOR_TEXT)
        value_label.pack(anchor="w")
        return value_label

    # --- Data Loading and Rendering ---
    def _load_reports(self):
        """Fetches report metadata from DB and triggers rendering."""
        try:
            self.reports = DB.list_reports() # Fetch fresh list
            self._sort_and_render_reports() # Sort and display
            self._update_summary_stats()
        except Exception as e:
            messagebox.showerror("Database Error", f"Could not load report history: {e}", parent=self)
            self.reports = [] # Ensure list is empty on error
            self._render_report_list() # Show empty message

    def _sort_and_render_reports(self):
        """Sorts the self.reports list based on self.sort_key and re-renders."""
        sort_option = self.sort_key.get()
        reverse_sort = False
        key_func = lambda r: r.get('timestamp', '') # Default: Date (Newest first implicitly due to DB query)

        if sort_option == "Date (Newest)":
             reverse_sort = True
             key_func = lambda r: r.get('timestamp', '')
        elif sort_option == "Date (Oldest)":
             reverse_sort = False
             key_func = lambda r: r.get('timestamp', '')
        elif sort_option == "Type (A-Z)":
             key_func = lambda r: r.get('type', '').lower()
        elif sort_option == "Format (A-Z)":
             key_func = lambda r: r.get('format', '').lower()

        try:
             self.reports.sort(key=key_func, reverse=reverse_sort)
        except Exception as e:
             print(f"Error sorting reports: {e}") # Log error but continue

        self._render_report_list()


    def _render_report_list(self):
        """Clears and re-populates the visual report list."""
        # Efficiently destroy old widgets
        for w in list(self.scroll_frame.winfo_children()): w.destroy()

        if not self.reports:
            ctk.CTkLabel(self.scroll_frame, text="No reports generated yet.", text_color=COLOR_TEXT_SECONDARY, font=FONT_BODY).pack(expand=True, pady=50)
            return

        # Add new widgets based on the (now sorted) self.reports list
        for r in self.reports: self._add_report_widget(r)

    def _add_report_widget(self, report: dict):
        """Creates a single styled row for a report in the history list."""
        # Use a card for each item for better visual separation
        widget = ModernComponents.create_card(self.scroll_frame) 
        # Set specific colors AFTER creation
        widget.configure(fg_color=COLOR_ELEVATION_3, border_color=COLOR_ELEVATION_4)

        widget.pack(fill="x", pady=UI_SETTINGS["spacing"]["xs"], padx=UI_SETTINGS["spacing"]["xs"])
        widget.grid_columnconfigure(1, weight=1) # Allow text area to expand

        # Icon based on format
        icon_map = {"PDF": "📄", "CSV": "📊", "JSON": "{ }"}
        icon = icon_map.get(str(report.get("format", "")).upper(), "📁") # Default icon
        ctk.CTkLabel(widget, text=icon, font=("Segoe UI Emoji", 24), text_color=COLOR_ACCENT).grid(
            row=0, column=0, rowspan=2, padx=(UI_SETTINGS["spacing"]["md"], UI_SETTINGS["spacing"]["sm"]), pady=UI_SETTINGS["spacing"]["sm"]
        )

        # Format timestamp nicely
        ts_str_display = "Unknown Date"
        ts_raw = report.get('timestamp')
        if ts_raw:
             try: ts = datetime.fromisoformat(ts_raw); ts_str_display = ts.strftime("%Y-%m-%d %H:%M")
             except (ValueError, TypeError): ts_str_display = str(ts_raw)[:16] # Fallback

        # Report Type and Date
        title_text = f"{report.get('type', 'Unknown Report')} ({ts_str_display})"
        ctk.CTkLabel(widget, text=title_text, font=FONT_BODY_MEDIUM, anchor="w", text_color=COLOR_TEXT).grid(
            row=0, column=1, sticky="ew", pady=(UI_SETTINGS["spacing"]["sm"], 0)
        )
        # Filename
        ctk.CTkLabel(widget, text=report.get('filename', 'N/A'), font=FONT_BODY_SMALL, text_color=COLOR_TEXT_SECONDARY, anchor="w").grid(
            row=1, column=1, sticky="ew", pady=(0, UI_SETTINGS["spacing"]["sm"])
        )

        # Action Buttons Frame
        actions = ctk.CTkFrame(widget, fg_color="transparent")
        actions.grid(row=0, column=2, rowspan=2, padx=UI_SETTINGS["spacing"]["md"])

        # Open Button
        open_btn = ctk.CTkButton(
            actions, text="Open", width=70, height=30, font=FONT_BODY_SMALL,
            fg_color=COLOR_ELEVATION_4, hover_color=COLOR_PRIMARY_VARIANT,
            command=lambda f=report.get('filename'): self._open_report_file(f) if f else None
        )
        open_btn.pack(side="left", padx=(0, UI_SETTINGS["spacing"]["xs"]))

        # Delete Button
        delete_btn = ctk.CTkButton(
            actions, text="Delete", width=70, height=30, font=FONT_BODY_SMALL,
            fg_color=COLOR_RED, hover_color=COLOR_ORANGE,
            command=lambda rid=report.get('id'), fname=report.get('filename'): self._delete_report(rid, fname) if rid else None
        )
        delete_btn.pack(side="left")

    def _update_summary_stats(self):
        """Updates the Total Reports and Top Format labels."""
        total_count = len(self.reports)
        self.total_reports_label.configure(text=str(total_count))
        if total_count > 0:
            format_counts = Counter(r.get('format', 'N/A') for r in self.reports)
            top_format = format_counts.most_common(1)[0][0] if format_counts else "N/A"
            self.top_format_label.configure(text=top_format)
        else:
            self.top_format_label.configure(text="N/A")

    # --- File System Interaction ---
    def _open_reports_folder(self):
        """Opens the REPORTS_DIR in the native file explorer."""
        path = os.path.realpath(REPORTS_DIR)
        try:
            if sys.platform == "win32": os.startfile(path)
            elif sys.platform == "darwin": subprocess.run(["open", path], check=True)
            else: subprocess.run(["xdg-open", path], check=True)
        except FileNotFoundError:
             messagebox.showerror("Error", f"Reports folder not found:\n{path}", parent=self)
        except Exception as e:
            messagebox.showerror("Error", f"Could not open reports folder: {e}\nPath: {path}", parent=self)

    def _open_report_file(self, filename: Optional[str]):
        """Attempts to open a specific report file with the default app."""
        if not filename: return
        filepath = os.path.join(REPORTS_DIR, filename)
        if not os.path.exists(filepath):
            messagebox.showerror("File Not Found", f"Report file '{filename}' not found.\nIt may have been moved or deleted.", parent=self)
            return
        try:
            if sys.platform == "win32": os.startfile(filepath)
            elif sys.platform == "darwin": subprocess.run(["open", filepath], check=True)
            else: subprocess.run(["xdg-open", filepath], check=True)
        except Exception as e:
            messagebox.showerror("Error", f"Could not open report file:\n{e}\nFile: {filepath}", parent=self)

    # --- Report Deletion ---
    def _delete_report(self, report_id: Optional[int], filename: Optional[str]):
        """Deletes report record from DB and the associated file."""
        if report_id is None or filename is None: return
        if not messagebox.askyesno("Confirm Delete", f"Delete report record and file?\n'{filename}'\n\nThis cannot be undone.", icon='warning', parent=self):
             return

        delete_success = False
        try:
            # Delete DB record first
            DB.delete_report(report_id)
            delete_success = True
            print(f"Deleted report record ID: {report_id}")
        except Exception as e_db:
            messagebox.showerror("Database Error", f"Could not delete report record from database.\nError: {e_db}", parent=self)

        # Only delete file if DB record was successfully deleted
        if delete_success:
            try:
                filepath = os.path.join(REPORTS_DIR, filename)
                if os.path.exists(filepath):
                    os.remove(filepath)
                    print(f"Deleted report file: {filepath}")
                else:
                    print(f"Report file not found (already deleted?): {filepath}")
                self._show_status_message(f"Report '{filename}' deleted.", "info")
            except Exception as e_file:
                # Warn user if file couldn't be deleted, but record is gone
                messagebox.showwarning("File Deletion Warning", f"Report record deleted, but could not delete the file '{filename}'. You may need to remove it manually.\nError: {e_file}", parent=self)

        # Refresh the list regardless of file deletion outcome
        self._load_reports()


    # --- Date Preset Helper ---
    def _set_date_preset(self, preset: str):
        """Sets the start and end date entries based on a preset string."""
        end = datetime.now()
        start = end
        if preset == "Today":
             start = end.replace(hour=0, minute=0, second=0, microsecond=0)
        elif preset == "Last 7 Days":
             start = (end - timedelta(days=6)).replace(hour=0, minute=0, second=0, microsecond=0)
        elif preset == "Last 30 Days":
             start = (end - timedelta(days=29)).replace(hour=0, minute=0, second=0, microsecond=0)

        self.start_date_entry.delete(0, 'end')
        self.start_date_entry.insert(0, start.strftime("%Y-%m-%d"))
        self.end_date_entry.delete(0, 'end')
        self.end_date_entry.insert(0, end.strftime("%Y-%m-%d"))


    # --- Report Generation ---
    def _generate_report(self):
        """Validates input, generates report file, saves DB record."""
        # --- FIX: Loading State Management Start ---
        if self.generate_btn:
            self.generate_btn.configure(state="disabled", text="Generating...")
            self.update_idletasks()
        # --- FIX: Loading State Management End ---
        
        start_str = self.start_date_entry.get().strip()
        end_str = self.end_date_entry.get().strip()
        filepath = None
        
        try:
            # 1. Input Validation
            start_date = datetime.strptime(start_str, "%Y-%m-%d")
            end_date_for_filter = datetime.strptime(end_str, "%Y-%m-%d") + timedelta(days=1)
            if start_date >= end_date_for_filter: 
                 raise ValueError("Start date must be before end date.")
        except ValueError as e:
            messagebox.showerror("Invalid Date", f"Please use YYYY-MM-DD format.\nError: {e}", parent=self)
            return
        finally:
            # Re-enable button ONLY if error happened before file generation began
            if filepath is None and self.generate_btn:
                self.generate_btn.configure(state="normal", text="Generate Report")
                
        
        report_type = self.report_type.get()
        fmt_full = self.export_format.get() 
        fmt = fmt_full.split(" ")[0].lower() # "csv", "pdf", "json"
        
        # Generate filename
        filename = f"{report_type.replace(' ','_')}_{start_str}_to_{end_str}_{datetime.now().strftime('%H%M%S')}.{fmt}"
        filepath = os.path.join(REPORTS_DIR, filename) # Filepath is now defined
        status_msg = "Starting report generation..."
        success = False
        self._show_status_message(status_msg, "info")
        self.update_idletasks()

        try:
            record_count = 0 
            
            # 2. Dry Run: Get record count for CSV/PDF
            if fmt == "csv":
                record_count = self._save_csv_report(filepath, report_type, start_date, end_date_for_filter, dry_run=True)
            elif fmt == "pdf" and REPORTLAB_AVAILABLE:
                 record_count = self._save_pdf_report(filepath, report_type, start_date, end_date_for_filter, dry_run=True)
            elif fmt == "pdf" or fmt == "json":
                 # Simulation/JSON always proceeds if the date is valid, assume data exists
                 if fmt == 'json': record_count = 5 
                 elif fmt == 'pdf' and not REPORTLAB_AVAILABLE: record_count = 5

            
            # --- FIX: Check for empty report before proceeding (Functionality Fix) ---
            if record_count == 0:
                messagebox.showinfo("No Data Found", f"No records found for '{report_type}' in the selected date range. No file was created.", parent=self)
                return # Exit successfully without creating a file or DB record
            # --- End FIX ---
            
            # 3. Save Final File 
            if fmt == "csv":
                record_count = self._save_csv_report(filepath, report_type, start_date, end_date_for_filter, dry_run=False)
                status_msg = f"Generated CSV with {record_count} records."
                success = True
            elif fmt == "pdf" and REPORTLAB_AVAILABLE:
                 record_count = self._save_pdf_report(filepath, report_type, start_date, end_date_for_filter, dry_run=False)
                 status_msg = f"Generated PDF with {record_count} records."
                 success = True
            else: # Simulated PDF/JSON 
                content = {
                    "report_info": {"title": "AI LAD Report", "type": report_type, "date_range": f"{start_str} to {end_str}", "generated_on": datetime.now().isoformat(), "format": fmt.upper()},
                    "status": "SIMULATED CONTENT", "message": f"Real data export implemented for CSV.{' Basic PDF available.' if REPORTLAB_AVAILABLE else ''}",
                    "simulated_data_summary": {"records_processed": record_count}
                }
                with open(filepath, "w", encoding="utf-8") as f:
                     if fmt == "json": json.dump(content, f, indent=4)
                     else: # Basic text for PDF sim if reportlab is missing
                         f.write(f"--- AI LAD Report ({fmt.upper()}) ---\n\n")
                         for key, value in content["report_info"].items(): f.write(f"{key.replace('_',' ').title()}: {value}\n")
                         f.write(f"\nStatus: {content['status']}\n{content['message']}\n")
                         f.write(f"\nSummary: {content['simulated_data_summary']}")
                status_msg = f"Generated simulated {fmt.upper()} report."
                success = True

            if success:
                # 4. Finalize
                DB.insert_report(report_type, filename, fmt.upper(), f"{start_str} to {end_str}")
                self._load_reports() # Refresh history list
                self._show_status_message(f"Report '{filename}' saved.", "success")
                if messagebox.askyesno("Report Generated", f"{status_msg}\n\nOpen reports folder?", parent=self):
                    self._open_reports_folder()
            else:
                 raise Exception("Report generation failed (unknown reason).")

        except Exception as e:
            err_msg = f"Could not generate report: {e}"
            self._show_status_message(f"Error: {e}", "error")
            messagebox.showerror("Save Error", err_msg, parent=self)
            # Clean up potentially incomplete file if generation failed mid-way
            if os.path.exists(filepath):
                 try: os.remove(filepath)
                 except Exception as e_del: print(f"Could not remove partial report file '{filepath}': {e_del}")

        finally:
            # Re-enable button after processing finishes
            if self.generate_btn:
                self.generate_btn.configure(state="normal", text="Generate Report")


    def _save_csv_report(self, path: str, report_type: str, start_date: datetime, end_date: datetime, dry_run: bool = False) -> int:
        """Generates CSV report by querying the DB. Returns record count."""
        records = []
        headers = []

        # --- Query Database based on Report Type ---
        start_ts_str = start_date.strftime('%Y-%m-%d %H:%M:%S')
        end_ts_str = end_date.strftime('%Y-%m-%d %H:%M:%S')

        try:
            if report_type == "Anomaly Details" or report_type == "Security Audit":
                # Fetch relevant columns from audit_log, filtering by action type and date
                sql = f"""
                     SELECT timestamp, action, details, user_id
                     FROM audit_log
                     WHERE timestamp >= ? AND timestamp < ?
                     AND (action LIKE ? OR action LIKE ? OR action LIKE ? OR action LIKE ?) /* Adjust based on actual anomaly actions */
                     ORDER BY timestamp DESC
                """
                params = (start_ts_str, end_ts_str, '%ANOMALY%', '%FAIL%', '%BLOCK%', '%ALERT%') # Example params
                cursor = DB._exec(sql, params)
                records = cursor.fetchall()
                headers = ["Timestamp", "Action", "Details", "UserID"]

            elif report_type == "User Activity":
                 # Fetch all actions for the date range, joining with users table
                 sql = """
                      SELECT al.timestamp, al.action, al.details, u.email
                      FROM audit_log al
                      LEFT JOIN users u ON al.user_id = u.id
                      WHERE al.timestamp >= ? AND al.timestamp < ?
                      ORDER BY al.timestamp DESC
                 """
                 params = (start_ts_str, end_ts_str)
                 cursor = DB._exec(sql, params)
                 records = cursor.fetchall()
                 headers = ["Timestamp", "Action", "Details", "UserEmail"]

            # Executive Summary Placeholder (Simulated records)
            else: 
                 headers = ["Summary Item", "Value"]
                 records = [("Total Logs Processed (Simulated)", "1,234,567"),
                              ("Anomalies Detected (Simulated)", "5,678"),
                              ("Top Anomaly Type (Simulated)", "Login Failed")]
                 if dry_run: return len(records)
                 
            # --- Check dry run and return record count ---
            if dry_run:
                 return len(records)
            # --- End FIX ---

            count = 0
            with open(path, "w", newline="", encoding="utf-8") as f:
                 writer = csv.writer(f)
                 writer.writerow(headers) # Write header row

                 if not records:
                      writer.writerow(["No data found for the selected criteria."] + [""] * (len(headers)-1))
                 else:
                      for record in records:
                           # FIX: Safely access data using lowercase keys directly
                           row_data = [record[h.lower()] if h.lower() in record.keys() else 'N/A' for h in headers]
                           writer.writerow(row_data)
                           count += 1
            print(f"Generated CSV report '{report_type}' with {count} records.")
            return count

        except sqlite3.Error as db_e:
             print(f"Database query error for report '{report_type}': {db_e}")
             raise Exception(f"Database query failed: {db_e}") # Re-raise to be caught by _generate_report
        except Exception:
             raise # Re-raise


    def _save_pdf_report(self, path: str, report_type: str, start_date: datetime, end_date: datetime, dry_run: bool = False) -> int:
        """Generates a basic PDF report using ReportLab. Returns record count."""
        if not REPORTLAB_AVAILABLE:
             raise ImportError("ReportLab library not found. Cannot generate PDF.")

        # --- Fetch Data (Run query first) ---
        records = []
        headers = []
        start_ts_str = start_date.strftime('%Y-%m-%d %H:%M:%S')
        end_ts_str = end_date.strftime('%Y-%m-%d %H:%M:%S')

        try:
             # Basic query - fetch recent audit logs for demonstration
             sql = "SELECT timestamp, action, details FROM audit_log WHERE timestamp >= ? AND timestamp < ? ORDER BY timestamp DESC LIMIT 100"
             params = (start_ts_str, end_ts_str)
             cursor = DB._exec(sql, params)
             records = cursor.fetchall()
             headers = ["Timestamp", "Action", "Details"]
        except sqlite3.Error as db_e:
             print(f"PDF DB query error: {db_e}")
             raise Exception(f"PDF Database query failed: {db_e}")
        
        # --- FIX: Check dry run and return record count ---
        if dry_run:
             return len(records)
        # --- End FIX ---
        
        # --- Proceed to PDF Generation ---
        doc = SimpleDocTemplate(path, pagesize=letter)
        # FIX: The original code had a typo here: getSampleStyleStyleSheet should be getSampleStyleSheet
        try: styles = getSampleStyleSheet()
        except NameError: styles = getSampleStyleSheet() 
        story = []

        # --- Title ---
        title = f"AI LAD Report: {report_type}"
        story.append(Paragraph(title, styles['h1']))
        story.append(Spacer(1, 12))

        # --- Date Range ---
        date_range_str = f"Date Range: {start_date.strftime('%Y-%m-%d')} to {(end_date - timedelta(days=1)).strftime('%Y-%m-%d')}"
        story.append(Paragraph(date_range_str, styles['Normal']))
        story.append(Paragraph(f"Generated On: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
        story.append(Spacer(1, 24))

        if not records:
            story.append(Paragraph("No data found for the selected criteria.", styles['Italic']))
        else:
             # --- Create Table ---
             table_data = [headers] # Start with header row
             for record in records:
                  # Format row data for PDF table
                  row = [
                       str(record['timestamp']),
                       str(record['action']),
                       Paragraph(str(record['details'])[:200], styles['Code']) # Use Code style, limit length
                  ]
                  table_data.append(row)

             # Define Table Style
             table_style = TableStyle([
                  ('BACKGROUND', (0,0), (-1,0), reportlab_colors.grey),
                  ('TEXTCOLOR', (0,0), (-1,0), reportlab_colors.whitesmoke),
                  ('ALIGN', (0,0), (-1,-1), 'CENTER'),
                  ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                  ('BOTTOMPADDING', (0,0), (-1,0), 12),
                  ('BACKGROUND', (0,1), (-1,-1), reportlab_colors.beige),
                  ('GRID', (0,0), (-1,-1), 1, reportlab_colors.black),
                  ('VALIGN', (0,0), (-1,-1), 'MIDDLE'), # Vertical alignment
                  ('FONTNAME', (0,1), (-1,-1), 'Helvetica'),
                  ('FONTSIZE', (0,1), (-1,-1), 9),
                  ('LEFTPADDING', (0,0), (-1,-1), 4),
                  ('RIGHTPADDING', (0,0), (-1,-1), 4),
             ])

             # Create Table object and apply style
             pdf_table = Table(table_data, colWidths=[100, 100, 300]) # Adjust column widths
             pdf_table.setStyle(table_style)
             story.append(pdf_table)

        # --- Build PDF ---
        try:
             doc.build(story)
             print(f"Generated PDF report with {len(records)} records.")
             return len(records)
        except Exception as e_pdf:
             print(f"Error during PDF generation: {e_pdf}")
             raise Exception(f"PDF generation failed: {e_pdf}")


    # --- UI Helpers ---
    def _show_status_message(self, message: str, status: str = "info"):
        """Displays a non-blocking status message."""
        if not hasattr(self, 'status_label') or not self.status_label.winfo_exists(): return

        if self.status_label_job:
            try: self.after_cancel(self.status_label_job)
            except ValueError: pass # Ignore if job ID invalid
            self.status_label_job = None

        color_map = {"success": COLOR_SUCCESS, "error": COLOR_RED, "info": COLOR_TEXT_SECONDARY}
        self.status_label.configure(text=message, text_color=color_map.get(status, COLOR_TEXT_SECONDARY))

        if message: # Set timer to clear the message
             self.status_label_job = self.after(4000, lambda: self.status_label.configure(text="") if self.status_label.winfo_exists() else None)
