import customtkinter as ctk
from tkinter import messagebox, filedialog
from src.config import *
from src.backend.database_manager import get_db_instance
import sqlite3
import csv
import json
from src.ui.components.modern_components import ModernComponents
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
import traceback
import os
from datetime import datetime 

# --- Call the function to get the instance ---
# This initializes the DB and gets the singleton instance
DB = get_db_instance()

@dataclass
class Rule:
    """Dataclass to hold complex rule information."""
    id: Optional[int]
    name: str
    enabled: bool
    priority: int = 0
    condition: Dict[str, Any] = field(default_factory=dict)
    action: Dict[str, Any] = field(default_factory=dict)

    PRIORITY_MAP_TO_INT = {"Highest": 0, "High": 1, "Medium": 2, "Low": 3, "Lowest": 4}
    PRIORITY_MAP_TO_STR = {v: k for k, v in PRIORITY_MAP_TO_INT.items()}
    # Define colors for use in the UI list display
    PRIORITY_COLORS = {
        0: COLOR_RED,          # Highest
        1: COLOR_ORANGE,       # High
        2: COLOR_ACCENT,       # Medium
        3: COLOR_TEXT_SECONDARY,# Low
        4: COLOR_TEXT_SECONDARY # Lowest
    }

    def get_priority_str(self) -> str:
        return self.PRIORITY_MAP_TO_STR.get(self.priority, "Medium")

    def set_priority_from_str(self, priority_str: str):
        self.priority = self.PRIORITY_MAP_TO_INT.get(priority_str, 2)


class ResponseRulesPage(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent, fg_color="transparent")
        self.controller = controller
        # Use DB's internal user info for simplicity in this example
        self.user_info = DB.user_info 
        self.rules: List[Rule] = []
        self.selected_rule: Optional[Rule] = None
        self.selected_widget: Optional[ctk.CTkFrame] = None
        self.status_label_job = None

        # --- Icons ---
        self.CONDITION_ICONS = {
            "Severity Level": "🔥", "Source IP": "🌐", "Log Message Content": "📄",
            "Repeated Event": "🔄"
        }
        self.ACTION_ICONS = {
            "Block IP": "⛔", "Send Email Alert": "📧", "Execute Script": "⚙️", "Log Event": "📝"
        }

        # --- Main Layout ---
        container = ctk.CTkFrame(self, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=UI_SETTINGS["spacing"]["md"], pady=UI_SETTINGS["spacing"]["md"])

        container.grid_columnconfigure(0, weight=1, minsize=300) 
        container.grid_columnconfigure(1, weight=2) 
        container.grid_rowconfigure(0, weight=1) 

        self.left_panel = self._create_left_panel(container)
        self.right_panel = self._create_right_panel(container)

        self.left_panel.grid(row=0, column=0, sticky="nsew", padx=(0, UI_SETTINGS["spacing"]["md"]))
        self.right_panel.grid(row=0, column=1, sticky="nsew")

        # --- Initial Load ---
        self._load_and_populate_rules()
        self._clear_editor_form(show_placeholder=True) # Show placeholder on initial load

    def stop_threads(self):
        """Placeholder for stopping potential background tasks."""
        print("ResponseRulesPage stopping.")
        if self.status_label_job:
            try: self.after_cancel(self.status_label_job)
            except ValueError: pass
            self.status_label_job = None

    # --- Left Panel (Rule List) ---
    def _create_left_panel(self, parent) -> ctk.CTkFrame:
        panel = ModernComponents.create_card(parent, width=300) # Use modern card
        panel.pack_propagate(False)
        panel.grid_rowconfigure(2, weight=1)
        panel.grid_columnconfigure(0, weight=1)

        # Header
        header_frame = ctk.CTkFrame(panel, fg_color="transparent")
        header_frame.grid(row=0, column=0, sticky="ew", padx=15, pady=15)
        ctk.CTkLabel(header_frame, text="Response Rules", font=FONT_HEADING, text_color=COLOR_TEXT).pack(side="left")
        
        # Button to add new rule, clears form
        ctk.CTkButton(header_frame, text="+ Add New Rule", height=UI_SETTINGS["button_height"]-10, font=FONT_BODY_MEDIUM,
                      fg_color=COLOR_PRIMARY, hover_color=COLOR_PRIMARY_VARIANT,
                      command=lambda: self._clear_editor_form(show_placeholder=False)).pack(side="right") 

        # Search/Filter
        search_frame = ctk.CTkFrame(panel, fg_color="transparent")
        search_frame.grid(row=1, column=0, sticky="ew", padx=15, pady=(0, 10))
        self.search_var = ctk.StringVar(value="")
        self.search_entry = ctk.CTkEntry(search_frame, placeholder_text="Search rules...", textvariable=self.search_var, font=FONT_BODY_SMALL, 
                                         fg_color=COLOR_ELEVATION_2, border_color=COLOR_ELEVATION_3, height=UI_SETTINGS["button_height"]-10) 
        self.search_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
        self.search_var.trace_add("write", lambda *_: self._filter_and_render()) 
        
        self.filter_var = ctk.StringVar(value="All")
        ctk.CTkOptionMenu(search_frame, values=["All", "Enabled", "Disabled"], variable=self.filter_var, width=80, 
                          font=FONT_BODY_SMALL, dropdown_font=FONT_BODY_SMALL, height=UI_SETTINGS["button_height"]-10, 
                          fg_color=COLOR_ELEVATION_2, button_color=COLOR_ELEVATION_3, button_hover_color=COLOR_ELEVATION_4,
                          command=self._filter_and_render).pack(side="left")

        # Scrollable List
        self.scroll_frame = ctk.CTkScrollableFrame(panel, fg_color=COLOR_BG, corner_radius=UI_SETTINGS["corner_radius"],
                                                   border_color=COLOR_ELEVATION_3, border_width=1)
        self.scroll_frame.grid(row=2, column=0, sticky="nsew", padx=15, pady=(0, 10))

        # Import/Export
        io_frame = ctk.CTkFrame(panel, fg_color="transparent")
        io_frame.grid(row=3, column=0, sticky="ew", padx=15, pady=(0, 15))
        io_frame.grid_columnconfigure((0,1), weight=1) 
        ctk.CTkButton(io_frame, text="Import Rules", height=UI_SETTINGS["button_height"]-10, font=FONT_BODY,
                      fg_color=COLOR_ELEVATION_3, hover_color=COLOR_ELEVATION_4, command=self._import_rules).grid(row=0, column=0, sticky="ew", padx=(0,5))
        ctk.CTkButton(io_frame, text="Export Rules", height=UI_SETTINGS["button_height"]-10, font=FONT_BODY,
                      fg_color=COLOR_ELEVATION_3, hover_color=COLOR_ELEVATION_4, command=self._export_rules).grid(row=0, column=1, sticky="ew", padx=(5,0))

        return panel

    # --- Right Panel (Rule Editor) ---
    def _create_right_panel(self, parent) -> ctk.CTkFrame:
        """
        [REDESIGN] Builds the right panel using a pinned Setup Card and a Tabview 
        for the complex Condition/Action configuration.
        """
        panel = ModernComponents.create_card(parent)
        
        # Row 1: Setup Card (fixed height)
        # Row 2: Tabview (expands)
        # Row 3: Buttons (fixed height)
        panel.grid_rowconfigure(2, weight=1) # Tabview (Row 2) expands
        panel.grid_rowconfigure(3, weight=0) # Button row (Row 3) is fixed
        panel.grid_columnconfigure(0, weight=1) 

        # Editor Title (Row 0)
        self.editor_title = ctk.CTkLabel(panel, text="Rule Editor", font=FONT_HEADING, text_color=COLOR_TEXT)
        self.editor_title.grid(row=0, column=0, sticky="w", padx=20, pady=20)
        
        # -----------------------------------------------------
        # 1. CONSOLIDATED SETUP CARD (Row 1) - Rule Name, Priority, Status
        # -----------------------------------------------------
        self.setup_card = ModernComponents.create_card(panel, fg_color=COLOR_ELEVATION_1)
        self.setup_card.grid(row=1, column=0, sticky="ew", padx=20, pady=(0, 10))
        self.setup_card.grid_columnconfigure(0, weight=1) # Name
        self.setup_card.grid_columnconfigure(1, weight=0) # Priority
        self.setup_card.grid_columnconfigure(2, weight=0) # Enabled Switch

        # Rule Name 
        ctk.CTkLabel(self.setup_card, text="Rule Name", font=FONT_BODY_MEDIUM).grid(row=0, column=0, sticky="w", padx=10, pady=(10, 0))
        self.name_entry = ctk.CTkEntry(
            self.setup_card, placeholder_text="e.g., Block IP on 5 failed logins", font=FONT_BODY,
            height=UI_SETTINGS["button_height"]-10, fg_color=COLOR_ELEVATION_2, border_color=COLOR_ELEVATION_3
        )
        self.name_entry.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 10))
        
        # Priority Segmented Button (Fixed Width)
        priority_frame = ctk.CTkFrame(self.setup_card, fg_color="transparent")
        priority_frame.grid(row=0, column=1, rowspan=2, sticky="ns", padx=(15, 10), pady=10)
        ctk.CTkLabel(priority_frame, text="Priority", font=FONT_BODY_SMALL, text_color=COLOR_TEXT_SECONDARY).pack(pady=(0, 2))
        self.priority_seg_btn = ctk.CTkSegmentedButton(
            priority_frame, values=list(Rule.PRIORITY_MAP_TO_INT.keys()), font=FONT_CAPTION, height=26, width=150,
            selected_color=COLOR_PRIMARY, selected_hover_color=COLOR_PRIMARY_VARIANT,
            unselected_color=COLOR_ELEVATION_3, unselected_hover_color=COLOR_ELEVATION_4
        )
        self.priority_seg_btn.set("Medium")
        self.priority_seg_btn.pack()
        
        # Enabled Switch
        enabled_frame = ctk.CTkFrame(self.setup_card, fg_color="transparent")
        enabled_frame.grid(row=0, column=2, rowspan=2, sticky="ns", pady=10, padx=(0, 10))
        ctk.CTkLabel(enabled_frame, text="Status", font=FONT_BODY_SMALL, text_color=COLOR_TEXT_SECONDARY).pack(pady=(0, 5))
        self.enabled_switch = ctk.CTkSwitch(enabled_frame, text="", font=FONT_BODY, progress_color=COLOR_PRIMARY)
        self.enabled_switch.pack(pady=5)
        
        # -----------------------------------------------------
        # 2. TABVIEW (Row 2) - Trigger and Response Configuration
        # -----------------------------------------------------
        self.tabview = ctk.CTkTabview(
            panel, 
            fg_color=COLOR_ELEVATION_1, 
            segmented_button_fg_color=COLOR_ELEVATION_2,
            segmented_button_selected_color=COLOR_PRIMARY,
            segmented_button_selected_hover_color=COLOR_PRIMARY_VARIANT,
            segmented_button_unselected_color=COLOR_ELEVATION_1,
            segmented_button_unselected_hover_color=COLOR_ELEVATION_3,
            text_color=COLOR_TEXT,
            height=0 # Allow it to expand vertically
        )
        self.tabview.grid(row=2, column=0, sticky="nsew", padx=20, pady=(0, 10))
        
        # --- Create Tabs ---
        trigger_tab = self.tabview.add("Trigger Condition")
        response_tab = self.tabview.add("Response Action")
        
        trigger_tab.grid_columnconfigure(0, weight=1)
        response_tab.grid_columnconfigure(0, weight=1)
        response_tab.grid_rowconfigure(2, weight=1) # Ensure the inner frame can expand
        
        # --- A. Trigger Tab UI ---
        ctk.CTkLabel(trigger_tab, text="Select Condition Type:", font=FONT_BODY_MEDIUM).grid(row=0, column=0, sticky="w", padx=20, pady=(15, 5))
        self.condition_menu = ctk.CTkOptionMenu(
            trigger_tab, values=list(self.CONDITION_ICONS.keys()), font=FONT_BODY,
            dropdown_font=FONT_BODY, height=UI_SETTINGS["button_height"]-5,
            fg_color=COLOR_ELEVATION_2, button_color=COLOR_ELEVATION_3, button_hover_color=COLOR_ELEVATION_4,
            command=self._build_condition_ui
        )
        self.condition_menu.grid(row=1, column=0, sticky="ew", padx=20, pady=(0, 10))
        
        self.condition_frame = ctk.CTkFrame(trigger_tab, fg_color="transparent")
        self.condition_frame.grid(row=2, column=0, sticky="nsew", padx=20, pady=(0, 15))
        self.condition_frame.grid_columnconfigure(0, weight=1) # Dynamic content frame expands
        
        # --- B. Response Tab UI ---
        ctk.CTkLabel(response_tab, text="Select Action Type:", font=FONT_BODY_MEDIUM).grid(row=0, column=0, sticky="w", padx=20, pady=(15, 5))
        self.action_menu = ctk.CTkOptionMenu(
            response_tab, values=list(self.ACTION_ICONS.keys()), font=FONT_BODY,
            dropdown_font=FONT_BODY, height=UI_SETTINGS["button_height"]-5,
            fg_color=COLOR_ELEVATION_2, button_color=COLOR_ELEVATION_3, button_hover_color=COLOR_ELEVATION_4,
            command=self._build_action_ui
        )
        self.action_menu.grid(row=1, column=0, sticky="ew", padx=20, pady=(0, 10))
        
        self.action_frame = ctk.CTkFrame(response_tab, fg_color="transparent")
        self.action_frame.grid(row=2, column=0, sticky="nsew", padx=20, pady=(0, 15))
        self.action_frame.grid_columnconfigure(0, weight=1) # Dynamic content frame expands


        # --- Empty State Placeholder (covers Tabview when no rule is selected) ---
        self.editor_placeholder = ctk.CTkFrame(panel, fg_color=COLOR_CARD)
        # Placeholder covers the Tabview area (Row 1-2)
        self.editor_placeholder.grid(row=1, column=0, rowspan=2, sticky="nsew", padx=20, pady=10) 
        
        ctk.CTkLabel(self.editor_placeholder, text="← Select a rule to edit",
                     font=FONT_HEADING, text_color=COLOR_TEXT_SECONDARY).pack(pady=(100, 10), expand=True)
        ctk.CTkLabel(self.editor_placeholder, text="or",
                     font=FONT_BODY, text_color=COLOR_TEXT_SECONDARY).pack(pady=5)
        ctk.CTkLabel(self.editor_placeholder, text="Click '+ Add New Rule' to start",
                     font=FONT_BODY_MEDIUM, text_color=COLOR_ACCENT).pack(pady=10)
        
        # -----------------------------------------------------
        # ACTION BUTTONS (Row 3 - Pinned to bottom using sticky="sew")
        # -----------------------------------------------------
        self.button_frame = ctk.CTkFrame(panel, fg_color="transparent")
        self.button_frame.grid(row=3, column=0, sticky="sew", padx=20, pady=(10, 20)) # Row 3 holds buttons
        self.button_frame.grid_columnconfigure(0, weight=1) # Status label space
        
        # --- UI Refinement: Adjust button weighting ---
        self.button_frame.grid_columnconfigure(1, weight=2) # SAVE button (Primary, more visual weight)
        self.button_frame.grid_columnconfigure(2, weight=1) # Test
        self.button_frame.grid_columnconfigure(3, weight=1) # Delete
        # ----------------------------------------------

        # Status Label (non-blocking messages)
        self.status_label = ctk.CTkLabel(self.button_frame, text="", text_color=COLOR_TEXT_SECONDARY, font=FONT_BODY_SMALL)
        self.status_label.grid(row=0, column=0, sticky="w", padx=(0, 10))

        # Save Button (Col 1) [Green/Success]
        self.save_btn = ctk.CTkButton(
            self.button_frame, text="Save Rule", height=UI_SETTINGS["button_height"],
            font=FONT_SIDEBAR, command=self._save_rule,
            fg_color=COLOR_SUCCESS, hover_color=COLOR_PRIMARY_VARIANT, text_color=COLOR_BG
        )
        self.save_btn.grid(row=0, column=1, sticky="ew", padx=(0, 5))
        
        # Test Button (Col 2) [Teal/Accent]
        self.test_btn = ctk.CTkButton(
            self.button_frame, text="Test Rule", height=UI_SETTINGS["button_height"],
            font=FONT_SIDEBAR, fg_color=COLOR_ACCENT, hover_color=COLOR_PRIMARY, text_color=COLOR_BG
        )
        self.test_btn.grid(row=0, column=2, sticky="ew", padx=5)
        self.test_btn.configure(command=self._test_rule) 

        # Delete Button (Col 3) [Red/Error]
        self.delete_btn = ctk.CTkButton(
            self.button_frame, text="Delete Rule", height=UI_SETTINGS["button_height"],
            font=FONT_SIDEBAR, fg_color=COLOR_ERROR, hover_color=COLOR_RED, text_color=COLOR_BG,
            command=self._delete_rule # Link delete function
        )
        self.delete_btn.grid(row=0, column=3, sticky="ew", padx=(5, 0))

        return panel

    def _build_condition_ui(self, condition_type: str, condition_data: dict = None):
        """Dynamically builds the UI for the selected trigger condition."""
        for widget in self.condition_frame.winfo_children(): widget.destroy()
        condition_data = condition_data or {}
        
        # NOTE: Removed outer card for simplicity inside the tab
        
        if condition_type == "Severity Level":
            ctk.CTkLabel(self.condition_frame, text="Trigger Severity:", font=FONT_BODY_SMALL).pack(anchor="w")
            self.condition_severity_menu = ctk.CTkOptionMenu(self.condition_frame, values=SEV_ORDER, font=FONT_BODY, dropdown_font=FONT_BODY, height=UI_SETTINGS["button_height"]-10, fg_color=COLOR_ELEVATION_2, button_color=COLOR_ELEVATION_3, button_hover_color=COLOR_ELEVATION_4)
            self.condition_severity_menu.pack(fill="x", pady=(0, 10))
            self.condition_severity_menu.set(condition_data.get("level", "Critical"))
            ctk.CTkLabel(self.condition_frame, text="Rule applies when severity is equal to or higher than selected level.", font=FONT_CAPTION, text_color=COLOR_TEXT_SECONDARY).pack(anchor="w")
            
        elif condition_type == "Source IP":
            ctk.CTkLabel(self.condition_frame, text="IP Address or CIDR:", font=FONT_BODY_SMALL).pack(anchor="w")
            self.condition_ip_entry = ctk.CTkEntry(self.condition_frame, placeholder_text="e.g., 192.168.1.100 or 10.0.0.0/24", font=FONT_BODY, height=UI_SETTINGS["button_height"]-10, fg_color=COLOR_ELEVATION_2, border_color=COLOR_ELEVATION_3)
            self.condition_ip_entry.pack(fill="x", pady=(0, 10))
            self.condition_ip_entry.insert(0, condition_data.get("ip_cidr", ""))
            ctk.CTkLabel(self.condition_frame, text="Use CIDR (e.g., /24) to match entire subnet.", font=FONT_CAPTION, text_color=COLOR_TEXT_SECONDARY).pack(anchor="w")
            
        elif condition_type == "Log Message Content":
            ctk.CTkLabel(self.condition_frame, text="Text Contains (Case-Insensitive):", font=FONT_BODY_SMALL).pack(anchor="w")
            self.condition_content_entry = ctk.CTkEntry(self.condition_frame, placeholder_text="e.g., 'failed login'", font=FONT_BODY, height=UI_SETTINGS["button_height"]-10, fg_color=COLOR_ELEVATION_2, border_color=COLOR_ELEVATION_3)
            self.condition_content_entry.pack(fill="x", pady=(0, 10))
            self.condition_content_entry.insert(0, condition_data.get("contains", ""))
            ctk.CTkLabel(self.condition_frame, text="Rule matches if this string is found anywhere in the log message.", font=FONT_CAPTION, text_color=COLOR_TEXT_SECONDARY).pack(anchor="w")
            
        elif condition_type == "Repeated Event":
            # Grid layout for two small inline inputs
            input_frame = ctk.CTkFrame(self.condition_frame, fg_color="transparent")
            input_frame.pack(fill="x", pady=5)
            input_frame.grid_columnconfigure(0, weight=1); input_frame.grid_columnconfigure(1, weight=1)
            
            # Occurrences
            ctk.CTkLabel(input_frame, text="Occurrences:", font=FONT_BODY_SMALL).grid(row=0, column=0, sticky="w")
            self.condition_attempts_entry = ctk.CTkEntry(input_frame, placeholder_text="e.g., 5", font=FONT_BODY, height=UI_SETTINGS["button_height"]-10, fg_color=COLOR_ELEVATION_2, border_color=COLOR_ELEVATION_3)
            self.condition_attempts_entry.grid(row=1, column=0, sticky="ew", padx=(0, 10))
            self.condition_attempts_entry.insert(0, str(condition_data.get("attempts", "5")))
            
            # Time Window
            ctk.CTkLabel(input_frame, text="Within Time (sec):", font=FONT_BODY_SMALL).grid(row=0, column=1, sticky="w")
            self.condition_window_entry = ctk.CTkEntry(input_frame, placeholder_text="e.g., 60", font=FONT_BODY, height=UI_SETTINGS["button_height"]-10, fg_color=COLOR_ELEVATION_2, border_color=COLOR_ELEVATION_3)
            self.condition_window_entry.grid(row=1, column=1, sticky="ew")
            self.condition_window_entry.insert(0, str(condition_data.get("window", "60")))
            
            ctk.CTkLabel(self.condition_frame, text="This rule tracks matching events by source IP over the time window.", font=FONT_CAPTION, text_color=COLOR_TEXT_SECONDARY).pack(anchor="w", pady=(10, 0))

        else: # Log Event
            ctk.CTkLabel(self.condition_frame, text="No additional configuration required.", text_color=COLOR_TEXT_SECONDARY, font=FONT_BODY_SMALL).pack(anchor="w")

    def _build_action_ui(self, action_type: str, action_data: Optional[Dict] = None):
        """Dynamically builds the UI for the selected response action."""
        for widget in self.action_frame.winfo_children(): widget.destroy()
        action_data = action_data or {}
        
        if action_type == "Block IP":
            ctk.CTkLabel(self.action_frame, text="Block Duration (minutes, 0 = permanent):", font=FONT_BODY_SMALL).pack(anchor="w")
            self.action_duration_entry = ctk.CTkEntry(self.action_frame, placeholder_text="e.g., 60", font=FONT_BODY, height=UI_SETTINGS["button_height"]-10, fg_color=COLOR_ELEVATION_2, border_color=COLOR_ELEVATION_3)
            self.action_duration_entry.pack(fill="x", pady=(0, 10))
            self.action_duration_entry.insert(0, str(action_data.get("duration", "60")))
            ctk.CTkLabel(self.action_frame, text="Note: This is a simulated action unless integrated with a firewall API.", font=FONT_CAPTION, text_color=COLOR_ORANGE).pack(anchor="w")

        elif action_type == "Send Email Alert":
            ctk.CTkLabel(self.action_frame, text="Recipient Email Address:", font=FONT_BODY_SMALL).pack(anchor="w")
            self.action_email_entry = ctk.CTkEntry(self.action_frame, placeholder_text="e.g., admin@example.com", font=FONT_BODY, height=UI_SETTINGS["button_height"]-10, fg_color=COLOR_ELEVATION_2, border_color=COLOR_ELEVATION_3)
            self.action_email_entry.pack(fill="x", pady=(0, 10))
            self.action_email_entry.insert(0, action_data.get("recipient", ""))
            
            ctk.CTkLabel(self.action_frame, text="Email Subject:", font=FONT_BODY_SMALL).pack(anchor="w", pady=(10, 0))
            self.action_subject_entry = ctk.CTkEntry(self.action_frame, placeholder_text="Alert: {rule_name} triggered by {ip}", font=FONT_BODY, height=UI_SETTINGS["button_height"]-10, fg_color=COLOR_ELEVATION_2, border_color=COLOR_ELEVATION_3)
            self.action_subject_entry.pack(fill="x", pady=(0, 10))
            self.action_subject_entry.insert(0, action_data.get("subject", "AI LAD Alert: {rule_name}"))
            ctk.CTkLabel(self.action_frame, text="Available template variables: {rule_name}, {ip}, {severity}.", font=FONT_CAPTION, text_color=COLOR_TEXT_SECONDARY).pack(anchor="w")

        elif action_type == "Execute Script":
            ctk.CTkLabel(self.action_frame, text="Path to Script (.bat, .sh, .py):", font=FONT_BODY_SMALL).pack(anchor="w")
            self.action_script_entry = ctk.CTkEntry(self.action_frame, placeholder_text="e.g., C:/scripts/remediator.py", font=FONT_BODY, height=UI_SETTINGS["button_height"]-10, fg_color=COLOR_ELEVATION_2, border_color=COLOR_ELEVATION_3)
            self.action_script_entry.pack(fill="x", pady=(0, 10))
            self.action_script_entry.insert(0, action_data.get("script_path", ""))
            
            ctk.CTkLabel(self.action_frame, text="Arguments:", font=FONT_BODY_SMALL).pack(anchor="w", pady=(10, 0))
            self.action_args_entry = ctk.CTkEntry(self.action_frame, placeholder_text="e.g., --ip {ip} --level {severity}", font=FONT_BODY, height=UI_SETTINGS["button_height"]-10, fg_color=COLOR_ELEVATION_2, border_color=COLOR_ELEVATION_3)
            self.action_args_entry.pack(fill="x", pady=(0, 10))
            self.action_args_entry.insert(0, action_data.get("arguments", ""))
            ctk.CTkLabel(self.action_frame, text="Use {ip}, {severity}, {message} in arguments.", font=FONT_CAPTION, text_color=COLOR_TEXT_SECONDARY).pack(anchor="w")

        else: # Log Event
            ctk.CTkLabel(self.condition_frame, text="No additional configuration required.", text_color=COLOR_TEXT_SECONDARY, font=FONT_BODY_SMALL).pack(anchor="w")

    def _load_and_populate_rules(self):
        """Loads rules from DB, fixes invalid JSON, and renders the list."""
        try:
            db_rules = DB.list_rules()
            self.rules = []
            for r in db_rules:
                try:
                    # Handle empty/invalid JSON strings
                    cond_str = r.get("condition", "{}")
                    act_str = r.get("action", "{}")
                    condition_dict = json.loads(cond_str) if cond_str and cond_str.strip() else {}
                    action_dict = json.loads(act_str) if act_str and act_str.strip() else {}

                    self.rules.append(Rule(
                        id=r["id"], name=r["name"], enabled=bool(r["enabled"]),
                        priority=r["priority"], condition=condition_dict, action=action_dict
                    ))
                except (json.JSONDecodeError, TypeError, KeyError) as e_parse:
                    print(f"Skipping malformed rule (ID: {r.get('id', 'N/A')}, Name: '{r.get('name', 'N/A')}') - Error: {e_parse}")

            self._filter_and_render()
        except Exception as e_load:
            messagebox.showerror("Database Error", f"Could not load rules: {e_load}", parent=self)
            self.rules = []
            self._filter_and_render()


    def _filter_and_render(self, _=None):
        """Applies filters/search and redraws the rule list."""
        for widget in list(self.scroll_frame.winfo_children()): widget.destroy()
        search_text = self.search_var.get().lower().strip()
        filter_status = self.filter_var.get()
        filtered = []
        for rule in self.rules:
            if filter_status == "Enabled" and not rule.enabled: continue
            if filter_status == "Disabled" and rule.enabled: continue
            condition_type = rule.condition.get("type", "").lower()
            action_type = rule.action.get("type", "").lower()
            if search_text and not (search_text in rule.name.lower() or search_text in condition_type or search_text in action_type):
                continue
            filtered.append(rule)

        if not filtered:
            ctk.CTkLabel(self.scroll_frame, text="No rules match your filters.", text_color=COLOR_TEXT_SECONDARY, font=FONT_BODY).pack(pady=20, padx=10)
            return

        for rule in sorted(filtered, key=lambda r: (r.priority, r.name.lower())):
            self._create_rule_widget(rule)


    def _create_rule_widget(self, rule: Rule):
        """Creates a styled card widget for a single rule with reduced vertical footprint."""
        widget = ModernComponents.create_card(self.scroll_frame) 
        
        # Determine visual style based on enabled state and priority
        status_color = Rule.PRIORITY_COLORS.get(rule.priority, COLOR_TEXT_SECONDARY)
        text_color = COLOR_TEXT if rule.enabled else COLOR_TEXT_SECONDARY
        
        # Initial colors
        # Reduced border_width from 2 to 1 for cleaner look
        widget.configure(fg_color=COLOR_ELEVATION_1, border_color=COLOR_ELEVATION_1, border_width=1) 
        
        # Priority Indicator on Left 
        priority_bar = ctk.CTkFrame(widget, width=4, fg_color=status_color)
        # Reduced padding (from 10 to 5)
        priority_bar.grid(row=0, column=0, rowspan=2, sticky="ns", padx=(0, 5)) 

        # Hover Effect: Use COLOR_ELEVATION_2 for hover and COLOR_PRIMARY for selection border
        widget.bind("<Enter>", lambda e: widget.configure(fg_color=COLOR_ELEVATION_2))
        # Restore color on leave, unless it's the selected widget (handled in _on_rule_selected)
        widget.bind("<Leave>", lambda e: widget.configure(fg_color=COLOR_ELEVATION_1) if self.selected_widget is not widget else None)

        # Click Command
        widget.bind("<Button-1>", lambda event, r=rule, w=widget: self._on_rule_selected(r, w))
        
        # SETTING EXTERNAL PADDING TO MINIMUM (pady=3)
        widget.pack(fill="x", pady=3, padx=UI_SETTINGS["spacing"]["xs"]) 
        widget.grid_columnconfigure(2, weight=1) 

        # Icon
        icon = self.CONDITION_ICONS.get(rule.condition.get("type"), "⚙️")
        # --- CRITICAL FIX: Use FONT_CAPTION (size 9) for minimum height ---
        icon_label = ctk.CTkLabel(widget, text=icon, font=FONT_CAPTION, text_color=status_color if rule.enabled else COLOR_TEXT_SECONDARY)
        # Reduced internal padding
        icon_label.grid(row=0, column=1, rowspan=2, padx=(5, 5), pady=1) # Reduced pady to 1

        # Name Label
        name_label = ctk.CTkLabel(widget, text=rule.name, font=FONT_BODY, anchor="w", text_color=text_color)
        # Reduced internal padding
        name_label.grid(row=0, column=2, sticky="w", padx=5, pady=(1, 0)) # Reduced pady

        # Info Text (Action | Priority)
        info_text = f"Action: {rule.action.get('type', 'N/A')} | Priority: {rule.get_priority_str()}"
        action_label = ctk.CTkLabel(widget, text=info_text, font=FONT_BODY_SMALL, text_color=COLOR_TEXT_SECONDARY, anchor="w")
        # Reduced internal padding
        action_label.grid(row=1, column=2, sticky="w", padx=5, pady=(0, 1)) # Reduced pady

        # Enabled/Disabled Switch (on the widget itself)
        switch_var = ctk.BooleanVar(value=rule.enabled)
        switch = ctk.CTkSwitch(
             widget, text="", variable=switch_var, progress_color=COLOR_PRIMARY,
             command=lambda r=rule, v=switch_var: self._toggle_rule_enabled(r, v.get())
        )
        # Reduced padding
        switch.grid(row=0, column=3, rowspan=2, padx=5, pady=1) # Reduced pady
        
        # Re-binding click events for reduced padding elements
        for child in widget.winfo_children():
            # Apply click event to non-switch elements to select the rule
            if not isinstance(child, ctk.CTkSwitch):
                child.bind("<Button-1>", lambda event, r=rule, w=widget: self._on_rule_selected(r, w))
                
        return widget

    # --- Editor Panel Logic ---
    def _on_rule_selected(self, rule: Rule, widget: ctk.CTkFrame):
        """Loads selected rule into editor and shows editor panel."""
        self.editor_placeholder.grid_forget() # Hide placeholder
        
        # Show specific layout frames (Rows 1, 2, 3)
        self.setup_card.grid(row=1, column=0, sticky="ew", padx=20, pady=(0, 10))
        # NEW: Show Tabview instead of individual cards
        self.tabview.grid(row=2, column=0, sticky="nsew", padx=20, pady=(0, 10)) 
        self.button_frame.grid(row=3, column=0, sticky="sew", padx=20, pady=(10, 20)) # Row changed to 3

        # Deselect/Highlight logic
        if self.selected_widget and self.selected_widget.winfo_exists():
            # Reset border width to 1 when deselected
            try: self.selected_widget.configure(border_color=COLOR_ELEVATION_1, fg_color=COLOR_ELEVATION_1, border_width=1)
            except Exception: pass
            
        if widget and widget.winfo_exists():
            # Set border width to 2 when selected for emphasis
            try: widget.configure(border_color=COLOR_PRIMARY, fg_color=COLOR_ELEVATION_2, border_width=2) # Highlight selection
            except Exception: pass

        self.selected_widget = widget
        self.selected_rule = rule
        self.editor_title.configure(text=f"Edit Rule: {rule.name}")

        # Load consolidated fields
        self.name_entry.delete(0, "end"); self.name_entry.insert(0, rule.name)
        self.priority_seg_btn.set(rule.get_priority_str())
        if rule.enabled: self.enabled_switch.select()
        else: self.enabled_switch.deselect()

        # Load tab content
        condition_type = rule.condition.get("type", list(self.CONDITION_ICONS.keys())[0])
        self.condition_menu.set(condition_type)
        self._build_condition_ui(condition_type, rule.condition)

        action_type = rule.action.get("type", list(self.ACTION_ICONS.keys())[0])
        self.action_menu.set(action_type)
        self._build_action_ui(action_type, rule.action)

        self.delete_btn.configure(state="normal")
        self.test_btn.configure(state="normal")
        self._show_status_message("")


    def _clear_editor_form(self, show_placeholder: bool = False):
        """Resets editor to blank, optionally showing placeholder."""
        if self.selected_widget and self.selected_widget.winfo_exists():
            # Reset border width when clearing/starting new rule
            try: self.selected_widget.configure(border_color=COLOR_ELEVATION_1, fg_color=COLOR_ELEVATION_1, border_width=1)
            except Exception: pass

        self.selected_rule = None
        self.selected_widget = None

        if show_placeholder:
            # --- Hide Editor, Show Placeholder ---
            self.editor_title.configure(text="Rule Editor") # Reset title
            self.setup_card.grid_forget() 
            # NEW: Hide Tabview
            self.tabview.grid_forget()
            self.button_frame.grid_forget()
            self.editor_placeholder.grid(row=1, column=0, rowspan=2, sticky="nsew", padx=20, pady=10) # Covers setup card and tabview rows
        else:
            # --- Show Editor, Hide Placeholder ---
            self.editor_placeholder.grid_forget()
            self.setup_card.grid(row=1, column=0, sticky="ew", padx=20, pady=(0, 10))
            # NEW: Show Tabview
            self.tabview.grid(row=2, column=0, sticky="nsew", padx=20, pady=(0, 10)) 
            self.button_frame.grid(row=3, column=0, sticky="sew", padx=20, pady=(10, 20))
            self.editor_title.configure(text="Add New Rule") # Set specific title

            # Reset fields
            self.name_entry.delete(0, "end")
            self.priority_seg_btn.set("Medium")
            self.enabled_switch.select()
            
            # Reset to first condition/action and rebuild UI
            default_cond = list(self.CONDITION_ICONS.keys())[0]
            self.condition_menu.set(default_cond)
            self._build_condition_ui(default_cond)
            
            default_act = list(self.ACTION_ICONS.keys())[0]
            self.action_menu.set(default_act)
            self._build_action_ui(default_act)
            
            # Switch to Trigger tab on new rule entry
            self.tabview.set("Trigger Condition") 

            self.delete_btn.configure(state="disabled")
            self.test_btn.configure(state="disabled")
            self._show_status_message("")


    def _save_rule(self):
        """Gathers data, validates, and saves rule to DB. Triggers CoreLogic reload."""
        rule_name = self.name_entry.get().strip()
        if not rule_name:
            messagebox.showwarning("Input Error", "Rule name cannot be empty.", parent=self)
            return

        try:
            # Gather form data and validate inputs
            temp_rule = self._gather_form_data()

            condition_json = json.dumps(temp_rule.condition)
            action_json = json.dumps(temp_rule.action)

            # --- Save to Database ---
            if self.selected_rule and self.selected_rule.id is not None: # Update
                rule_id = self.selected_rule.id
                DB.update_rule(rule_id, rule_name, condition_json, action_json, temp_rule.enabled, temp_rule.priority)
                DB.log_action("RULE_UPDATED", user_id=self.user_info.get('id'), details=f"Rule: '{rule_name}'")
                
                # Update local selected rule object 
                self.selected_rule.name = rule_name
                self.selected_rule.enabled = temp_rule.enabled
                self.selected_rule.priority = temp_rule.priority
                self.selected_rule.condition = temp_rule.condition
                self.selected_rule.action = temp_rule.action

            else: # Insert
                new_rule_id = DB.insert_rule(rule_name, condition_json, action_json, temp_rule.enabled, temp_rule.priority)
                DB.log_action("RULE_CREATED", user_id=self.user_info.get('id'), details=f"Rule: '{rule_name}' (ID: {new_rule_id})")
                self._clear_editor_form(show_placeholder=False) # Clear for next entry

            # CRITICAL FIX: Tell CoreLogic to reload rules immediately
            if self.controller.reload_core_logic_rules():
                 self._show_status_message(f"Rule '{rule_name}' saved and engine reloaded.", "success")
            else:
                 self._show_status_message(f"Rule '{rule_name}' saved. Engine reload FAILED.", "error")


        except ValueError as ve:
            messagebox.showwarning("Input Error", str(ve), parent=self)
        except sqlite3.IntegrityError:
            messagebox.showerror("Save Error", f"A rule with the name '{rule_name}' already exists.", parent=self)
        except Exception as e:
            messagebox.showerror("Save Error", f"An unexpected error occurred:\n{e}", parent=self)
            traceback.print_exc() 

        self._load_and_populate_rules() # Always reload list


    def _delete_rule(self):
        """Deletes the currently selected rule."""
        if not self.selected_rule or self.selected_rule.id is None:
            self._show_status_message("No rule selected to delete.", "error")
            return
        
        rule_name, rule_id = self.selected_rule.name, self.selected_rule.id
        if messagebox.askyesno("Confirm Delete", f"Permanently delete rule:\n'{rule_name}'?", icon='warning', parent=self):
            try:
                DB.delete_rule(rule_id)
                DB.log_action("RULE_DELETED", user_id=self.user_info.get('id'), details=f"Rule: '{rule_name}' (ID: {rule_id})")
                
                # CRITICAL FIX: Tell CoreLogic to reload rules immediately
                if self.controller.reload_core_logic_rules():
                    self._show_status_message(f"Rule '{rule_name}' deleted and engine reloaded.", "info")
                else:
                    self._show_status_message(f"Rule '{rule_name}' deleted. Engine reload FAILED.", "error")
                    
                self._load_and_populate_rules() # Refresh list
                self._clear_editor_form(show_placeholder=True) # Hide editor
                
            except Exception as e:
                messagebox.showerror("Database Error", f"Could not delete rule: {e}", parent=self)


    def _toggle_rule_enabled(self, rule: Rule, is_enabled: bool):
        """Updates rule status from the list switch. Triggers CoreLogic reload."""
        if rule.id is None: return
        try:
            rule.enabled = is_enabled # Update local object
            condition_json = json.dumps(rule.condition)
            action_json = json.dumps(rule.action)
            DB.update_rule(rule.id, rule.name, condition_json, action_json, is_enabled, rule.priority)
            
            # CRITICAL FIX: Tell CoreLogic to reload rules immediately
            if self.controller.reload_core_logic_rules():
                status_msg = f"Rule '{rule.name}' {'enabled' if is_enabled else 'disabled'} (Engine Reloaded)."
                status_type = "success"
            else:
                status_msg = f"Rule '{rule.name}' {'enabled' if is_enabled else 'disabled'} (Reload Failed)."
                status_type = "error"

            DB.log_action("RULE_TOGGLED", user_id=self.user_info.get('id'), details=status_msg)
            self._show_status_message(status_msg, status_type)
            
            # Ensure editor reflects the change if this is the currently selected rule
            if self.selected_rule and self.selected_rule.id == rule.id:
                if is_enabled: self.enabled_switch.select()
                else: self.enabled_switch.deselect()
            
            # Refresh list rendering to update colors
            self._filter_and_render()
            
        except Exception as e:
            messagebox.showerror("Update Error", f"Could not update rule status:\n{e}", parent=self)
            self._load_and_populate_rules() # Reload list to fix UI


    def _test_rule(self):
        """(Simulated) Prints rule details to console."""
        
        # NOTE: We grab the latest data from the editor form *before* saving
        try:
            temp_rule = self._gather_form_data()
        except ValueError as ve:
             messagebox.showwarning("Input Error", f"Cannot test. Invalid fields: {ve}", parent=self)
             return

        self._show_status_message(f"Simulating rule: '{temp_rule.name}'...", "info")
        print(f"\n--- SIMULATING RULE ---")
        print(f" Name: {temp_rule.name} (ID: {temp_rule.id}, Enabled: {temp_rule.enabled}, Prio: {temp_rule.priority})")
        print(f" Trigger (IF): {temp_rule.condition}")
        print(f" Response (THEN): {temp_rule.action}")
        print(f"--- END SIMULATION ---\n")
        
        messagebox.showinfo("Rule Test (Simulated)",
                            f"Rule '{temp_rule.name}' simulation triggered.\n\n"
                            f"Trigger: {temp_rule.condition.get('type')}\n"
                            f"Action: {temp_rule.action.get('type')}\n\n"
                            f"Check console for full details.",
                            parent=self)


    def _gather_form_data(self) -> Rule:
        """Helper to safely gather and validate form data for Test/Save."""
        rule_name = self.name_entry.get().strip()
        if not rule_name: raise ValueError("Rule name cannot be empty.")
        
        priority_str = self.priority_seg_btn.get()
        is_enabled = bool(self.enabled_switch.get())
        
        temp_rule = Rule(id=self.selected_rule.id if self.selected_rule else None, name=rule_name, enabled=is_enabled)
        temp_rule.set_priority_from_str(priority_str)
        
        # --- Gather Dynamic Condition Data ---
        condition_type = self.condition_menu.get()
        condition_dict: Dict[str, Any] = {"type": condition_type}
        
        if condition_type == "Severity Level":
            condition_dict["level"] = getattr(self, 'condition_severity_menu', ctk.StringVar(value="Critical")).get()
        elif condition_type == "Source IP":
            ip_cidr = getattr(self, 'condition_ip_entry', ctk.CTkEntry(self)).get().strip()
            if not ip_cidr: raise ValueError("IP/CIDR cannot be empty in Source IP condition.")
            condition_dict["ip_cidr"] = ip_cidr
        elif condition_type == "Log Message Content":
            contains = getattr(self, 'condition_content_entry', ctk.CTkEntry(self)).get().strip()
            if not contains: raise ValueError("Content text cannot be empty in Log Message condition.")
            condition_dict["contains"] = contains
        elif condition_type == "Repeated Event":
            try:
                attempts = int(getattr(self, 'condition_attempts_entry', ctk.CTkEntry(self)).get() or "0")
                window = int(getattr(self, 'condition_window_entry', ctk.CTkEntry(self)).get() or "0")
            except ValueError:
                raise ValueError("Occurrences and Time Window must be valid integers.")
            
            if attempts <= 0 or window <= 0: raise ValueError("Occurrences and Time Window must be positive in Repeated Event condition.")
            condition_dict["attempts"] = attempts
            condition_dict["window"] = window

        temp_rule.condition = condition_dict
        
        # --- Gather Dynamic Action Data ---
        action_type = self.action_menu.get()
        action_dict: Dict[str, Any] = {"type": action_type}

        if action_type == "Block IP":
            try:
                duration = int(getattr(self, 'action_duration_entry', ctk.CTkEntry(self)).get() or "-1")
            except ValueError:
                raise ValueError("Block duration must be a valid integer.")
                
            if duration < 0: raise ValueError("Block duration cannot be negative.")
            action_dict["duration"] = duration
        elif action_type == "Send Email Alert":
            recipient = getattr(self, 'action_email_entry', ctk.CTkEntry(self)).get().strip()
            subject = getattr(self, 'action_subject_entry', ctk.CTkEntry(self)).get().strip() or "AI LAD Alert: {rule_name}"
            if not recipient or '@' not in recipient: raise ValueError("Valid recipient email is required.")
            action_dict["recipient"] = recipient
            action_dict["subject"] = subject
        elif action_type == "Execute Script":
            script_path = getattr(self, 'action_script_entry', ctk.CTkEntry(self)).get().strip()
            if not script_path: raise ValueError("Script path cannot be empty.")
            action_dict["script_path"] = script_path
            action_dict["arguments"] = getattr(self, 'action_args_entry', ctk.CTkEntry(self)).get().strip()
            
        temp_rule.action = action_dict
        
        return temp_rule

    # --- Import / Export ---
    def _export_rules(self):
        """Exports all rules (raw dicts from DB) to a JSON or CSV file."""
        default_filename = f"ai_logguard_rules_{datetime.now():%Y%m%d}.json"
        file_path = filedialog.asksaveasfilename(
            initialfile=default_filename, defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("CSV files (flattened)","*.csv")]
        )
        if not file_path: return

        try:
            all_rules_raw: List[Dict] = DB.list_rules()
            if file_path.endswith(".json"):
                with open(file_path, "w", encoding="utf-8") as f:
                    json.dump(all_rules_raw, f, indent=4)
            else: 
                with open(file_path, "w", newline="", encoding="utf-8") as f:
                    # We export the raw JSON strings for condition/action to keep structure intact
                    headers = ["id", "name", "condition", "action", "enabled", "priority"]
                    writer = csv.writer(f)
                    writer.writerow(headers)
                    for r in all_rules_raw:
                        writer.writerow([r.get(h) for h in headers])
            
            log_details = f"Exported {len(all_rules_raw)} rules to {os.path.basename(file_path)}"
            DB.log_action("RULES_EXPORTED", user_id=self.user_info.get('id'), details=log_details)
            messagebox.showinfo("Export Success", log_details, parent=self)
        except Exception as e:
            messagebox.showerror("Export Error", f"Could not export rules:\n{e}", parent=self)


    def _import_rules(self):
        """Imports rules from JSON or CSV, skipping duplicates by name."""
        file_path = filedialog.askopenfilename(
            title="Select Rules File to Import",
            filetypes=[("JSON or CSV","*.json;*.csv"), ("All Files", "*.*")]
        )
        if not file_path: return

        imported_count, skipped_count, error_count = 0, 0, 0
        try:
            if file_path.endswith(".json"):
                with open(file_path, "r", encoding="utf-8") as f: data = json.load(f)
                if not isinstance(data, list): raise ValueError("JSON must contain a list of rules.")
                for r in data:
                    try:
                        if not isinstance(r, dict) or not all(k in r for k in ["name", "condition", "action", "enabled"]):
                            raise ValueError("Rule object missing required keys (name, condition, action, enabled).")
                        
                        # Ensure condition/action are JSON strings for DB insertion
                        cond_str = r["condition"] if isinstance(r["condition"], str) else json.dumps(r["condition"])
                        act_str = r["action"] if isinstance(r["action"], str) else json.dumps(r["action"])
                        
                        DB.insert_rule(
                            str(r["name"]), cond_str, act_str,
                            bool(r["enabled"]), int(r.get("priority", 2)) # Default priority 2
                        )
                        imported_count += 1
                    except sqlite3.IntegrityError: skipped_count += 1 # Duplicate name
                    except (ValueError, KeyError, TypeError, json.JSONDecodeError) as ve:
                        print(f"Skipping JSON rule: {r.get('name', 'N/A')} - {ve}"); error_count += 1
            else: # CSV
                with open(file_path, "r", newline="", encoding="utf-8-sig") as f: 
                    reader = csv.DictReader(f)
                    
                    req_headers = ["name", "condition", "action", "enabled"] 
                    if not all(h in (reader.fieldnames or []) for h in req_headers):
                         raise ValueError(f"CSV missing required headers: {req_headers}")
                    
                    for r in reader:
                        try:
                            enabled_val = str(r.get("enabled", "1")).lower()
                            is_enabled = enabled_val in ['true', '1', 'yes', 'on']
                            try: priority_val = int(r.get("priority", 2))
                            except ValueError: priority_val = 2
                            
                            # CSV columns condition/action MUST contain valid JSON strings
                            DB.insert_rule(
                                str(r["name"]), str(r["condition"]), str(r["action"]),
                                is_enabled, priority_val
                            )
                            imported_count += 1
                        except sqlite3.IntegrityError: skipped_count += 1
                        except (ValueError, KeyError, TypeError, json.JSONDecodeError) as ve:
                            print(f"Skipping CSV rule: {r.get('name', 'N/A')} - {ve}"); error_count += 1
            
            # --- Finalize Import ---
            self._load_and_populate_rules() # Refresh UI
            result_msg = f"Import complete.\n\nAdded: {imported_count}\nSkipped (duplicates): {skipped_count}"
            if error_count > 0: result_msg += f"\nErrors (malformed): {error_count}"
            DB.log_action("RULES_IMPORTED", user_id=self.user_info.get('id'), details=f"Import: +{imported_count}, Skip: {skipped_count}, Err: {error_count}")
            messagebox.showinfo("Import Results", result_msg, parent=self)
        except Exception as e:
            messagebox.showerror("Import Error", f"Could not import file.\nFile may be invalid.\n\nError: {e}", parent=self)


    # --- UI Helpers ---
    def _show_status_message(self, message: str, status: str = "info"):
        """Displays a non-blocking status message."""
        if not hasattr(self, 'status_label') or not self.status_label.winfo_exists(): return
        if self.status_label_job:
            try: self.after_cancel(self.status_label_job)
            except ValueError: pass
            self.status_label_job = None

        COLOR_CUSTOM_SUCCESS = "#2ecc71" 
        color_map = {"success": COLOR_CUSTOM_SUCCESS, "error": COLOR_RED, "info": COLOR_TEXT_SECONDARY}
        self.status_label.configure(text=message, text_color=color_map.get(status, COLOR_TEXT_SECONDARY))

        if message:
            self.status_label_job = self.after(4000, lambda: self.status_label.configure(text="") if self.status_label.winfo_exists() else None)