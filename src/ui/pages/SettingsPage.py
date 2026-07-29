import customtkinter as ctk
from tkinter import messagebox, filedialog
import os
from datetime import datetime
from typing import Optional, List, Dict, Any, Tuple
import sys # For restarting application simulation
import json # Required for config export/import

# Import config, components, and DB access
from src.config import *
from src.backend.database_manager import get_db_instance
from src.ui.components.modern_components import ModernComponents 

# Get the single DB instance
DB = get_db_instance()

# --- Custom Dialog for Changing Password ---
class ChangePasswordDialog(ctk.CTkToplevel):
    """A custom dialog window for changing a user's password."""
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Change Password")
        self.geometry("400x350")
        self.transient(parent)
        self.grab_set()
        self.resizable(False, False)
        self.configure(fg_color=COLOR_CARD) # Use card color for the dialog background

        main_frame = ctk.CTkFrame(self, fg_color="transparent") # Use transparent frame inside
        main_frame.pack(expand=True, fill="both", padx=UI_SETTINGS["spacing"]["lg"], pady=UI_SETTINGS["spacing"]["lg"])

        ctk.CTkLabel(main_frame, text="🔒 Update Your Password", font=FONT_HEADING, text_color=COLOR_TEXT).pack(pady=UI_SETTINGS["spacing"]["md"])

        self.current_pass_entry = ctk.CTkEntry(
            main_frame, placeholder_text="Current Password", show="*",
            width=280, height=UI_SETTINGS["button_height"], font=FONT_BODY,
            fg_color=COLOR_ELEVATION_2, border_color=COLOR_PRIMARY
        )
        self.current_pass_entry.pack(pady=UI_SETTINGS["spacing"]["sm"])

        self.new_pass_entry = ctk.CTkEntry(
            main_frame, placeholder_text="New Password (min 8 chars)", show="*",
            width=280, height=UI_SETTINGS["button_height"], font=FONT_BODY,
            fg_color=COLOR_ELEVATION_2, border_color=COLOR_PRIMARY
        )
        self.new_pass_entry.pack(pady=UI_SETTINGS["spacing"]["sm"])

        self.confirm_pass_entry = ctk.CTkEntry(
            main_frame, placeholder_text="Confirm New Password", show="*",
            width=280, height=UI_SETTINGS["button_height"], font=FONT_BODY,
            fg_color=COLOR_ELEVATION_2, border_color=COLOR_PRIMARY
        )
        self.confirm_pass_entry.pack(pady=UI_SETTINGS["spacing"]["sm"])

        button_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        button_frame.pack(pady=UI_SETTINGS["spacing"]["md"])

        cancel_btn = ctk.CTkButton(
            button_frame, text="Cancel",
            height=UI_SETTINGS["button_height"], font=FONT_BODY_MEDIUM,
            fg_color=COLOR_ELEVATION_3, hover_color=COLOR_ELEVATION_4,
            command=self.cancel
        )
        cancel_btn.pack(side="left", padx=UI_SETTINGS["spacing"]["sm"])

        update_btn = ctk.CTkButton(
            button_frame, text="Update",
            height=UI_SETTINGS["button_height"], font=FONT_BODY_MEDIUM,
            fg_color=COLOR_SUCCESS, hover_color=COLOR_PRIMARY_VARIANT,
            command=self.update
        )
        update_btn.pack(side="left", padx=UI_SETTINGS["spacing"]["sm"])

        self.current_pass_entry.focus()

    def update(self):
        self.result = {
            "current": self.current_pass_entry.get(),
            "new": self.new_pass_entry.get(),
            "confirm": self.confirm_pass_entry.get()
            }
        self.destroy()

    def cancel(self):
        self.result = None
        self.destroy()

    def get_input(self) -> Optional[dict]:
        self.master.wait_window(self)
        return self.result

# --- Main Settings Page ---
class SettingsPage(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent, fg_color="transparent")
        self.controller = controller
        self.user_info = controller.user_info
        
        # --- Removed Page Title to comply with user request ---
        
        # Use a single scrollable frame to hold all setting panels
        self.scroll_container = ctk.CTkScrollableFrame(self, fg_color="transparent")
        self.scroll_container.pack(fill="both", expand=True, padx=UI_SETTINGS["spacing"]["md"], pady=(UI_SETTINGS["spacing"]["md"], UI_SETTINGS["spacing"]["md"]))
        
        # Use a grid inside the scrollable frame for responsive layout
        # Uniform sizing makes the Appearance and Notification cards look perfectly aligned.
        self.scroll_container.grid_columnconfigure((0, 1), weight=1, uniform="settings_group") 
        
        # All panels are created and arranged in the grid
        # R0: Account Panel (Full Width)
        self._create_account_panel(self.scroll_container).grid(row=0, column=0, columnspan=2, sticky="ew", padx=0, pady=(UI_SETTINGS["spacing"]["sm"], UI_SETTINGS["spacing"]["md"]))
        # R1: Appearance Panel (Col 0)
        self._create_appearance_panel(self.scroll_container).grid(row=1, column=0, sticky="nsew", padx=(0, UI_SETTINGS["spacing"]["md"]), pady=(0, UI_SETTINGS["spacing"]["md"]))
        # R1: Notifications Panel (Col 1)
        self._create_notifications_panel(self.scroll_container).grid(row=1, column=1, sticky="nsew", padx=(0, 0), pady=(0, UI_SETTINGS["spacing"]["md"]))
        # R2: Data Management (Full Width)
        self._create_data_panel(self.scroll_container).grid(row=2, column=0, columnspan=2, sticky="ew", padx=0, pady=(0, UI_SETTINGS["spacing"]["md"]))


    def stop_threads(self):
        print("SettingsPage stopping (no threads to stop).")
        pass

    # --- UI Helper Methods ---
    def _create_panel_header(self, parent, title):
        ctk.CTkLabel(parent, text=title, font=FONT_HEADING, text_color=COLOR_ACCENT).pack(
             anchor="w", padx=15, pady=(15, 5)
        )
        ctk.CTkFrame(parent, fg_color=COLOR_DIVIDER, height=1).pack(fill="x", padx=15, pady=(0, 10))

    def _create_setting_row_frame(self, parent) -> ctk.CTkFrame:
        """
        Helper for creating a consistent row frame that uses .grid() internally
        and packs into the parent panel.
        """
        row = ctk.CTkFrame(parent, fg_color=COLOR_ELEVATION_1, corner_radius=UI_SETTINGS["corner_radius"])
        row.pack(fill="x", padx=15, pady=UI_SETTINGS["spacing"]["xs"])

        # Configure the grid *inside* this 'row' frame
        row.grid_columnconfigure(0, weight=1) # Column 0 (Label) expands
        row.grid_columnconfigure(1, weight=0) # Column 1 (Widget) stays fixed
        
        return row

    # --- Panel Builders ---
    def _create_appearance_panel(self, parent):
        panel = ModernComponents.create_card(parent) # Use ModernComponents
        self._create_panel_header(panel, "Appearance")

        # --- Theme Toggle ---
        initial_mode = DB.get_setting("appearance_mode", "Dark")
        theme_row = self._create_setting_row_frame(panel) 
        
        ctk.CTkLabel(theme_row, text="Appearance Mode (Dark/Light)", font=FONT_BODY, text_color=COLOR_TEXT).grid(
            row=0, column=0, sticky="w", padx=UI_SETTINGS["spacing"]["md"], pady=UI_SETTINGS["spacing"]["sm"]
        )
        theme_switch = ctk.CTkSwitch(theme_row, text="", command=self._toggle_theme, progress_color=COLOR_PRIMARY, height=UI_SETTINGS["button_height"]-15)
        theme_switch.grid(row=0, column=1, sticky="e", padx=UI_SETTINGS["spacing"]["md"], pady=UI_SETTINGS["spacing"]["sm"])
        if initial_mode == "Dark": theme_switch.select()
        else: theme_switch.deselect()

        # --- Accent Color ---
        initial_color = DB.get_setting("accent_color", "blue")
        color_row = self._create_setting_row_frame(panel)
        
        ctk.CTkLabel(color_row, text="Accent Color (Restart Required)", font=FONT_BODY, text_color=COLOR_TEXT).grid(
            row=0, column=0, sticky="w", padx=UI_SETTINGS["spacing"]["md"], pady=UI_SETTINGS["spacing"]["sm"]
        )
        color_menu = ctk.CTkOptionMenu(
            color_row, values=["green", "blue", "dark-blue"],
            command=self._change_accent_color, font=FONT_BODY, dropdown_font=FONT_BODY,
            fg_color=COLOR_ELEVATION_3, button_color=COLOR_ELEVATION_4, height=UI_SETTINGS["button_height"]-5
        )
        color_menu.set(initial_color)
        color_menu.grid(row=0, column=1, sticky="e", padx=UI_SETTINGS["spacing"]["md"], pady=UI_SETTINGS["spacing"]["sm"])

        # --- UI Scaling ---
        initial_scale_str = DB.get_setting("ui_scale", "100%")
        scaling_row = self._create_setting_row_frame(panel) 
        
        ctk.CTkLabel(scaling_row, text="UI Scaling (Restart Required)", font=FONT_BODY, text_color=COLOR_TEXT).grid(
            row=0, column=0, sticky="w", padx=UI_SETTINGS["spacing"]["md"], pady=UI_SETTINGS["spacing"]["sm"]
        )
        scaling_menu = ctk.CTkOptionMenu(
            scaling_row, values=["80%", "90%", "100%", "110%", "120%"],
            command=self._change_scaling, font=FONT_BODY, dropdown_font=FONT_BODY,
            fg_color=COLOR_ELEVATION_3, button_color=COLOR_ELEVATION_4, height=UI_SETTINGS["button_height"]-5
        )
        scaling_menu.set(initial_scale_str)
        scaling_menu.grid(row=0, column=1, sticky="e", padx=UI_SETTINGS["spacing"]["md"], pady=UI_SETTINGS["spacing"]["sm"])

        ctk.CTkFrame(panel, fg_color="transparent", height=UI_SETTINGS["spacing"]["sm"]).pack() # Bottom padding
        return panel

    def _create_account_panel(self, parent):
        panel = ModernComponents.create_card(parent)
        self._create_panel_header(panel, "Account Management")

        # --- User Info Display ---
        info_frame = ctk.CTkFrame(panel, fg_color=COLOR_ELEVATION_1, corner_radius=UI_SETTINGS["corner_radius"])
        info_frame.pack(fill="x", padx=15, pady=(0, UI_SETTINGS["spacing"]["xs"]))

        # Check for guest/unauthenticated user
        is_guest = self.user_info.get('id') == 0 or self.user_info.get('id') is None

        self.name_label = ctk.CTkLabel(info_frame, text=f"👤 User: {self.user_info.get('name', 'N/A')}", font=FONT_BODY)
        self.name_label.pack(anchor="w", padx=15, pady=(15, 5))
        self.email_label = ctk.CTkLabel(info_frame, text=f"📧 Email: {self.user_info.get('email', 'N/A')}", font=FONT_BODY)
        self.email_label.pack(anchor="w", padx=15, pady=5)

        # Format creation date cleanly
        created_at_str_raw = self.user_info.get('created_at', 'N/A')
        created_at_str_formatted = "N/A"
        if isinstance(created_at_str_raw, str) and created_at_str_raw != 'N/A':
             try:
                 created_at_dt = datetime.strptime(created_at_str_raw.split('.')[0], '%Y-%m-%d %H:%M:%S')
                 created_at_str_formatted = created_at_dt.strftime("%B %d, %Y")
             except Exception:
                 created_at_str_formatted = created_at_str_raw
        
        self.created_label = ctk.CTkLabel(info_frame, text=f"🗓️ Member Since: {created_at_str_formatted}", font=FONT_BODY)
        self.created_label.pack(anchor="w", padx=15, pady=(5, 15))

        # --- Action Buttons ---
        button_frame = ctk.CTkFrame(panel, fg_color="transparent")
        button_frame.pack(fill="x", padx=15, pady=UI_SETTINGS["spacing"]["sm"])
        button_frame.grid_columnconfigure((0, 1), weight=1)

        change_name_btn = ctk.CTkButton(button_frame, text="Change Name", height=UI_SETTINGS["button_height"], font=FONT_BODY_MEDIUM,
                                         fg_color=COLOR_ELEVATION_3, hover_color=COLOR_ELEVATION_4, command=self._change_name,
                                         state="disabled" if is_guest else "normal")
        change_name_btn.grid(row=0, column=0, sticky="ew", padx=(0, UI_SETTINGS["spacing"]["xs"]))
        
        change_pass_btn = ctk.CTkButton(button_frame, text="Change Password", height=UI_SETTINGS["button_height"], font=FONT_BODY_MEDIUM,
                                         fg_color=COLOR_ELEVATION_3, hover_color=COLOR_ELEVATION_4, command=self._change_password,
                                         state="disabled" if is_guest else "normal")
        change_pass_btn.grid(row=0, column=1, sticky="ew", padx=(UI_SETTINGS["spacing"]["xs"], 0))

        # --- Delete Account Warning Card ---
        delete_frame = ctk.CTkFrame(panel, fg_color=COLOR_ELEVATION_1, border_width=2, border_color=COLOR_RED, corner_radius=UI_SETTINGS["corner_radius"])
        delete_frame.pack(fill="x", padx=15, pady=(UI_SETTINGS["spacing"]["md"], UI_SETTINGS["spacing"]["sm"]))
        
        delete_frame.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(delete_frame, text="⚠️ Danger Zone: Delete Account (Permanent)", font=FONT_BODY_MEDIUM, text_color=COLOR_ORANGE).grid(
            row=0, column=0, sticky="w", padx=15, pady=15)
        
        delete_btn = ctk.CTkButton(
            delete_frame, text="Delete", height=UI_SETTINGS["button_height"] - 10,
            fg_color=COLOR_RED, hover_color=COLOR_ORANGE, font=FONT_BODY_MEDIUM, command=self._delete_account,
            state="disabled" if is_guest else "normal"
        )
        delete_btn.grid(row=0, column=1, sticky="e", padx=15, pady=15)

        ctk.CTkFrame(panel, fg_color="transparent", height=UI_SETTINGS["spacing"]["sm"]).pack()
        return panel

    def _create_notifications_panel(self, parent):
        panel = ModernComponents.create_card(parent)
        self._create_panel_header(panel, "Notification Preferences")

        # Load states from DB
        email_enabled = DB.get_setting("notify_email_enabled", "True") == "True"
        desktop_enabled = DB.get_setting("notify_desktop_enabled", "True") == "True"
        sound_enabled = DB.get_setting("notify_sound_enabled", "False") == "True"

        # --- Email Switch ---
        email_row = self._create_setting_row_frame(panel)
        ctk.CTkLabel(email_row, text="📧 Critical Alerts via Email (Simulated)", font=FONT_BODY, text_color=COLOR_TEXT).grid(
            row=0, column=0, sticky="w", padx=UI_SETTINGS["spacing"]["md"], pady=UI_SETTINGS["spacing"]["sm"]
        )
        switch1 = ctk.CTkSwitch(email_row, text="", command=lambda: DB.set_setting("notify_email_enabled", str(switch1.get()==1)), progress_color=COLOR_PRIMARY, height=UI_SETTINGS["button_height"]-15)
        if email_enabled: switch1.select()
        switch1.grid(row=0, column=1, sticky="e", padx=UI_SETTINGS["spacing"]["md"], pady=UI_SETTINGS["spacing"]["sm"])
        
        # --- Desktop Switch ---
        desktop_row = self._create_setting_row_frame(panel)
        ctk.CTkLabel(desktop_row, text="🖥️ Desktop Notifications (Simulated)", font=FONT_BODY, text_color=COLOR_TEXT).grid(
            row=0, column=0, sticky="w", padx=UI_SETTINGS["spacing"]["md"], pady=UI_SETTINGS["spacing"]["sm"]
        )
        switch2 = ctk.CTkSwitch(desktop_row, text="", command=lambda: DB.set_setting("notify_desktop_enabled", str(switch2.get()==1)), progress_color=COLOR_PRIMARY, height=UI_SETTINGS["button_height"]-15)
        if desktop_enabled: switch2.select()
        switch2.grid(row=0, column=1, sticky="e", padx=UI_SETTINGS["spacing"]["md"], pady=UI_SETTINGS["spacing"]["sm"])

        # --- Sound Switch ---
        sound_row = self._create_setting_row_frame(panel)
        ctk.CTkLabel(sound_row, text="🔊 Audible Alerts (Simulated)", font=FONT_BODY, text_color=COLOR_TEXT).grid(
            row=0, column=0, sticky="w", padx=UI_SETTINGS["spacing"]["md"], pady=UI_SETTINGS["spacing"]["sm"]
        )
        switch3 = ctk.CTkSwitch(sound_row, text="", command=lambda: DB.set_setting("notify_sound_enabled", str(switch3.get()==1)), progress_color=COLOR_PRIMARY, height=UI_SETTINGS["button_height"]-15)
        if sound_enabled: switch3.select()
        switch3.grid(row=0, column=1, sticky="e", padx=UI_SETTINGS["spacing"]["md"], pady=UI_SETTINGS["spacing"]["sm"])

        ctk.CTkFrame(panel, fg_color="transparent", height=UI_SETTINGS["spacing"]["sm"]).pack()
        return panel

    def _create_data_panel(self, parent):
        panel = ModernComponents.create_card(parent)
        self._create_panel_header(panel, "Data Management")

        # --- Backup Button ---
        backup_row = self._create_setting_row_frame(panel)
        ctk.CTkLabel(backup_row, text="💾 Create Database Backup", font=FONT_BODY, text_color=COLOR_TEXT).grid(
            row=0, column=0, sticky="w", padx=UI_SETTINGS["spacing"]["md"], pady=UI_SETTINGS["spacing"]["sm"]
        )
        backup_btn = ctk.CTkButton(
            backup_row, text="Backup Now", font=FONT_BODY_MEDIUM, height=UI_SETTINGS["button_height"]-10, # Smaller button
            fg_color=COLOR_ELEVATION_3, hover_color=COLOR_ELEVATION_4,
            command=self._backup_database
        )
        backup_btn.grid(row=0, column=1, sticky="e", padx=UI_SETTINGS["spacing"]["md"], pady=UI_SETTINGS["spacing"]["sm"])
        
        # --- Config Export Button (New Feature) ---
        export_config_row = self._create_setting_row_frame(panel)
        ctk.CTkLabel(export_config_row, text="Export Configuration (.json)", font=FONT_BODY, text_color=COLOR_TEXT).grid(
            row=0, column=0, sticky="w", padx=UI_SETTINGS["spacing"]["md"], pady=UI_SETTINGS["spacing"]["sm"]
        )
        export_btn = ctk.CTkButton(
            export_config_row, text="Export Config", font=FONT_BODY_MEDIUM, height=UI_SETTINGS["button_height"]-10,
            fg_color=COLOR_ELEVATION_3, hover_color=COLOR_ELEVATION_4,
            command=self._export_settings
        )
        export_btn.grid(row=0, column=1, sticky="e", padx=UI_SETTINGS["spacing"]["md"], pady=UI_SETTINGS["spacing"]["sm"])

        # --- Config Import Button (New Feature) ---
        import_config_row = self._create_setting_row_frame(panel)
        ctk.CTkLabel(import_config_row, text="Import Configuration (.json)", font=FONT_BODY, text_color=COLOR_TEXT).grid(
            row=0, column=0, sticky="w", padx=UI_SETTINGS["spacing"]["md"], pady=UI_SETTINGS["spacing"]["sm"]
        )
        import_btn = ctk.CTkButton(
            import_config_row, text="Import Config", font=FONT_BODY_MEDIUM, height=UI_SETTINGS["button_height"]-10,
            fg_color=COLOR_ELEVATION_3, hover_color=COLOR_ELEVATION_4,
            command=self._import_settings
        )
        import_btn.grid(row=0, column=1, sticky="e", padx=UI_SETTINGS["spacing"]["md"], pady=UI_SETTINGS["spacing"]["sm"])


        ctk.CTkFrame(panel, fg_color="transparent", height=UI_SETTINGS["spacing"]["sm"]).pack()
        return panel


    # --- Action Handlers ---
    def _toggle_theme(self):
        """
        Toggles appearance mode, saves preference, and forces the main window
        to regain focus to prevent hiding.
        """
        current_mode = ctk.get_appearance_mode()
        new_mode = "Light" if current_mode == "Dark" else "Dark"
        ctk.set_appearance_mode(new_mode)
        DB.set_setting("appearance_mode", new_mode) # Save preference
        
        # Notify controller (AiLogGuard) to redraw graphs (if implemented)
        if hasattr(self.controller, '_toggle_theme'):
             self.controller._toggle_theme()
        
        # FIX: Force the main window to redraw, deiconify, and focus itself 
        self.controller.after(50, self.controller.deiconify)
        self.controller.after(100, self.controller.focus_force)

    def _change_accent_color(self, new_color: str):
        """
        Saves new accent color, informs user to restart, and forces the main window
        to regain focus to prevent hiding.
        """
        # Save preference
        DB.set_setting("accent_color", new_color)
        
        messagebox.showinfo("Theme Update", f"Accent color set to '{new_color}'.\nPlease restart the application for changes to fully apply.", parent=self)
        
        # FIX: Reassert window focus state after changing theme settings
        self.controller.after(50, self.controller.deiconify)
        self.controller.after(100, self.controller.focus_force)


    def _change_scaling(self, new_scaling: str):
        """Saves new scaling value and informs user to restart."""
        try:
            new_scaling_float = int(new_scaling.replace("%", "")) / 100
            ctk.set_widget_scaling(new_scaling_float) # Apply immediately
            DB.set_setting("ui_scale", new_scaling) # Save string
            messagebox.showinfo("UI Scaling", "UI scaling changed. A restart is required for all elements to apply changes correctly.", parent=self)
        except ValueError:
            messagebox.showerror("Error", "Invalid scaling value.", parent=self)

    def _change_name(self):
        """Handles the 'Change Name' button click."""
        dialog = ctk.CTkInputDialog(text="Enter your new name:", title="Change Name")
        new_name = dialog.get_input()
        
        if new_name and new_name.strip():
            user_id = self.user_info.get('id')
            if user_id is None:
                 messagebox.showerror("Error", "User ID not found.", parent=self)
                 return

            success, msg = DB.update_user_name(user_id, new_name.strip())
            if success:
                self.user_info['name'] = new_name.strip()
                self.name_label.configure(text=f"👤 User: {new_name.strip()}")
                DB.log_action("NAME_UPDATE", user_id=user_id, details="User changed their name.")
                # Update main app display
                if hasattr(self.controller, 'update_user_display'):
                     self.controller.update_user_display()
                messagebox.showinfo("Success", "Name updated successfully.", parent=self)
            else:
                messagebox.showerror("Error", f"Could not update name: {msg}", parent=self)

    def _change_password(self):
        """Handles the 'Change Password' button click."""
        dialog = ChangePasswordDialog(self)
        passwords = dialog.get_input()
        if not passwords: return # User cancelled

        current, new, confirm = passwords['current'], passwords['new'], passwords['confirm']
        if not all([current, new, confirm]):
            messagebox.showwarning("Input Error", "All password fields are required.", parent=self)
            return

        user_id = self.user_info.get('id')
        email = self.user_info.get('email')
        if user_id is None or email is None:
             messagebox.showerror("Error", "User session info missing.", parent=self)
             return

        is_valid, _ = DB.verify_user(email, current)
        if not is_valid:
            messagebox.showerror("Error", "Current password does not match.", parent=self)
            return
        if len(new) < 8: # Add full strength check later
            messagebox.showwarning("Weak Password", "New password must be at least 8 characters.", parent=self)
            return
        if new != confirm:
            messagebox.showerror("Error", "New passwords do not match.", parent=self)
            return

        success, msg = DB.update_user_password(user_id, new)
        if success:
            DB.log_action("PASSWORD_UPDATE", user_id=user_id, details="User changed their password.")
            messagebox.showinfo("Success", "Password changed successfully.", parent=self)
        else:
            messagebox.showerror("Error", f"Could not change password: {msg}", parent=self)

    def _delete_account(self):
        """Handles the 'Delete Account' button click."""
        user_id = self.user_info.get('id')
        email = self.user_info.get('email')
        if user_id is None or email is None or user_id == 0: # Prevent guest delete
             messagebox.showerror("Error", "Cannot delete this account (Guest or invalid user).", parent=self)
             return

        if messagebox.askyesno("Confirm Delete", f"Delete account '{email}'?\n\nTHIS IS PERMANENT!", icon='warning', parent=self):
            success, msg = DB.delete_user(user_id)
            if success:
                 DB.log_action("ACCOUNT_DELETE", user_id=user_id, details=f"User account {email} deleted.")
                 messagebox.showinfo("Account Deleted", "Account deleted. Logging out.", parent=self)
                 if hasattr(self.controller, 'logout'): self.controller.logout() # Trigger logout
            else:
                 messagebox.showerror("Error", f"Could not delete account: {msg}", parent=self)

    def _backup_database(self):
        """Handles the 'Backup Database' button click."""
        default_filename = f"ai_logguard_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
        backup_path = filedialog.asksaveasfilename(
             initialdir=os.path.expanduser("~"), # Start in user's home
             initialfile=default_filename,
             defaultextension=".db",
             filetypes=[("SQLite Database", "*.db"), ("All Files", "*.*")],
             title="Save Database Backup As..."
        )
        if not backup_path: return # User cancelled

        success, msg = DB.backup_database(backup_path)
        if success:
             DB.log_action("DB_BACKUP", user_id=self.user_info.get('id'), details=f"DB backed up to {os.path.basename(backup_path)}")
             messagebox.showinfo("Backup Success", msg, parent=self)
        else:
             messagebox.showerror("Backup Failed", msg, parent=self)

    def _export_settings(self):
        """Exports application settings (key-value pairs from the settings table) to JSON."""
        # This function requires reading all settings keys/values from the DB
        try:
            # Note: We assume DB._exec returns a list of sqlite3.Row objects that support dict conversion
            cur = DB._exec("SELECT key, value FROM settings")
            # Convert sqlite3.Row objects to dictionary for JSON serialization
            settings_data = {row['key']: row['value'] for row in cur.fetchall()}
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to retrieve settings from DB: {e}", parent=self)
            return

        default_filename = f"ai_logguard_settings_{datetime.now().strftime('%Y%m%d')}.json"
        file_path = filedialog.asksaveasfilename(
            initialfile=default_filename, defaultextension=".json",
            filetypes=[("JSON files", "*.json")]
        )
        if not file_path: return

        try:
            import json 
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(settings_data, f, indent=4)
            
            DB.log_action("SETTINGS_EXPORTED", user_id=self.user_info.get('id'), details=f"Exported {len(settings_data)} settings.")
            messagebox.showinfo("Export Success", f"Exported {len(settings_data)} settings to {os.path.basename(file_path)}.", parent=self)
        except Exception as e:
            messagebox.showerror("Export Error", f"Could not export settings:\n{e}", parent=self)

    def _import_settings(self):
        """Imports settings from a JSON file and updates the settings table."""
        file_path = filedialog.askopenfilename(
            title="Select Settings File to Import",
            filetypes=[("JSON files", "*.json")]
        )
        if not file_path: return

        try:
            import json
            with open(file_path, "r", encoding="utf-8") as f:
                settings_data = json.load(f)
            
            if not isinstance(settings_data, dict):
                raise ValueError("JSON file must contain a dictionary of settings.")
                
            imported_count = 0
            for key, value in settings_data.items():
                if isinstance(value, (str, int, float, bool)):
                    # Ensure value is saved as string
                    DB.set_setting(key, str(value))
                    imported_count += 1
                
            DB.log_action("SETTINGS_IMPORTED", user_id=self.user_info.get('id'), details=f"Imported {imported_count} settings.")
            messagebox.showinfo("Import Success", f"Imported {imported_count} settings.\n\nPlease restart the application for the imported appearance changes to take full effect.", parent=self)
            
            # Since theme/scaling settings are common, we trigger a soft refresh
            self.controller.after(50, self.controller.deiconify)
            self.controller.after(100, self.controller.focus_force)
            
        except (ValueError, FileNotFoundError, json.JSONDecodeError) as e:
            messagebox.showerror("Import Error", f"Failed to import settings. Error: {e}", parent=self)