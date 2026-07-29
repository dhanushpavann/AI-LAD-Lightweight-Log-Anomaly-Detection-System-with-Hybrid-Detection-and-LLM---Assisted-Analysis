# import customtkinter as ctk
# from customtkinter import CTkInputDialog
# from tkinter import messagebox
# import os
# import sys
# import re
# import json
# from datetime import datetime
# from PIL import Image, ImageTk
# from typing import Optional, List, Dict, Any, Tuple 
# import threading
# import time

# # --- Import DB function and Config ---
# from database_manager import get_db_instance
# from config import * # For Main Dashboard launch
# # Note: AiLogGuard is imported inside open_dashboard to avoid circular imports.

# # --- Get the DB instance ---
# DB = get_db_instance()

# # --- Animation & Layout Config ---
# PANEL_W = 400
# ANIM_STEPS = 40 
# ANIM_DELAY = 8 

# # --- Easing Function for Smoothness ---
# def _ease_in_out_cubic(t: float) -> float:
#     """Cubic ease-in-out function for smooth acceleration and deceleration."""
#     if t < 0.5: 
#         return 4.0 * t * t * t
#     else:
#         t -= 1.0
#         return 4.0 * t * t * t + 1.0
        
# # --- Asset Helper ---
# def resource_path(relative_path: str) -> str:
#     """ Get absolute path to resource, works for dev and for PyInstaller """
#     try: base_path = sys._MEIPASS
#     except Exception: base_path = os.path.abspath(os.path.dirname(__file__))
#     return os.path.join(base_path, relative_path)

# # --- Validation Helpers ---
# def is_valid_email(email: str) -> bool:
#     if not email: return False
#     return re.fullmatch(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", email)

# def is_valid_password(password: str) -> Tuple[bool, str]:
#     if len(password) < 8: return False, "Password must be at least 8 characters."
#     if not re.search(r"[A-Z]", password): return False, "Must contain an uppercase letter."
#     if not re.search(r"[a-z]", password): return False, "Must contain a lowercase letter."
#     if not re.search(r"[0-9]", password): return False, "Must contain a number."
#     if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?~`]", password): return False, "Must contain a special character."
#     return True, "Valid"

# class LoginPage(ctk.CTk):
    
#     _ease_in_out_cubic = staticmethod(_ease_in_out_cubic) 

#     def __init__(self):
#         super().__init__()
#         self.title(" AI LogGuard - Secure Access")
#         self.geometry("950x620") 
#         self.after(0, lambda: self.wm_state('zoomed'))
#         self.minsize(950, 620)
#         self.configure(fg_color=COLOR_BG)

#         self._set_window_icon()

#         # --- State Variables ---
#         self.current_view = "sign_in"
#         self.is_animating = False
#         self.remember_file = os.path.join(os.path.dirname(__file__), ".remember_me.json")
#         self.loading_pulse_job = None

#         # --- Main Animated Card (Central container) ---
#         card_w = PANEL_W * 2
#         card_h = 580
#         self.grid_rowconfigure(0, weight=1)
#         self.grid_columnconfigure(0, weight=1)
        
#         self.card = ctk.CTkFrame(self, fg_color="transparent", width=card_w, height=card_h)
#         self.card.grid(row=0, column=0) 
#         self.card.pack_propagate(False)

#         # --- Build UI Panels ---
#         self.sign_in_frame = self._build_sign_in_frame(self.card, PANEL_W, card_h)
#         self.sign_up_frame = self._build_sign_up_frame(self.card, PANEL_W, card_h)
#         self.overlay_frame = self._build_overlay_frame(self.card, PANEL_W, card_h)

#         # --- Initial Placement (using .place inside the .card container) ---
#         self.sign_in_frame.place(x=0, y=0)
#         self.sign_up_frame.place(x=PANEL_W * 2, y=0)
#         self.overlay_frame.place(x=PANEL_W, y=0)

#         # --- Copyright Footer ---
#         footer = ctk.CTkFrame(self, fg_color="transparent")
#         footer.place(relx=0.5, rely=0.98, anchor="center")
#         ctk.CTkLabel(footer, text=f"© {datetime.now().year} AI LogGuard. All rights reserved.", font=FONT_CAPTION, text_color=COLOR_TEXT_SECONDARY).pack(side="left", padx=UI_SETTINGS["spacing"]["sm"])
#         ctk.CTkButton(footer, text="Help", fg_color="transparent", text_color=COLOR_ACCENT, width=40, font=FONT_BODY_SMALL, command=lambda: messagebox.showinfo("Help", "Contact support@ailogguard.com")).pack(side="left")
#         ctk.CTkButton(footer, text="About", fg_color="transparent", text_color=COLOR_ACCENT, width=40, font=FONT_BODY_SMALL, command=lambda: messagebox.showinfo("About", "AI LogGuard v1.0")).pack(side="left")

#         self.bind("<Return>", self._on_enter_pressed)
#         self._load_remembered_user()
        
#     def _set_window_icon(self):
#         """Sets the window icon robustly."""
#         try:
#             icon_path = resource_path("assets/logo.png")
#             if os.path.exists(icon_path):
#                 pil_image = Image.open(icon_path)
#                 tk_image = ImageTk.PhotoImage(pil_image)
#                 self.tk_image = tk_image # <-- Keep reference
#                 self.iconphoto(True, tk_image)
#         except Exception:
#             pass
            
#     def _create_input_frame(self, parent, icon, placeholder, show=None, is_password=False):
#         frame = ctk.CTkFrame(
#             parent, fg_color=COLOR_ELEVATION_1, corner_radius=UI_SETTINGS["corner_radius"],
#             height=48, border_width=1, border_color=COLOR_ELEVATION_1
#         )
#         frame.pack(fill="x", pady=UI_SETTINGS["spacing"]["xs"])
#         frame.pack_propagate(False)
#         icon_label = ctk.CTkLabel(frame, text=icon, font=ctk.CTkFont(size=20), text_color=COLOR_TEXT_SECONDARY, fg_color="transparent")
#         icon_label.pack(side="left", padx=(12, 10))
#         entry = ctk.CTkEntry(
#             frame, placeholder_text=placeholder, show=show,
#             fg_color="transparent", border_width=0, font=FONT_BODY,
#             placeholder_text_color=COLOR_TEXT_SECONDARY
#         )
#         if is_password:
#             show_btn = ctk.CTkButton(
#                 frame, text="👁", font=ctk.CTkFont(size=20),
#                 fg_color="transparent", hover=False, width=30,
#                 text_color=COLOR_TEXT_SECONDARY
#             )
#             show_btn.pack(side="right", padx=(0, 10))
#             show_btn.configure(command=lambda: self._toggle_password_visibility(entry, show_btn))
#             entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
#         else:
#             entry.pack(side="left", fill="x", expand=True, padx=(0, 12))
#         return frame, entry

#     def _toggle_password_visibility(self, entry, button):
#         """Toggles password visibility and updates button icon."""
#         is_hidden = entry.cget("show") == "*"
#         entry.configure(show="" if is_hidden else "*")
#         button.configure(text="🙈" if is_hidden else "👁")

#     def _build_sign_in_frame(self, parent, width, height):
#         f = ctk.CTkFrame(parent, fg_color=COLOR_CARD, corner_radius=12, width=width, height=height)
#         f.pack_propagate(False)
#         content = ctk.CTkFrame(f, fg_color="transparent", width=width - 120)
#         content.place(relx=0.5, rely=0.5, anchor="center")
#         ctk.CTkLabel(content, text="🛡️AI LogGuard", font=FONT_TITLE, text_color=COLOR_PRIMARY).pack(pady=(20, 15))
#         ctk.CTkLabel(content, text="Secure Login Portal", font=FONT_BODY, text_color=COLOR_TEXT_SECONDARY).pack(pady=(5, 40))
#         f.email_frame, f.email_entry = self._create_input_frame(content, "✉️", "Email")
#         f.pass_frame, f.pass_entry = self._create_input_frame(content, "🔒", "Password", show="*", is_password=True)
#         sub_frame = ctk.CTkFrame(content, fg_color="transparent")
#         sub_frame.pack(fill="x", pady=(15, 10))
#         f.remember_me = ctk.CTkCheckBox(sub_frame, text="Remember Me", font=FONT_BODY_SMALL, text_color=COLOR_TEXT_SECONDARY, hover_color=COLOR_PRIMARY, fg_color=COLOR_PRIMARY)
#         f.remember_me.pack(side="left")
#         forgot_btn = ctk.CTkButton(sub_frame, text="Forgot Password?", fg_color="transparent", hover=False, text_color=COLOR_ACCENT, command=self._forgot_password, font=FONT_BODY_SMALL)
#         forgot_btn.pack(side="right")
        
#         # --- Action Container (Login Button / Loading Indicator) ---
#         f.action_container = ctk.CTkFrame(content, fg_color="transparent", height=UI_SETTINGS["button_height"])
#         f.action_container.pack(fill="x", pady=(10, 10))
#         f.action_container.pack_propagate(False)
        
#         # Login Button (Main)
#         f.login_btn = ctk.CTkButton(f.action_container, text="Login", fg_color=COLOR_PRIMARY, text_color=COLOR_BG, hover_color=COLOR_PRIMARY_VARIANT, height=UI_SETTINGS["button_height"], font=FONT_SIDEBAR, corner_radius=UI_SETTINGS["corner_radius"], command=self.handle_login)
#         f.login_btn.place(relx=0, rely=0, relwidth=1, relheight=1)
        
#         # Loading Indicator (Overlays login button when active)
#         f.loading_label = ctk.CTkLabel(f.action_container, text="Processing...", fg_color=COLOR_PRIMARY, text_color=COLOR_BG, font=FONT_SIDEBAR, height=UI_SETTINGS["button_height"], corner_radius=UI_SETTINGS["corner_radius"])
#         f.loading_label.place(relx=0, rely=0, relwidth=1, relheight=1)
#         f.loading_label.lower() # Hide initially by placing below button

#         f.guest_btn = ctk.CTkButton(content, text="Continue as Guest", text_color=COLOR_ACCENT, fg_color="transparent", hover_color=COLOR_ELEVATION_1, height=30, font=FONT_BODY_SMALL, command=self.handle_guest_login)
#         f.guest_btn.pack(fill="x", pady=(0, 15))
#         return f

#     def _build_sign_up_frame(self, parent, width, height):
#         f = ctk.CTkFrame(parent, fg_color=COLOR_CARD, corner_radius=12, width=width, height=height)
#         f.pack_propagate(False)
#         content = ctk.CTkFrame(f, fg_color="transparent", width=width - 120)
#         content.place(relx=0.5, rely=0.5, anchor="center")
#         ctk.CTkLabel(content, text="🛡️Create Account", font=FONT_TITLE, text_color=COLOR_PRIMARY).pack(pady=(20, 15))
#         ctk.CTkLabel(content, text="Join the AI LogGuard Network", font=FONT_BODY, text_color=COLOR_TEXT_SECONDARY).pack(pady=(5, 25))
#         f.name_frame, f.name_entry = self._create_input_frame(content, "👤", "Full Name")
#         f.email_frame, f.email_entry = self._create_input_frame(content, "✉️", "Email")
#         f.pass_frame, f.password_entry = self._create_input_frame(content, "🔒", "New Password", show="*", is_password=True)
#         f.confirm_frame, f.confirm_entry = self._create_input_frame(content, "🔒", "Confirm Password", show="*", is_password=True)
#         ctk.CTkLabel(content, text="Min 8 chars, upper, lower, num, special.", font=FONT_BODY_SMALL, text_color=COLOR_TEXT_SECONDARY, justify="left").pack(anchor="w", padx=5, pady=(5,15))
        
#         # --- Action Container (Register Button / Loading Indicator) ---
#         f.action_container = ctk.CTkFrame(content, fg_color="transparent", height=UI_SETTINGS["button_height"])
#         f.action_container.pack(fill="x", pady=(10, 10))
#         f.action_container.pack_propagate(False)

#         # Register Button (Main)
#         f.register_btn = ctk.CTkButton(f.action_container, text="Register", fg_color=COLOR_PRIMARY, text_color=COLOR_BG, hover_color=COLOR_PRIMARY_VARIANT, height=UI_SETTINGS["button_height"], font=FONT_SIDEBAR, corner_radius=UI_SETTINGS["corner_radius"], command=self.handle_register)
#         f.register_btn.place(relx=0, rely=0, relwidth=1, relheight=1)

#         # Loading Indicator (Overlays register button when active)
#         f.loading_label = ctk.CTkLabel(f.action_container, text="Registering...", fg_color=COLOR_PRIMARY, text_color=COLOR_BG, font=FONT_SIDEBAR, height=UI_SETTINGS["button_height"], corner_radius=UI_SETTINGS["corner_radius"])
#         f.loading_label.place(relx=0, rely=0, relwidth=1, relheight=1)
#         f.loading_label.lower() # Hide initially

#         return f

#     def _build_overlay_frame(self, parent, width, height):
#         f = ctk.CTkFrame(parent, fg_color=COLOR_PRIMARY, corner_radius=12, width=width, height=height)
#         f.pack_propagate(False)
#         content = ctk.CTkFrame(f, fg_color="transparent", width=width - 100)
#         content.place(relx=0.5, rely=0.5, anchor="center")
#         f.title_label = ctk.CTkLabel(content, text="Hello, Administrator!", font=FONT_HEADING, text_color=COLOR_BG)
#         f.title_label.pack(pady=(10, 10))
#         f.desc_label = ctk.CTkLabel(content, text="Don't have an account?\nCreate one to secure your systems.", text_color=COLOR_BG, justify="center", font=FONT_BODY)
#         f.desc_label.pack(pady=(10, 25))
#         f.action_btn = ctk.CTkButton(content, text="Create Account", fg_color=COLOR_BG, text_color=COLOR_PRIMARY, height=UI_SETTINGS["button_height"], font=FONT_SIDEBAR, corner_radius=UI_SETTINGS["corner_radius"], command=lambda: self.animate_to("sign_up"))
#         f.action_btn.pack(pady=10)
#         return f

#     def _animate_loading_pulse(self):
#         """Smoothly pulses the loading indicator color."""
#         if not self.loading_pulse_job: return

#         if self.current_view == "sign_in":
#             label = self.sign_in_frame.loading_label
#         elif self.current_view == "sign_up":
#             label = self.sign_up_frame.loading_label
#         else:
#             return

#         # Simple pulse effect: gradually lighten/darken the primary color
#         r_base = int(COLOR_PRIMARY[1:3], 16)
#         g_base = int(COLOR_PRIMARY[3:5], 16)
#         b_base = int(COLOR_PRIMARY[5:7], 16)
        
#         pulse_intensity = (time.time() * 2) % 2 # Cycle between 0 and 2
#         brightness_factor = 0.8 + (0.2 * abs(pulse_intensity - 1)) # Range: 0.8 to 1.0

#         r = min(255, int(r_base * brightness_factor))
#         g = min(255, int(g_base * brightness_factor))
#         b = min(255, int(b_base * brightness_factor))
        
#         new_color = f"#{r:02x}{g:02x}{b:02x}"
        
#         label.configure(fg_color=new_color)

#         self.loading_pulse_job = self.after(ANIM_DELAY * 2, self._animate_loading_pulse)


#     def animate_to(self, target_view):
#         if self.is_animating or target_view == self.current_view: return
#         self.is_animating = True
#         self._reset_highlights()
        
#         start_si_x = self.sign_in_frame.winfo_x()
#         start_ov_x = self.overlay_frame.winfo_x()
        
#         if target_view == "sign_up":
#             end_si_x, end_ov_x = -PANEL_W, 0
#             title, desc, btn_text = "Welcome Back!", "Already have an account?\nLog in.", "Sign In"
#             self.overlay_frame.action_btn.configure(command=lambda: self.animate_to("sign_in"))
#         else:
#             end_si_x, end_ov_x = 0, PANEL_W
#             title, desc, btn_text = "Hello, Administrator!", "Don't have an account?\nRegister now.", "Create Account"
#             self.overlay_frame.action_btn.configure(command=lambda: self.animate_to("sign_up"))
            
#         self.overlay_frame.title_label.configure(text=title)
#         self.overlay_frame.desc_label.configure(text=desc)
#         self.overlay_frame.action_btn.configure(text=btn_text)
        
#         # Calculate total distance to travel
#         dist_si = end_si_x - start_si_x
#         dist_ov = end_ov_x - start_ov_x

#         def _step(step_count):
#             if step_count <= ANIM_STEPS:
#                 t = step_count / ANIM_STEPS
#                 eased_t = self._ease_in_out_cubic(t) # Apply cubic easing for smoothness
                
#                 # Calculate current position using easing
#                 current_si_x = start_si_x + dist_si * eased_t
#                 current_ov_x = start_ov_x + dist_ov * eased_t
                
#                 self.sign_in_frame.place(x=current_si_x)
#                 self.overlay_frame.place(x=current_ov_x)
#                 # The sign-up frame moves in tandem with the overlay
#                 self.sign_up_frame.place(x=current_ov_x + PANEL_W) 
                
#                 self.after(ANIM_DELAY, lambda: _step(step_count + 1))
#             else:
#                 # Ensure final position is exact
#                 self.sign_in_frame.place(x=end_si_x)
#                 self.overlay_frame.place(x=end_ov_x)
#                 self.sign_up_frame.place(x=end_ov_x + PANEL_W)
                
#                 self.current_view = target_view
#                 self.is_animating = False
                
#         _step(1)

#     def _on_enter_pressed(self, _):
#         if self.is_animating: return
#         if self.current_view == "sign_in": self.handle_login()
#         else: self.handle_register()

#     def _forgot_password(self):
#         dialog = CTkInputDialog(text="Enter email for password reset:", title="Forgot Password", parent=self)
#         email = dialog.get_input()
#         if email and is_valid_email(email):
#             DB.log_action(action="PASSWORD_RESET_REQUEST", details=f"Reset requested for {email}.")
#             messagebox.showinfo("Reset Request", f"Reset instructions simulated for {email}.", parent=self)
#         elif email:
#             messagebox.showwarning("Invalid Email", "Please enter a valid email address.", parent=self)

#     def _reset_highlights(self, frames_to_highlight: List[ctk.CTkFrame] = None):
#         """
#         Resets all input frames to default border color (COLOR_ELEVATION_1). 
#         Applies a temporary red highlight to specified frames.
#         """
#         # Ensure frame attributes exist before attempting to access them
#         all_frames = [
#             getattr(self.sign_in_frame, 'email_frame', None), getattr(self.sign_in_frame, 'pass_frame', None),
#             getattr(self.sign_up_frame, 'name_frame', None), getattr(self.sign_up_frame, 'email_frame', None),
#             getattr(self.sign_up_frame, 'pass_frame', None), getattr(self.sign_up_frame, 'confirm_frame', None)
#         ]
        
#         # 1. Reset all frames to default color
#         for frame in all_frames:
#             if frame: frame.configure(border_color=COLOR_ELEVATION_1)
            
#         # 2. Apply temporary highlight if requested
#         if frames_to_highlight:
#             # Set to red immediately
#             for frame in frames_to_highlight:
#                 if frame: frame.configure(border_color=COLOR_RED)
                
#             # Schedule reset back to default after 750ms
#             self.after(750, lambda: [f.configure(border_color=COLOR_ELEVATION_1) for f in frames_to_highlight if f])


#     def _set_loading_state(self, is_loading, view_frame):
#         """Manages the visibility and animation of the loading indicator."""
#         state = "disabled" if is_loading else "normal"
        
#         # Set buttons state
#         if view_frame == self.sign_in_frame:
#             view_frame.login_btn.configure(state=state)
#             view_frame.guest_btn.configure(state=state)
#             label = view_frame.loading_label
#         elif view_frame == self.sign_up_frame:
#             view_frame.register_btn.configure(state=state)
#             label = view_frame.loading_label
#         else:
#             return

#         # Show/Hide Loading Indicator
#         if is_loading:
#             label.lift() # Bring indicator forward
#             self.loading_pulse_job = self.after(0, self._animate_loading_pulse)
#         else:
#             label.lower() # Send indicator backward
#             if self.loading_pulse_job:
#                 self.after_cancel(self.loading_pulse_job)
#                 self.loading_pulse_job = None
        
#         self.update_idletasks()


#     def handle_login(self):
#         self._reset_highlights() # Reset previous highlights
#         email = self.sign_in_frame.email_entry.get().strip()
#         password = self.sign_in_frame.pass_entry.get().strip()
#         remember = self.sign_in_frame.remember_me.get() == 1
        
#         error_frames = []
#         if not email: error_frames.append(self.sign_in_frame.email_frame)
#         if not password: error_frames.append(self.sign_in_frame.pass_frame)

#         if error_frames:
#             self._reset_highlights(error_frames) # Apply temporary red highlight
#             messagebox.showwarning("Input Error", "Email and password required.", parent=self)
#             return
            
#         self._set_loading_state(True, self.sign_in_frame)
        
#         # Simulating DB call asynchronously
#         def async_login():
#             is_valid, user_info = DB.verify_user(email, password)
#             self.after(0, lambda: self._handle_login_result(is_valid, user_info, email, remember))

#         threading.Thread(target=async_login, daemon=True).start()

#     def _handle_login_result(self, is_valid, user_info, email, remember):
#         self._set_loading_state(False, self.sign_in_frame)

#         if is_valid:
#             DB.log_action(action="USER_LOGIN", user_id=user_info.get('id'), details=f"User {email} logged in.")
#             if remember: self._save_remembered_user(email)
#             else: self._clear_remembered_user()
            
#             self.open_dashboard(user_info)
#         else:
#             messagebox.showerror("Access Denied", "Invalid email or password.", parent=self)
#             DB.log_action(action="LOGIN_FAILED", details=f"Failed login for {email}.")
            
#             # Apply temporary red highlight on failed attempt
#             self._reset_highlights([self.sign_in_frame.email_frame, self.sign_in_frame.pass_frame]) 

#     def handle_guest_login(self):
#         DB.log_action(action="GUEST_LOGIN", details="Guest user accessed dashboard.")
#         guest_info = {'id': 'guest-000', 'name': 'Guest User', 'email': 'guest@ailogguard.com', 'role': 'guest'}
#         self.open_dashboard(guest_info)

#     def handle_register(self):
#         self._reset_highlights() # Reset previous highlights
#         name = self.sign_up_frame.name_entry.get().strip()
#         email = self.sign_up_frame.email_entry.get().strip()
#         password = self.sign_up_frame.password_entry.get().strip()
#         confirm = self.sign_up_frame.confirm_entry.get().strip()
#         has_error, error_msg, highlight_frames = False, "", []
        
#         if not all([name, email, password, confirm]):
#             error_msg = "All fields are required!"
#             if not name: highlight_frames.append(self.sign_up_frame.name_frame)
#             if not email: highlight_frames.append(self.sign_up_frame.email_frame)
#             if not password: highlight_frames.append(self.sign_up_frame.pass_frame)
#             if not confirm: highlight_frames.append(self.sign_up_frame.confirm_frame)
#             has_error = True
#         elif not is_valid_email(email):
#             error_msg, highlight_frames = "Invalid email format.", [self.sign_up_frame.email_frame]
#             has_error = True
#         else:
#             is_strong, strength_msg = is_valid_password(password)
#             if not is_strong:
#                 error_msg, highlight_frames = strength_msg, [self.sign_up_frame.pass_frame]
#                 has_error = True
#             elif password != confirm:
#                 error_msg, highlight_frames = "Passwords do not match!", [self.sign_up_frame.pass_frame, self.sign_up_frame.confirm_frame]
#                 has_error = True

#         if has_error:
#             messagebox.showerror("Registration Error", error_msg, parent=self)
#             self._reset_highlights(highlight_frames) # Apply temporary red highlight
#             return
            
#         self._set_loading_state(True, self.sign_up_frame)
        
#         # Simulating DB call asynchronously
#         def async_register():
#             success, msg = DB.create_user(name, email, password)
#             self.after(0, lambda: self._handle_register_result(success, msg))

#         threading.Thread(target=async_register, daemon=True).start()

#     def _handle_register_result(self, success, msg):
#         self._set_loading_state(False, self.sign_up_frame)

#         if success:
#             DB.log_action(action="USER_REGISTER", details=f"New user registered.")
#             messagebox.showinfo("Success", "Account created! Please sign in.", parent=self)
#             self.animate_to("sign_in")
#             # Clear sign up fields
#             self.sign_up_frame.name_entry.delete(0, 'end')
#             self.sign_up_frame.email_entry.delete(0, 'end')
#             self.sign_up_frame.password_entry.delete(0, 'end')
#             self.sign_up_frame.confirm_entry.delete(0, 'end')
#         else:
#             messagebox.showerror("Registration Failed", msg, parent=self)
#             if "email" in msg.lower(): 
#                 self._reset_highlights([self.sign_up_frame.email_frame])

#     def _save_remembered_user(self, email):
#         try:
#             with open(self.remember_file, "w") as f: json.dump({"email": email}, f)
#         except Exception as e: print(f"Error saving remember_me: {e}")

#     def _clear_remembered_user(self):
#           try:
#             if os.path.exists(self.remember_file): os.remove(self.remember_file)
#           except Exception as e: print(f"Error clearing remember_me: {e}")

#     def _load_remembered_user(self):
#         if os.path.exists(self.remember_file):
#             try:
#                 with open(self.remember_file, "r") as f: data = json.load(f)
#                 email = data.get("email")
#                 if email and hasattr(self.sign_in_frame, 'email_entry'):
#                     self.sign_in_frame.email_entry.insert(0, email)
#                     self.sign_in_frame.remember_me.select()
#                     self.sign_in_frame.pass_entry.focus()
#             except Exception as e:
#                 print(f"Error loading remember_me: {e}")
#                 self._clear_remembered_user()

#     def open_dashboard(self, user_info):
#         from AiLogGuard import AiLogGuard 
        
#         self._set_loading_state(True, self.sign_in_frame)
        
#         def launch_dashboard():
#             try:
#                 # Close the login window
#                 self.withdraw()
#                 # Create the main dashboard instance
#                 dashboard = AiLogGuard(user_info)
#                 dashboard.protocol("WM_DELETE_WINDOW", self.on_dashboard_close)
#                 dashboard.mainloop()
#             except Exception:
#                messagebox.showerror("Fatal Error", "Could not load Dashboard. Check for missing files.", parent=self)
#                self.deiconify() # Show login window again on failure
#                self._set_loading_state(False, self.sign_in_frame)
                
#         # A small delay to ensure the loading animation starts rendering before withdrawal
#         threading.Thread(target=lambda: self.after(500, launch_dashboard), daemon=True).start()


#     def on_dashboard_close(self):
#         print("Dashboard closed. Exiting application.")
#         try:
#             DB.close()
#         except Exception as e:
#             print(f"Error closing database: {e}")
#         self.quit()
#         self.destroy()

import customtkinter as ctk
from customtkinter import CTkInputDialog
from tkinter import messagebox
import os
import sys
import re
import json
from datetime import datetime
from PIL import Image, ImageTk
from typing import Optional, List, Dict, Any, Tuple 
import threading
import time

# --- Import DB function and Config ---
from ...backend.database_manager import get_db_instance
from ...config import * # For Main Dashboard launch
# Note: Ai LAD is imported inside open_dashboard to avoid circular imports.

# --- Get the DB instance ---\
DB = get_db_instance()

# --- Animation & Layout Config ---\
PANEL_W = 400
ANIM_STEPS = 40 
ANIM_DELAY = 8 

# --- Easing Function for Smoothness ---\
def _ease_in_out_cubic(t: float) -> float:
    """Cubic ease-in-out function for smooth acceleration and deceleration."""
    if t < 0.5: 
        return 4.0 * t * t * t
    else:
        t -= 1.0
        return 4.0 * t * t * t + 1.0
        
# --- Asset Helper ---\
def resource_path(relative_path: str) -> str:
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try: base_path = sys._MEIPASS
    except Exception: base_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
    return os.path.join(base_path, relative_path)

# --- Validation Helpers ---\
def is_valid_email(email: str) -> bool:
    if not email: return False
    return re.fullmatch(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", email)

def is_valid_password(password: str) -> Tuple[bool, str]:
    if len(password) < 8: return False, "Password must be at least 8 characters."
    if not re.search(r"[A-Z]", password): return False, "Must contain an uppercase letter."
    if not re.search(r"[a-z]", password): return False, "Must contain a lowercase letter."
    if not re.search(r"[0-9]", password): return False, "Must contain a number."
    if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?~`]", password): return False, "Must contain a special character."
    return True, "Valid"

class LoginPage(ctk.CTk):
    
    _ease_in_out_cubic = staticmethod(_ease_in_out_cubic) 

    def __init__(self):
        super().__init__()
        self.title(" AI LAD - Secure Access")
        self.geometry("950x620") 
        self.after(0, lambda: self.wm_state('zoomed'))
        self.minsize(950, 620)
        self.configure(fg_color=COLOR_BG)

        self._set_window_icon()

        # --- State Variables ---\
        self.current_view = "sign_in"
        self.is_animating = False
        self.remember_file = os.path.join(os.path.dirname(__file__), ".remember_me.json")
        self.loading_pulse_job = None

        # --- Main Animated Card (Central container) ---\
        card_w = PANEL_W * 2
        card_h = 580
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)
        
        self.card = ctk.CTkFrame(self, fg_color="transparent", width=card_w, height=card_h)
        self.card.grid(row=0, column=0) 
        self.card.pack_propagate(False)

        # --- Build UI Panels ---\
        self.sign_in_frame = self._build_sign_in_frame(self.card, PANEL_W, card_h)
        self.sign_up_frame = self._build_sign_up_frame(self.card, PANEL_W, card_h)
        self.overlay_frame = self._build_overlay_frame(self.card, PANEL_W, card_h)

        # --- Initial Placement (using .place inside the .card container) ---\
        self.sign_in_frame.place(x=0, y=0)
        self.sign_up_frame.place(x=PANEL_W * 2, y=0)
        self.overlay_frame.place(x=PANEL_W, y=0)

        # --- Copyright Footer ---\
        footer = ctk.CTkFrame(self, fg_color="transparent")
        footer.place(relx=0.5, rely=0.98, anchor="center")
        ctk.CTkLabel(footer, text=f"© {datetime.now().year} AI LAD. All rights reserved.", font=FONT_CAPTION, text_color=COLOR_TEXT_SECONDARY).pack(side="left", padx=UI_SETTINGS["spacing"]["sm"])
        ctk.CTkButton(footer, text="Help", fg_color="transparent", text_color=COLOR_ACCENT, width=40, font=FONT_BODY_SMALL, command=lambda: messagebox.showinfo("Help", "Contact support@ailad.com")).pack(side="left")
        ctk.CTkButton(footer, text="About", fg_color="transparent", text_color=COLOR_ACCENT, width=40, font=FONT_BODY_SMALL, command=lambda: messagebox.showinfo("About", "AI LAD v1.0")).pack(side="left")

        self.bind("<Return>", self._on_enter_pressed)
        self._load_remembered_user()
        
    def _set_window_icon(self):
        """Sets the window icon robustly."""
        try:
            icon_path = resource_path("assets/logo.png")
            if os.path.exists(icon_path):
                pil_image = Image.open(icon_path)
                tk_image = ImageTk.PhotoImage(pil_image)
                self.tk_image = tk_image # <-- Keep reference
                self.iconphoto(True, tk_image)
        except Exception:
            pass
            
    def _create_input_frame(self, parent, icon, placeholder, show=None, is_password=False):
        frame = ctk.CTkFrame(
            parent, fg_color=COLOR_ELEVATION_1, corner_radius=UI_SETTINGS["corner_radius"],
            height=48, border_width=1, border_color=COLOR_ELEVATION_1
        )
        frame.pack(fill="x", pady=UI_SETTINGS["spacing"]["xs"])
        frame.pack_propagate(False)
        icon_label = ctk.CTkLabel(frame, text=icon, font=ctk.CTkFont(size=20), text_color=COLOR_TEXT_SECONDARY, fg_color="transparent")
        icon_label.pack(side="left", padx=(12, 10))
        entry = ctk.CTkEntry(
            frame, placeholder_text=placeholder, show=show,
            fg_color="transparent", border_width=0, font=FONT_BODY,
            placeholder_text_color=COLOR_TEXT_SECONDARY
        )
        if is_password:
            show_btn = ctk.CTkButton(
                frame, text="👁", font=ctk.CTkFont(size=20),
                fg_color="transparent", hover=False, width=30,
                text_color=COLOR_TEXT_SECONDARY
            )
            show_btn.pack(side="right", padx=(0, 10))
            show_btn.configure(command=lambda: self._toggle_password_visibility(entry, show_btn))
            entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
        else:
            entry.pack(side="left", fill="x", expand=True, padx=(0, 12))
        return frame, entry

    def _toggle_password_visibility(self, entry, button):
        """Toggles password visibility and updates button icon."""
        is_hidden = entry.cget("show") == "*"
        entry.configure(show="" if is_hidden else "*")
        button.configure(text="🙈" if is_hidden else "👁")

    def _build_sign_in_frame(self, parent, width, height):
        f = ctk.CTkFrame(parent, fg_color=COLOR_CARD, corner_radius=12, width=width, height=height)
        f.pack_propagate(False)
        content = ctk.CTkFrame(f, fg_color="transparent", width=width - 120)
        content.place(relx=0.5, rely=0.5, anchor="center")
        ctk.CTkLabel(content, text="🛡️AI LAD", font=FONT_TITLE, text_color=COLOR_PRIMARY).pack(pady=(20, 15))
        ctk.CTkLabel(content, text="Secure Login Portal", font=FONT_BODY, text_color=COLOR_TEXT_SECONDARY).pack(pady=(5, 40))
        f.email_frame, f.email_entry = self._create_input_frame(content, "✉️", "Email")
        f.pass_frame, f.pass_entry = self._create_input_frame(content, "🔒", "Password", show="*", is_password=True)
        sub_frame = ctk.CTkFrame(content, fg_color="transparent")
        sub_frame.pack(fill="x", pady=(15, 10))
        f.remember_me = ctk.CTkCheckBox(sub_frame, text="Remember Me", font=FONT_BODY_SMALL, text_color=COLOR_TEXT_SECONDARY, hover_color=COLOR_PRIMARY, fg_color=COLOR_PRIMARY)
        f.remember_me.pack(side="left")
        forgot_btn = ctk.CTkButton(sub_frame, text="Forgot Password?", fg_color="transparent", hover=False, text_color=COLOR_ACCENT, command=self._forgot_password, font=FONT_BODY_SMALL)
        forgot_btn.pack(side="right")
        
        # --- Action Container (Login Button / Loading Indicator) ---\
        f.action_container = ctk.CTkFrame(content, fg_color="transparent", height=UI_SETTINGS["button_height"])
        f.action_container.pack(fill="x", pady=(10, 10))
        f.action_container.pack_propagate(False)
        
        # Login Button (Main)
        f.login_btn = ctk.CTkButton(f.action_container, text="Login", fg_color=COLOR_PRIMARY, text_color=COLOR_BG, hover_color=COLOR_PRIMARY_VARIANT, height=UI_SETTINGS["button_height"], font=FONT_SIDEBAR, corner_radius=UI_SETTINGS["corner_radius"], command=self.handle_login)
        f.login_btn.place(relx=0, rely=0, relwidth=1, relheight=1)
        
        # Loading Indicator (Overlays login button when active)
        f.loading_label = ctk.CTkLabel(f.action_container, text="Processing...", fg_color=COLOR_PRIMARY, text_color=COLOR_BG, font=FONT_SIDEBAR, height=UI_SETTINGS["button_height"], corner_radius=UI_SETTINGS["corner_radius"])
        f.loading_label.place(relx=0, rely=0, relwidth=1, relheight=1)
        f.loading_label.lower() # Hide initially by placing below button

        f.guest_btn = ctk.CTkButton(content, text="Continue as Guest", text_color=COLOR_ACCENT, fg_color="transparent", hover_color=COLOR_ELEVATION_1, height=30, font=FONT_BODY_SMALL, command=self.handle_guest_login)
        f.guest_btn.pack(fill="x", pady=(0, 15))
        return f

    def _build_sign_up_frame(self, parent, width, height):
        f = ctk.CTkFrame(parent, fg_color=COLOR_CARD, corner_radius=12, width=width, height=height)
        f.pack_propagate(False)
        content = ctk.CTkFrame(f, fg_color="transparent", width=width - 120)
        content.place(relx=0.5, rely=0.5, anchor="center")
        ctk.CTkLabel(content, text="🛡️Create Account", font=FONT_TITLE, text_color=COLOR_PRIMARY).pack(pady=(20, 15))
        ctk.CTkLabel(content, text="Join the AI LAD Network", font=FONT_BODY, text_color=COLOR_TEXT_SECONDARY).pack(pady=(5, 25))
        f.name_frame, f.name_entry = self._create_input_frame(content, "👤", "Full Name")
        f.email_frame, f.email_entry = self._create_input_frame(content, "✉️", "Email")
        f.pass_frame, f.password_entry = self._create_input_frame(content, "🔒", "New Password", show="*", is_password=True)
        f.confirm_frame, f.confirm_entry = self._create_input_frame(content, "🔒", "Confirm Password", show="*", is_password=True)
        ctk.CTkLabel(content, text="Min 8 chars, upper, lower, num, special.", font=FONT_BODY_SMALL, text_color=COLOR_TEXT_SECONDARY, justify="left").pack(anchor="w", padx=5, pady=(5,15))
        
        # --- Action Container (Register Button / Loading Indicator) ---\
        f.action_container = ctk.CTkFrame(content, fg_color="transparent", height=UI_SETTINGS["button_height"])
        f.action_container.pack(fill="x", pady=(10, 10))
        f.action_container.pack_propagate(False)

        # Register Button (Main)
        f.register_btn = ctk.CTkButton(f.action_container, text="Register", fg_color=COLOR_PRIMARY, text_color=COLOR_BG, hover_color=COLOR_PRIMARY_VARIANT, height=UI_SETTINGS["button_height"], font=FONT_SIDEBAR, corner_radius=UI_SETTINGS["corner_radius"], command=self.handle_register)
        f.register_btn.place(relx=0, rely=0, relwidth=1, relheight=1)

        # Loading Indicator (Overlays register button when active)
        f.loading_label = ctk.CTkLabel(f.action_container, text="Registering...", fg_color=COLOR_PRIMARY, text_color=COLOR_BG, font=FONT_SIDEBAR, height=UI_SETTINGS["button_height"], corner_radius=UI_SETTINGS["corner_radius"])
        f.loading_label.place(relx=0, rely=0, relwidth=1, relheight=1)
        f.loading_label.lower() # Hide initially

        return f

    def _build_overlay_frame(self, parent, width, height):
        f = ctk.CTkFrame(parent, fg_color=COLOR_PRIMARY, corner_radius=12, width=width, height=height)
        f.pack_propagate(False)
        content = ctk.CTkFrame(f, fg_color="transparent", width=width - 100)
        content.place(relx=0.5, rely=0.5, anchor="center")
        f.title_label = ctk.CTkLabel(content, text="Hello, Administrator!", font=FONT_HEADING, text_color=COLOR_BG)
        f.title_label.pack(pady=(10, 10))
        f.desc_label = ctk.CTkLabel(content, text="Don't have an account?\nCreate one to secure your systems.", text_color=COLOR_BG, justify="center", font=FONT_BODY)
        f.desc_label.pack(pady=(10, 25))
        f.action_btn = ctk.CTkButton(content, text="Create Account", fg_color=COLOR_BG, text_color=COLOR_PRIMARY, height=UI_SETTINGS["button_height"], font=FONT_SIDEBAR, corner_radius=UI_SETTINGS["corner_radius"], command=lambda: self.animate_to("sign_up"))
        f.action_btn.pack(pady=10)
        return f

    def _animate_loading_pulse(self):
        """Smoothly pulses the loading indicator color."""
        if not self.loading_pulse_job: return

        if self.current_view == "sign_in":
            label = self.sign_in_frame.loading_label
        elif self.current_view == "sign_up":
            label = self.sign_up_frame.loading_label
        else:
            return

        # Simple pulse effect: gradually lighten/darken the primary color
        r_base = int(COLOR_PRIMARY[1:3], 16)
        g_base = int(COLOR_PRIMARY[3:5], 16)
        b_base = int(COLOR_PRIMARY[5:7], 16)
        
        pulse_intensity = (time.time() * 2) % 2 # Cycle between 0 and 2
        brightness_factor = 0.8 + (0.2 * abs(pulse_intensity - 1)) # Range: 0.8 to 1.0

        r = min(255, int(r_base * brightness_factor))
        g = min(255, int(g_base * brightness_factor))
        b = min(255, int(b_base * brightness_factor))
        
        new_color = f"#{r:02x}{g:02x}{b:02x}"
        
        label.configure(fg_color=new_color)

        self.loading_pulse_job = self.after(ANIM_DELAY * 2, self._animate_loading_pulse)


    def animate_to(self, target_view):
        if self.is_animating or target_view == self.current_view: return
        self.is_animating = True
        self._reset_highlights()
        
        start_si_x = self.sign_in_frame.winfo_x()
        start_ov_x = self.overlay_frame.winfo_x()
        
        if target_view == "sign_up":
            end_si_x, end_ov_x = -PANEL_W, 0
            title, desc, btn_text = "Welcome Back!", "Already have an account?\nLog in.", "Sign In"
            self.overlay_frame.action_btn.configure(command=lambda: self.animate_to("sign_in"))
        else:
            end_si_x, end_ov_x = 0, PANEL_W
            title, desc, btn_text = "Hello, Administrator!", "Don't have an account?\nRegister now.", "Create Account"
            self.overlay_frame.action_btn.configure(command=lambda: self.animate_to("sign_up"))
            
        self.overlay_frame.title_label.configure(text=title)
        self.overlay_frame.desc_label.configure(text=desc)
        self.overlay_frame.action_btn.configure(text=btn_text)
        
        # Calculate total distance to travel
        dist_si = end_si_x - start_si_x
        dist_ov = end_ov_x - start_ov_x

        def _step(step_count):
            if step_count <= ANIM_STEPS:
                t = step_count / ANIM_STEPS
                eased_t = self._ease_in_out_cubic(t) # Apply cubic easing for smoothness
                
                # Calculate current position using easing
                current_si_x = start_si_x + dist_si * eased_t
                current_ov_x = start_ov_x + dist_ov * eased_t
                
                self.sign_in_frame.place(x=current_si_x)
                self.overlay_frame.place(x=current_ov_x)
                # The sign-up frame moves in tandem with the overlay
                self.sign_up_frame.place(x=current_ov_x + PANEL_W) 
                
                self.after(ANIM_DELAY, lambda: _step(step_count + 1))
            else:
                # Ensure final position is exact
                self.sign_in_frame.place(x=end_si_x)
                self.overlay_frame.place(x=end_ov_x)
                self.sign_up_frame.place(x=end_ov_x + PANEL_W)
                
                self.current_view = target_view
                self.is_animating = False
                
        _step(1)

    def _on_enter_pressed(self, _):
        if self.is_animating: return
        if self.current_view == "sign_in": self.handle_login()
        else: self.handle_register()

    def _forgot_password(self):
        dialog = CTkInputDialog(text="Enter email for password reset:", title="Forgot Password", parent=self)
        email = dialog.get_input()
        if email and is_valid_email(email):
            DB.log_action(action="PASSWORD_RESET_REQUEST", details=f"Reset requested for {email}.")
            messagebox.showinfo("Reset Request", f"Reset instructions simulated for {email}.", parent=self)
        elif email:
            messagebox.showwarning("Invalid Email", "Please enter a valid email address.", parent=self)

    def _reset_highlights(self, frames_to_highlight: List[ctk.CTkFrame] = None):
        """
        Resets all input frames to default border color (COLOR_ELEVATION_1). 
        Applies a temporary red highlight to specified frames.
        """
        # Ensure frame attributes exist before attempting to access them
        all_frames = [
            getattr(self.sign_in_frame, 'email_frame', None), getattr(self.sign_in_frame, 'pass_frame', None),
            getattr(self.sign_up_frame, 'name_frame', None), getattr(self.sign_up_frame, 'email_frame', None),
            getattr(self.sign_up_frame, 'pass_frame', None), getattr(self.sign_up_frame, 'confirm_frame', None)
        ]
        
        # 1. Reset all frames to default color
        for frame in all_frames:
            if frame: frame.configure(border_color=COLOR_ELEVATION_1)
            
        # 2. Apply temporary highlight if requested
        if frames_to_highlight:
            # Set to red immediately
            for frame in frames_to_highlight:
                if frame: frame.configure(border_color=COLOR_RED)
                
            # Schedule reset back to default after 750ms
            self.after(750, lambda: [f.configure(border_color=COLOR_ELEVATION_1) for f in frames_to_highlight if f])


    def _set_loading_state(self, is_loading, view_frame):
        """Manages the visibility and animation of the loading indicator."""
        state = "disabled" if is_loading else "normal"
        
        # Set buttons state
        if view_frame == self.sign_in_frame:
            view_frame.login_btn.configure(state=state)
            view_frame.guest_btn.configure(state=state)
            label = view_frame.loading_label
        elif view_frame == self.sign_up_frame:
            view_frame.register_btn.configure(state=state)
            label = view_frame.loading_label
        else:
            return

        # Show/Hide Loading Indicator
        if is_loading:
            label.lift() # Bring indicator forward
            self.loading_pulse_job = self.after(0, self._animate_loading_pulse)
        else:
            label.lower() # Send indicator backward
            if self.loading_pulse_job:
                self.after_cancel(self.loading_pulse_job)
                self.loading_pulse_job = None
        
        self.update_idletasks()


    def handle_login(self):
        self._reset_highlights() # Reset previous highlights
        email = self.sign_in_frame.email_entry.get().strip()
        password = self.sign_in_frame.pass_entry.get().strip()
        remember = self.sign_in_frame.remember_me.get() == 1
        
        error_frames = []
        if not email: error_frames.append(self.sign_in_frame.email_frame)
        if not password: error_frames.append(self.sign_in_frame.pass_frame)

        if error_frames:
            self._reset_highlights(error_frames) # Apply temporary red highlight
            messagebox.showwarning("Input Error", "Email and password required.", parent=self)
            return
            
        self._set_loading_state(True, self.sign_in_frame)
        
        # Simulating DB call asynchronously
        def async_login():
            is_valid, user_info = DB.verify_user(email, password)
            self.after(0, lambda: self._handle_login_result(is_valid, user_info, email, remember))

        threading.Thread(target=async_login, daemon=True).start()

    def _handle_login_result(self, is_valid, user_info, email, remember):
        self._set_loading_state(False, self.sign_in_frame)

        if is_valid:
            DB.log_action(action="USER_LOGIN", user_id=user_info.get('id'), details=f"User {email} logged in.")
            if remember: self._save_remembered_user(email)
            else: self._clear_remembered_user()
            
            self.open_dashboard(user_info)
        else:
            messagebox.showerror("Access Denied", "Invalid email or password.", parent=self)
            DB.log_action(action="LOGIN_FAILED", details=f"Failed login for {email}.")
            
            # Apply temporary red highlight on failed attempt
            self._reset_highlights([self.sign_in_frame.email_frame, self.sign_in_frame.pass_frame]) 

    def handle_guest_login(self):
        DB.log_action(action="GUEST_LOGIN", details="Guest user accessed dashboard.")
        guest_info = {'id': 'guest-000', 'name': 'Guest User', 'email': 'guest@ailogguard.com', 'role': 'guest'}
        self.open_dashboard(guest_info)

    def handle_register(self):
        self._reset_highlights() # Reset previous highlights
        name = self.sign_up_frame.name_entry.get().strip()
        email = self.sign_up_frame.email_entry.get().strip()
        password = self.sign_up_frame.password_entry.get().strip()
        confirm = self.sign_up_frame.confirm_entry.get().strip()
        has_error, error_msg, highlight_frames = False, "", []
        
        if not all([name, email, password, confirm]):
            error_msg = "All fields are required!"
            if not name: highlight_frames.append(self.sign_up_frame.name_frame)
            if not email: highlight_frames.append(self.sign_up_frame.email_frame)
            if not password: highlight_frames.append(self.sign_up_frame.pass_frame)
            if not confirm: highlight_frames.append(self.sign_up_frame.confirm_frame)
            has_error = True
        elif not is_valid_email(email):
            error_msg, highlight_frames = "Invalid email format.", [self.sign_up_frame.email_frame]
            has_error = True
        else:
            is_strong, strength_msg = is_valid_password(password)
            if not is_strong:
                error_msg, highlight_frames = strength_msg, [self.sign_up_frame.pass_frame]
                has_error = True
            elif password != confirm:
                error_msg, highlight_frames = "Passwords do not match!", [self.sign_up_frame.pass_frame, self.sign_up_frame.confirm_frame]
                has_error = True

        if has_error:
            messagebox.showerror("Registration Error", error_msg, parent=self)
            self._reset_highlights(highlight_frames) # Apply temporary red highlight
            return
            
        self._set_loading_state(True, self.sign_up_frame)
        
        # Simulating DB call asynchronously
        def async_register():
            success, msg = DB.create_user(name, email, password)
            self.after(0, lambda: self._handle_register_result(success, msg))

        threading.Thread(target=async_register, daemon=True).start()

    def _handle_register_result(self, success, msg):
        self._set_loading_state(False, self.sign_up_frame)

        if success:
            DB.log_action(action="USER_REGISTER", details=f"New user registered.")
            messagebox.showinfo("Success", "Account created! Please sign in.", parent=self)
            self.animate_to("sign_in")
            # Clear sign up fields
            self.sign_up_frame.name_entry.delete(0, 'end')
            self.sign_up_frame.email_entry.delete(0, 'end')
            self.sign_up_frame.password_entry.delete(0, 'end')
            self.sign_up_frame.confirm_entry.delete(0, 'end')
        else:
            messagebox.showerror("Registration Failed", msg, parent=self)
            if "email" in msg.lower(): 
                self._reset_highlights([self.sign_up_frame.email_frame])

    def _save_remembered_user(self, email):
        try:
            with open(self.remember_file, "w") as f: json.dump({"email": email}, f)
        except Exception as e: print(f"Error saving remember_me: {e}")

    def _clear_remembered_user(self):
          try:
            if os.path.exists(self.remember_file): os.remove(self.remember_file)
          except Exception as e: print(f"Error clearing remember_me: {e}")

    def _load_remembered_user(self):
        if os.path.exists(self.remember_file):
            try:
                with open(self.remember_file, "r") as f: data = json.load(f)
                email = data.get("email")
                if email and hasattr(self.sign_in_frame, 'email_entry'):
                    self.sign_in_frame.email_entry.insert(0, email)
                    self.sign_in_frame.remember_me.select()
                    self.sign_in_frame.pass_entry.focus()
            except Exception as e:
                print(f"Error loading remember_me: {e}")
                self._clear_remembered_user()

    def open_dashboard(self, user_info):
        from src.controller.main import Ai_LAD 
        
        self._set_loading_state(True, self.sign_in_frame)
        
        def launch_dashboard():
            try:
                # Close the login window
                self.withdraw()
                # Create the main dashboard instance
                dashboard = Ai_LAD(user_info)
                dashboard.protocol("WM_DELETE_WINDOW", self.on_dashboard_close)
                dashboard.mainloop()
            except Exception as e: # Catch the specific exception during dashboard launch
               # --- CRITICAL FIX: Report detailed error to the console ---
               import traceback
               print("FATAL ERROR during Dashboard Launch:")
               traceback.print_exc()
               
               # Show generic error box
               messagebox.showerror("Fatal Error", "Could not load Dashboard. Check for missing files or dependencies (See console for details).", parent=self)
               self.deiconify() # Show login window again on failure
               self._set_loading_state(False, self.sign_in_frame)
                
        # Keep the Tk callback on the main thread; Tkinter is not thread-safe.
        self.after(500, launch_dashboard)


    def on_dashboard_close(self):
        print("Dashboard closed. Exiting application.")
        try:
            DB.close()
        except Exception as e:
            print(f"Error closing database: {e}")
        self.quit()
        self.destroy()
