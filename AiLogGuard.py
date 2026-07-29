import customtkinter as ctk
from tkinter import messagebox
import traceback
import sys
import os
from PIL import Image, ImageTk, ImageDraw
import ctypes # <-- NEW: For Windows API calls

# Import config and database
from src.config import *
from src.backend.database_manager import get_db_instance
from src.ui.pages.LoginPage import LoginPage

# Helper to find assets
def resource_path(relative_path: str) -> str:
    # ... (resource_path implementation)
    try: base_path = sys._MEIPASS
    except Exception: base_path = os.path.abspath(os.path.dirname(__file__))
    return os.path.join(base_path, relative_path)

# Global variable to hold the reference to the PhotoImage object (CRITICAL for Tkinter/OS icons)
app_icon_ref = None 

# --- NEW: Windows Taskbar Icon Fix Function ---
def force_taskbar_icon(app_id="AiLogGuard.Monitor.v1"):
    """
    Attempts to set a unique Application User Model ID (AppUserModelID)
    to prevent Windows from grouping the application under the default python.exe icon.
    This helps the custom icon show on the taskbar.
    """
    if os.name == 'nt':  # Check if the operating system is Windows
        try:
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(app_id)
        except Exception as e:
            # This fails if the OS is too old or if permissions are insufficient, but it's safe.
            print(f"Windows AppUserModelID setting failed: {e}")
            pass
# -----------------------------------------------

def set_app_icon(app_instance):
    # ... (set_app_icon implementation)
    global app_icon_ref
    
    # 1. Try loading from file (best quality/best practice)
    try:
        icon_path_png = resource_path("assets/logo.png")
        
        if os.path.exists(icon_path_png):
            pil_image = Image.open(icon_path_png)
            app_icon_ref = ImageTk.PhotoImage(pil_image)
            app_instance.iconphoto(True, app_icon_ref)
            print("Taskbar icon set successfully from 'assets/logo.png'.")
            return
    except Exception as e:
        print(f"File-based icon setting failed: {e}. Attempting programmatic fallback.", file=sys.stderr)

    # 2. Programmatic Fallback (Guaranteed Custom Icon: Shield Color)
    try:
        size = (64, 64)
        fallback_img = Image.new('RGB', size, COLOR_PRIMARY)
        draw = ImageDraw.Draw(fallback_img)
        draw.ellipse((8, 8, 56, 56), fill=COLOR_PRIMARY_VARIANT)
        
        app_icon_ref = ImageTk.PhotoImage(fallback_img)
        app_instance.iconphoto(True, app_icon_ref)
        print("Taskbar icon set using programmatic shield fallback.")
        
    except Exception as e_fallback:
        print(f"Programmatic icon fallback failed: {e_fallback}", file=sys.stderr)


def main():
    # --- 0. CRITICAL: Force Windows to use a unique App ID before launching the window ---
    force_taskbar_icon()
    
    # --- 1. Initialize Database ---
    try:
        db = get_db_instance()
    except Exception as e:
        print(f"FATAL: Could not initialize database: {e}", file=sys.stderr)
        messagebox.showerror("Fatal Error", f"Could not initialize database.\nSee console for details.\n\nError: {e}")
        return

    # --- 2. Load Persistent Settings ---
    try:
        appearance_mode = db.get_setting("appearance_mode", "Dark") 
        accent_color = db.get_setting("accent_color", "blue")
        ui_scale_str = db.get_setting("ui_scale", "100%")
        
        try:
            ui_scale_float = int(ui_scale_str.replace("%", "")) / 100
        except ValueError:
            ui_scale_float = 1.0

    except Exception as e:
        print(f"Error loading settings from DB: {e}. Using defaults.", file=sys.stderr)
        appearance_mode = "Dark"
        accent_color = "blue"
        ui_scale_float = 1.0

    # --- 3. Apply Global Theme ---
    try:
        ctk.set_appearance_mode(appearance_mode)
        ctk.set_default_color_theme(accent_color)
        ctk.set_widget_scaling(ui_scale_float)
    except Exception as e:
        print(f"Error applying theme settings: {e}", file=sys.stderr)

    # --- 4. Launch the Login Window ---
    try:
        app = LoginPage()
        
        # --- Apply OS Icon here, before mainloop starts ---
        set_app_icon(app)
        
        try:
            db.log_action(action="APPLICATION_START", user_id=0, details=f"Theme: {appearance_mode}, Scale: {ui_scale_float}")
        except AttributeError:
            pass
        
        app.mainloop()
        
    except Exception as e:
        print(f"Critical error starting application: {e}", file=sys.stderr)
        traceback.print_exc()
        
        # Fallback error window
        try:
            root = ctk.CTk()
            root.title("Fatal Error")
            root.geometry("400x250")
            
            lbl_title = ctk.CTkLabel(root, text="Critical Application Error", text_color="red", font=("Arial", 18, "bold"))
            lbl_title.pack(pady=(20, 10))
            
            lbl_msg = ctk.CTkLabel(root, text=str(e), wraplength=350)
            lbl_msg.pack(pady=10)
            
            btn_quit = ctk.CTkButton(root, text="Exit", command=root.destroy, fg_color="red")
            btn_quit.pack(pady=20)
            
            root.mainloop()
        except:
            pass

if __name__ == "__main__":
    main()