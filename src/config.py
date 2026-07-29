import os
from typing import Dict, Any, List

# --- App Directory ---
APP_DIR = os.path.abspath(os.path.dirname(__file__))
ASSETS_DIR = os.path.join(APP_DIR, "assets") 

# --- Primary Theme Colors ---
COLOR_PRIMARY = "#00b894"       # Main Green (Brand Color)
COLOR_PRIMARY_VARIANT = "#008a70"   # Darker Green for hover
COLOR_ACCENT = "#00cec9"        # Lighter Teal (Highlight)

# --- Status & Action Colors ---
COLOR_SUCCESS = "#2ecc71"       # Success Green
COLOR_SUCCESS_HOVER = "#21b660" # Darker success green
COLOR_WARNING = "#f39c12"       # Warning Yellow/Orange
COLOR_WARN = COLOR_WARNING      # <-- ADDED: Alias for COLOR_WARNING
COLOR_ERROR = "#e74c3c"         # Error Red (Used for Critical base)
COLOR_CRITICAL = COLOR_ERROR    # Alias for KPI display
COLOR_CRITICAL_HOVER = "#c0392b" # Darker error red
COLOR_INFO = "#3498db"          # Info Blue
COLOR_RED = COLOR_ERROR         # Alias for consistency
COLOR_ORANGE = "#ff7675"        # A lighter, secondary red/orange

# --- Elevation / Background Colors (Dark Theme) ---
COLOR_BG = "#1e272e"            # Main window background (Lowest Elevation)
COLOR_ELEVATION_1 = "#2d3436"   # Sidebar/Input Background
COLOR_ELEVATION_2 = "#3a4246"   # Default Card Background
COLOR_ELEVATION_3 = "#434b4d"   # Header/Stronger Hover
COLOR_ELEVATION_4 = "#505a5c"   # Clicked/Active states

# --- Define standard component colors based on elevations ---
COLOR_CARD = COLOR_ELEVATION_2      # Default card background
COLOR_INPUT_BG = COLOR_ELEVATION_1  # Make inputs slightly darker than cards
COLOR_SIDEBAR = COLOR_ELEVATION_1
COLOR_RED_CONSOLE = '\033[91m' # Red ANSI escape code
COLOR_BLUE_CONSOLE = '\033[94m' # Blue ANSI escape code
COLOR_END_CONSOLE = '\033[0m'    # ANSI reset code

# --- Text & Dividers ---
COLOR_TEXT = "#dfe6e9"          # Standard text
COLOR_TEXT_PRIMARY = "#ffffff"  # For prominent titles/headings
COLOR_TEXT_SECONDARY = "#b0b0b0" # Lighter, secondary text
COLOR_DIVIDER = COLOR_ELEVATION_3 # Use elevation for subtle dividers

# --- Card & Shadow Colors (Optional, for specific effects) ---
COLOR_SHADOW = "#0a0a0a"          # Dark shadow for cards
icon_color = "#ffffff"          # White icons for contrast

# --- Fonts (FIXED: Defined as tuples/raw parameters to avoid RuntimeError) ---
FONT_FAMILY = "Segoe UI" 
FONT_TITLE = (FONT_FAMILY, 30, "bold")
FONT_HEADING = (FONT_FAMILY, 20, "bold")
FONT_BODY = (FONT_FAMILY, 15)
FONT_VALUE = (FONT_FAMILY, 38, "bold")
FONT_SIDEBAR = (FONT_FAMILY, 17, "bold")
FONT_BODY_MEDIUM = (FONT_FAMILY, 15, "bold")
FONT_BODY_SMALL = (FONT_FAMILY, 13)
FONT_CAPTION = (FONT_FAMILY, 12)

# === Severity Mappings (Consolidated) ===
SEV_COLOR: Dict[str, str] = {
    "Critical": COLOR_ERROR,
    "High": COLOR_ORANGE,
    "Error": COLOR_ERROR,
    "Warn": COLOR_WARNING,
    "Medium": COLOR_WARNING,
    "Low": COLOR_ACCENT,
    "Info": COLOR_INFO,
    "Other": COLOR_TEXT_SECONDARY,
    # App-specific categories
    "Authentication": COLOR_INFO,
    "Injection": "#9b59b6",         # Custom Purple for attacks
    "Scan": COLOR_WARNING,
    "ML Anomaly": COLOR_ACCENT
}
# Define order for sorting/display
SEV_ORDER: List[str] = ["Critical", "Error", "High", "Warn", "Medium", "Low", "Info"]

# --- UI Settings (Consistent Spacing & Sizing) ---
UI_SETTINGS: Dict[str, Any] = {
    "corner_radius": 10, # Slightly more rounded
    "border_width": 1,
    "button_height": 45, # Larger buttons
    "spacing": {
        "xs": 5,
        "sm": 10,
        "md": 20, # Increased
        "lg": 30, # Increased
        "xl": 40,
        "xxl": 64
    }
}

# --- ML MODEL PATHS ---
MODEL_DIR = os.path.join(APP_DIR, "models")
BUILT_IN_MODEL_PATH = os.path.join(MODEL_DIR, "isolation_forest_model.pkl")
BUILT_IN_VECTORIZER_PATH = os.path.join(MODEL_DIR, "tfidf_vectorizer.pkl")
LLM_PROMPT_TEMPLATE_PATH = os.path.join(ASSETS_DIR, "security-prompt.txt")


# --- LLM Configuration (OpenRouter) ---
# Load API key from environment only (never hardcode secrets in source).
# Preferred: OPENROUTER_API_KEY. Fallback: LLM_API_KEY.
LLM_API_KEY = os.getenv("OPENROUTER_API_KEY") or os.getenv("LLM_API_KEY", "")

LLM_BASE_URL = "https://openrouter.ai/api/v1"

# Limit tokens requested from the LLM (helps avoid 402/credit errors)
# IMPORTANT: Must be high enough to allow complete JSON response (min 2500-3000 recommended)
LLM_MAX_TOKENS = 3000

# Optional: fallback model name (leave empty to skip automatic fallback)
LLM_FALLBACK_MODEL_NAME = ""
LLM_MODEL_NAME = "google/gemini-2.0-flash-001"

# Headers for OpenRouter
LLM_HEADERS = {
    "Authorization": f"Bearer {LLM_API_KEY}",
    "Content-Type": "application/json",
    "HTTP-Referer": "https://github.com/YourUser/AiLogGuard", 
    "X-Title": "AI LogGuard Forensic Tool", 
}
# ---------------------------------------------------------------------

# --- DATABASE PATH ---
DB_PATH = os.path.join(APP_DIR, "ai_logguard.db")

# ---------------------------------------------------------------------
