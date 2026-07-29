import customtkinter as ctk
from typing import Callable, Optional, Dict, Any, Tuple
from src.config import * # Import all constants

class ModernComponents:
    """A static class for creating modern, themed UI components."""

    @staticmethod
    def create_badge(parent, text: str, badge_type: str = "info") -> ctk.CTkLabel:
        """Create a modern badge label with different styles based on type."""
        colors = {
            "info": COLOR_INFO, "success": COLOR_SUCCESS,
            "warning": COLOR_WARNING, "error": COLOR_ERROR
        }
        fg_color = colors.get(badge_type.lower(), COLOR_INFO)
        
        badge = ctk.CTkLabel(
            parent, text=text, font=FONT_CAPTION, text_color=COLOR_TEXT,
            fg_color=fg_color, corner_radius=UI_SETTINGS["corner_radius"],
            width=30, height=20
        )
        return badge

    @staticmethod
    def create_card(parent, **kwargs) -> ctk.CTkFrame:
        """Create a modern elevated card frame with default styling."""
        # Set defaults, but allow kwargs to override
        config = {
            "fg_color": COLOR_CARD,
            "corner_radius": UI_SETTINGS["corner_radius"],
            "border_width": UI_SETTINGS["border_width"],
            "border_color": COLOR_DIVIDER
        }
        config.update(kwargs) # Apply any overrides
        
        card = ctk.CTkFrame(parent, **config)
        return card

    @staticmethod
    def create_header(parent, title: str, user_info: Optional[Dict[str, Any]] = None, 
                      on_search: Optional[Callable] = None, 
                      on_notifications: Optional[Callable] = None,
                      notification_count: int = 0) -> ctk.CTkFrame:
        """Create a modern application header. Packs itself to the top."""
        
        header = ctk.CTkFrame(
            parent, fg_color=COLOR_ELEVATION_3,
            height=UI_SETTINGS["spacing"]["xxl"], corner_radius=0
        )
        header.pack(fill="x", side="top", pady=0)
        header.pack_propagate(False)

        # Left: Title (if provided)
        left = ctk.CTkFrame(header, fg_color="transparent")
        left.pack(side="left", padx=UI_SETTINGS["spacing"]["md"])
        if title:
            app_title = ctk.CTkLabel(left, text=title, font=FONT_TITLE, text_color=COLOR_PRIMARY)
            app_title.pack(side="left")

        # Center: Search Bar (if callback provided)
        center = ctk.CTkFrame(header, fg_color="transparent")
        center.pack(side="left", expand=True, fill="x", padx=UI_SETTINGS["spacing"]["md"], pady=UI_SETTINGS["spacing"]["sm"])
        
        if on_search:
            # Safely get COLOR_INPUT_BG or fallback to COLOR_ELEVATION_1
            input_bg_color = globals().get('COLOR_INPUT_BG', globals().get('COLOR_ELEVATION_1', "#2d3436"))
            
            search_frame = ctk.CTkFrame(
                center, fg_color=input_bg_color, # Use input bg color
                height=38, corner_radius=UI_SETTINGS["corner_radius"],
                border_width=1, border_color=COLOR_ELEVATION_3
            )
            search_frame.pack(side="left", fill="x", expand=True, padx=UI_SETTINGS["spacing"]["md"])
            search_frame.pack_propagate(False)
            
            search_icon = ctk.CTkLabel(search_frame, text="🔍", font=ctk.CTkFont(size=16), text_color=COLOR_TEXT_SECONDARY)
            search_icon.pack(side="left", padx=(12, 6))
            
            search_var = ctk.StringVar()
            search_entry = ctk.CTkEntry(
                search_frame, placeholder_text="Search logs, alerts, IP addresses...",
                textvariable=search_var, height=36, border_width=0,
                fg_color="transparent", font=FONT_BODY,
                placeholder_text_color=COLOR_TEXT_SECONDARY
            )
            search_entry.pack(side="left", fill="x", expand=True, padx=(0, 12))

            def _on_enter(event=None):
                query = search_var.get().strip()
                if on_search and query:
                    on_search(query)
                    
            search_entry.bind("<Return>", _on_enter)

        # Right: Notifications and User Info
        right = ctk.CTkFrame(header, fg_color="transparent")
        right.pack(side="right", padx=UI_SETTINGS["spacing"]["md"])
        
        if on_notifications:
            notif_btn_frame = ctk.CTkFrame(right, fg_color="transparent")
            notif_btn_frame.pack(side="left", padx=UI_SETTINGS["spacing"]["sm"])
            
            notif_btn = ctk.CTkButton(
                notif_btn_frame, text="🔔", font=ctk.CTkFont(size=18),
                width=40, height=40, corner_radius=20, # Circular
                fg_color=COLOR_ELEVATION_2, hover_color=COLOR_ELEVATION_4,
                text_color=COLOR_TEXT, command=on_notifications
            )
            notif_btn.pack()
            
            if notification_count > 0:
                badge = ModernComponents.create_badge(
                    notif_btn_frame, # Place badge relative to frame
                    text=str(min(notification_count, 99)) if notification_count < 100 else "99+",
                    badge_type="error"
                )
                badge.place(relx=0.7, rely=0.1) # Position badge on frame
        
        if user_info:
            user_frame = ctk.CTkFrame(right, fg_color="transparent")
            user_frame.pack(side="right", padx=(UI_SETTINGS["spacing"]["md"], 0))
            
            user_icon = ctk.CTkLabel(user_frame, text="👤", font=ctk.CTkFont(size=24), text_color=COLOR_TEXT)
            user_icon.pack(side="left", padx=(0, 8))
            
            user_text = ctk.CTkFrame(user_frame, fg_color="transparent")
            user_text.pack(side="left")
            
            username = user_info.get('name', 'User')
            if len(username) > 20: username = username[:17] + "..."
                
            name_label = ctk.CTkLabel(user_text, text=username, font=FONT_BODY, text_color=COLOR_TEXT, anchor="e")
            name_label.pack(anchor="e")
            
            role_text = user_info.get('role', 'User').title() # Capitalize role
            role_label = ctk.CTkLabel(user_text, text=role_text, font=FONT_BODY_SMALL, text_color=COLOR_TEXT_SECONDARY, anchor="e")
            role_label.pack(anchor="e")
            
        return header

    @staticmethod
    def create_footer(parent, text: str, version: str = None):
        """Create a modern footer. Packs itself to the bottom."""
        footer = ctk.CTkFrame(
            parent, fg_color=COLOR_ELEVATION_1,
            height=UI_SETTINGS["spacing"]["xl"]
        )
        footer.pack(side="bottom", fill="x")
        footer.pack_propagate(False)

        container = ctk.CTkFrame(footer, fg_color="transparent")
        container.pack(expand=True) # Center content

        lbl = ctk.CTkLabel(container, text=text, font=FONT_CAPTION, text_color=COLOR_TEXT_SECONDARY)
        lbl.pack(side="left", pady=UI_SETTINGS["spacing"]["xs"])

        if version:
            version_badge = ModernComponents.create_badge(container, text=f"v{version}", badge_type="info")
            version_badge.pack(side="left", padx=UI_SETTINGS["spacing"]["sm"])

        return footer

    @staticmethod
    def create_sidebar_button(parent, text: str, icon: str = "➜", is_active: bool = False, 
                              command: Optional[Callable] = None) -> ctk.CTkButton:
        """Create a modern sidebar button with icon and hover effects."""
        return ctk.CTkButton(
            parent, text=f" {icon}  {text}", font=FONT_SIDEBAR,
            anchor="w", height=UI_SETTINGS["button_height"],
            fg_color=COLOR_PRIMARY if is_active else "transparent",
            text_color=COLOR_TEXT if is_active else COLOR_TEXT_SECONDARY,
            hover_color=COLOR_PRIMARY_VARIANT if is_active else COLOR_ELEVATION_2,
            corner_radius=UI_SETTINGS["corner_radius"],
            command=command
        )

    @staticmethod
    def create_stat_card(parent, title: str, value: str, trend: Optional[float] = None,
                         icon: str = None) -> Tuple[ctk.CTkFrame, ctk.CTkLabel]:
        """Create a modern stat card. Returns (card_frame, value_label)."""
        card = ModernComponents.create_card(parent, border_color=COLOR_ELEVATION_3)
        card.grid_columnconfigure(0, weight=1)

        top_frame = ctk.CTkFrame(card, fg_color="transparent")
        top_frame.grid(row=0, column=0, sticky="ew", padx=UI_SETTINGS["spacing"]["md"], pady=(UI_SETTINGS["spacing"]["sm"], 0))

        if icon:
            ctk.CTkLabel(top_frame, text=icon, font=FONT_HEADING, text_color=COLOR_ACCENT).pack(side="left")
            title_pad_left = UI_SETTINGS["spacing"]["sm"]
        else:
            title_pad_left = 0

        ctk.CTkLabel(top_frame, text=title.upper(), font=FONT_CAPTION, text_color=COLOR_TEXT_SECONDARY).pack(
            side="left", padx=(title_pad_left, 0)
        )

        # --- Store the value label ---
        value_label = ctk.CTkLabel(card, text=value, font=FONT_VALUE, text_color=COLOR_TEXT)
        value_label.grid(
            row=1, column=0, sticky="w", padx=UI_SETTINGS["spacing"]["md"], pady=(0, UI_SETTINGS["spacing"]["xs"])
        )

        # Trend row (if exists)
        if trend is not None:
            trend_color_type = "success" if trend >= 0 else "error"
            trend_icon = "↑" if trend >= 0 else "↓"
            trend_text = f"{trend_icon} {abs(trend):.1f}%"
            trend_badge = ModernComponents.create_badge(card, text=trend_text, badge_type=trend_color_type)
            trend_badge.grid(row=2, column=0, sticky="w", padx=UI_SETTINGS["spacing"]["md"], pady=(0, UI_SETTINGS["spacing"]["sm"]))

        # --- Return both the card frame and the value label ---
        return card, value_label