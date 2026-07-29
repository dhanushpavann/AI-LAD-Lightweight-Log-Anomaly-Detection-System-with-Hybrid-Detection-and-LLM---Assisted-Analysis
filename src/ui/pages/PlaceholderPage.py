# PlaceholderPage.py
import customtkinter as ctk
from src.config import * # For fonts and colors

class PlaceholderPage(ctk.CTkFrame):
    """
    A generic placeholder page for features that are not yet implemented.
    """
    def __init__(self, parent, controller, page_name: str = "This Page"):
        super().__init__(parent, fg_color="transparent") # Transparent background

        # Use grid to center all content within the frame
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # A container frame to hold the centered content
        container = ctk.CTkFrame(self, fg_color="transparent")
        container.grid(row=0, column=0, sticky="nsew")

        # Configure the container's grid to center its children
        container.grid_rowconfigure(0, weight=1) # Spacer above
        container.grid_rowconfigure(1, weight=0) # Emoji
        container.grid_rowconfigure(2, weight=0) # Title
        container.grid_rowconfigure(3, weight=0) # Subtitle
        container.grid_rowconfigure(4, weight=1) # Spacer below
        container.grid_columnconfigure(0, weight=1) # Center horizontally

        # 1. Emoji Icon
        emoji_label = ctk.CTkLabel(
            container,
            text="🚧", # Construction emoji
            font=("Segoe UI Emoji", 80),
            text_color=COLOR_TEXT_SECONDARY
        )
        emoji_label.grid(row=1, column=0, sticky="s", pady=(0, 10))

        # 2. Title
        title_label = ctk.CTkLabel(
            container,
            text=f"'{page_name}' Page Under Construction",
            font=FONT_HEADING,
            text_color=COLOR_ACCENT
        )
        title_label.grid(row=2, column=0, sticky="n", pady=(0, 10))
        
        # 3. Subtitle
        subtitle_label = ctk.CTkLabel(
            container,
            text="This feature is not yet available and will be added in a future update.",
            font=FONT_BODY,
            text_color=COLOR_TEXT_SECONDARY
        )
        subtitle_label.grid(row=3, column=0, sticky="n")

    def stop_threads(self):
        """
        Required by the main controller, but placeholders have no threads.
        """
        pass