"""
Clipboard Management with Auto-Clear
"""

import threading
from typing import Optional
import tkinter as tk

try:
    import pyperclip
    PYPERCLIP_AVAILABLE = True
except ImportError:
    PYPERCLIP_AVAILABLE = False


class SecureClipboard:
    """Manages clipboard with automatic clearing"""

    def __init__(self, auto_clear_timeout: int = 15):
        """
        Initialize secure clipboard manager.

        Args:
            auto_clear_timeout: Seconds before clipboard is automatically cleared
        """
        self.auto_clear_timeout = auto_clear_timeout
        self.clear_thread: Optional[threading.Thread] = None
        self.stop_clear = False

    def copy_to_clipboard(self, text: str, clear_after_seconds: Optional[int] = None):
        """
        Copy text to clipboard with automatic clearing.

        Args:
            text: Text to copy
            clear_after_seconds: Override default timeout (None uses instance default)
        """
        timeout = clear_after_seconds or self.auto_clear_timeout

        try:
            if PYPERCLIP_AVAILABLE:
                pyperclip.copy(text)
            else:
                # Fallback for Tkinter clipboard
                try:
                    tk.Tk().clipboard_clear()
                    tk.Tk().clipboard_append(text)
                except:
                    pass

            # Schedule clearing
            self.stop_clear = False
            if self.clear_thread:
                self.stop_clear = True
                self.clear_thread.join(timeout=1)

            self.clear_thread = threading.Thread(
                target=self._auto_clear,
                args=(timeout,),
                daemon=True
            )
            self.clear_thread.start()
        except Exception as e:
            print(f"Warning: Failed to copy to clipboard: {e}")

    def _auto_clear(self, timeout: int):
        """Clear clipboard after timeout"""
        for _ in range(timeout * 10):  # Check every 100ms
            if self.stop_clear:
                return
            threading.Event().wait(0.1)

        if not self.stop_clear:
            self.clear_clipboard_silent()

    def clear_clipboard_silent(self):
        """Silently clear clipboard"""
        try:
            if PYPERCLIP_AVAILABLE:
                pyperclip.copy("")
            else:
                try:
                    root = tk.Tk()
                    root.withdraw()
                    root.clipboard_clear()
                    root.destroy()
                except:
                    pass
        except Exception:
            pass

    def stop_auto_clear(self):
        """Stop any pending auto-clear operations"""
        self.stop_clear = True
        if self.clear_thread:
            self.clear_thread.join(timeout=1)

