#!/usr/bin/env python3
"""
Password Manager GUI - Tkinter Interface with Enhanced Security
Professional UI with password strength validation, auto-lock, and secure clipboard
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import json
import threading
from pathlib import Path
from datetime import datetime, timedelta
import time

from vault import VaultManager
from clipboard_manager import SecureClipboard
from security import (
    validate_password_strength, get_password_strength_bar, log_audit_event
)
from config import AUTO_LOCK_TIMEOUT, CLIPBOARD_CLEAR_TIMEOUT
from exceptions import (
    VaultException, WeakPasswordError, BruteForceDetectedError,
    VaultLockedError, VaultNotLoadedError
)


class PasswordManagerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Password Manager")
        self.root.geometry("1000x700")
        self.root.minsize(900, 600)

        self.vault = VaultManager()
        self.is_loaded = False
        self.current_vault_name = None
        self.show_password = False
        self.actual_password = ""

        self.bg_color = "#2c3e50"
        self.fg_color = "#ecf0f1"
        self.accent_color = "#3498db"
        self.success_color = "#2ecc71"
        self.danger_color = "#e74c3c"
        self.warning_color = "#f39c12"

        self.root.configure(bg=self.bg_color)

        self.clipboard_manager = SecureClipboard(CLIPBOARD_CLEAR_TIMEOUT)

        self.auto_lock_thread = None
        self.stop_auto_lock = False

        self.load_vault_list()
        self.create_ui()

    def get_vaults_config_path(self):
        """Get path to vaults configuration file"""
        from config import VAULTS_CONFIG_FILE
        return VAULTS_CONFIG_FILE

    def load_vault_list(self):
        """Load list of available vaults from config and auto-discover from directory"""
        try:
            config_path = self.get_vaults_config_path()
            if config_path.exists():
                with open(config_path, 'r') as f:
                    self.vaults_config = json.load(f)
            else:
                self.vaults_config = {"vaults": {}}
        except:
            self.vaults_config = {"vaults": {}}

        try:
            from config import VAULT_DIR
            if VAULT_DIR.exists():
                for vault_file in VAULT_DIR.glob("*.json"):
                    if vault_file.name in ["vaults.json", "audit.log"]:
                        continue

                    vault_name = vault_file.stem

                    if vault_name not in self.vaults_config.get("vaults", {}):
                        if "vaults" not in self.vaults_config:
                            self.vaults_config["vaults"] = {}
                        self.vaults_config["vaults"][vault_name] = str(vault_file)
                        self.save_vault_list()
        except Exception as e:
            print(f"Warning: Could not auto-discover vaults: {e}")

    def save_vault_list(self):
        """Save vaults configuration"""
        try:
            config_path = self.get_vaults_config_path()
            config_path.parent.mkdir(parents=True, exist_ok=True)
            with open(config_path, 'w') as f:
                json.dump(self.vaults_config, f, indent=2)
        except Exception as e:
            print(f"Error saving vault config: {e}")

    def create_ui(self):
        """Create main UI layout"""
        main = tk.Frame(self.root, bg=self.bg_color)
        main.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        header = tk.Frame(main, bg=self.bg_color)
        header.pack(fill=tk.X, pady=(0, 10))

        left_header = tk.Frame(header, bg=self.bg_color)
        left_header.pack(side=tk.LEFT, fill=tk.X, expand=True)

        tk.Label(left_header, text="Secure Password Manager", font=("Arial", 18, "bold"),
                bg=self.bg_color, fg=self.accent_color).pack(side=tk.LEFT)

        self.vault_name_label = tk.Label(left_header, text="NO VAULT LOADED",
                font=("Arial", 14, "bold"), bg=self.bg_color, fg=self.danger_color)
        self.vault_name_label.pack(side=tk.LEFT, padx=(20, 0))

        right_header = tk.Frame(header, bg=self.bg_color)
        right_header.pack(side=tk.RIGHT)

        self.status_label = tk.Label(right_header, text="Status: Not Loaded",
                bg=self.bg_color, fg=self.danger_color, font=("Arial", 10))
        self.status_label.pack(side=tk.RIGHT, padx=(10, 0))

        self.locktime_label = tk.Label(right_header, text="",
                bg=self.bg_color, fg=self.warning_color, font=("Arial", 10))
        self.locktime_label.pack(side=tk.RIGHT)

        ttk.Separator(main, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=10)

        btns = tk.Frame(main, bg=self.bg_color)
        btns.pack(fill=tk.X, pady=(0, 10))

        tk.Button(btns, text="New Vault", command=self.new_vault_dialog,
                bg=self.accent_color, fg="white", padx=15, pady=5, font=("Arial", 10)).pack(side=tk.LEFT, padx=5)
        tk.Button(btns, text="Open Vault", command=self.open_vault_dialog,
                bg=self.success_color, fg="white", padx=15, pady=5, font=("Arial", 10)).pack(side=tk.LEFT, padx=5)
        tk.Button(btns, text="Export Backup", command=self.export_vault,
                bg=self.warning_color, fg="white", padx=15, pady=5, font=("Arial", 10)).pack(side=tk.LEFT, padx=5)
        tk.Button(btns, text="Import Backup", command=self.import_vault,
                bg="#9b59b6", fg="white", padx=15, pady=5, font=("Arial", 10)).pack(side=tk.LEFT, padx=5)
        tk.Button(btns, text="Lock Vault", command=self.lock_vault,
                bg=self.danger_color, fg="white", padx=15, pady=5, font=("Arial", 10)).pack(side=tk.LEFT, padx=5)
        tk.Button(btns, text="Delete Vault", command=self.delete_vault_dialog,
                bg="#c0392b", fg="white", padx=15, pady=5, font=("Arial", 10)).pack(side=tk.LEFT, padx=5)

        if self.vaults_config.get("vaults"):
            available = ", ".join(self.vaults_config["vaults"].keys())
            tk.Label(btns, text=f"Available: {available}",
                    bg=self.bg_color, fg="#95a5a6", font=("Arial", 9)).pack(side=tk.LEFT, padx=(20, 0))

        ttk.Separator(main, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=10)

        content = tk.Frame(main, bg=self.bg_color)
        content.pack(fill=tk.BOTH, expand=True)

        left = tk.Frame(content, bg=self.bg_color)
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))

        tk.Label(left, text="Stored Passwords", font=("Arial", 12, "bold"),
                bg=self.bg_color, fg=self.fg_color).pack(anchor=tk.W, pady=(0, 5))

        search_f = tk.Frame(left, bg=self.bg_color)
        search_f.pack(fill=tk.X, pady=(0, 5))
        tk.Label(search_f, text="Search:", bg=self.bg_color, fg=self.fg_color).pack(side=tk.LEFT, padx=(0, 5))
        self.search_var = tk.StringVar()
        self.search_var.trace("w", self.filter_entries)
        tk.Entry(search_f, textvariable=self.search_var, font=("Arial", 10), width=25,
                bg="#34495e", fg=self.fg_color).pack(side=tk.LEFT, fill=tk.X, expand=True)

        list_f = tk.Frame(left, bg=self.bg_color)
        list_f.pack(fill=tk.BOTH, expand=True)
        sb = tk.Scrollbar(list_f)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.entries_listbox = tk.Listbox(list_f, yscrollcommand=sb.set,
                font=("Arial", 10), bg="#34495e", fg=self.fg_color, selectmode=tk.SINGLE)
        self.entries_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.entries_listbox.bind('<<ListboxSelect>>', self.on_entry_selected)
        sb.config(command=self.entries_listbox.yview)

        entry_btns = tk.Frame(left, bg=self.bg_color)
        entry_btns.pack(fill=tk.X, pady=(5, 0))
        tk.Button(entry_btns, text="+ Add", command=self.add_entry_window,
                bg=self.success_color, fg="white", padx=10).pack(side=tk.LEFT, padx=2)
        tk.Button(entry_btns, text="✏ Edit", command=self.edit_entry_window,
                bg=self.accent_color, fg="white", padx=10).pack(side=tk.LEFT, padx=2)
        tk.Button(entry_btns, text="Delete", command=self.delete_entry,
                bg=self.danger_color, fg="white", padx=10).pack(side=tk.LEFT, padx=2)

        # Right panel - Entry details
        right = tk.Frame(content, bg=self.bg_color, width=400)
        right.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(10, 0))
        right.pack_propagate(False)

        tk.Label(right, text="Entry Details", font=("Arial", 12, "bold"),
                bg=self.bg_color, fg=self.fg_color).pack(anchor=tk.W, pady=(0, 10))

        details = tk.Frame(right, bg=self.bg_color)
        details.pack(fill=tk.BOTH, expand=True)

        self.name_var = tk.StringVar()
        self.username_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.url_var = tk.StringVar()
        self.notes_var = tk.StringVar()
        self.created_var = tk.StringVar()

        tk.Label(details, text="Name:", bg=self.bg_color, fg=self.fg_color).grid(row=0, column=0, sticky=tk.W, pady=5)
        tk.Label(details, textvariable=self.name_var, bg="#34495e", fg=self.accent_color, wraplength=300).grid(row=0, column=1, sticky=tk.EW, padx=10, pady=5)

        tk.Label(details, text="Username:", bg=self.bg_color, fg=self.fg_color).grid(row=1, column=0, sticky=tk.W, pady=5)
        tk.Label(details, textvariable=self.username_var, bg="#34495e", fg=self.fg_color, wraplength=300).grid(row=1, column=1, sticky=tk.EW, padx=10, pady=5)

        tk.Label(details, text="Password:", bg=self.bg_color, fg=self.fg_color).grid(row=2, column=0, sticky=tk.W, pady=5)
        pass_f = tk.Frame(details, bg=self.bg_color)
        pass_f.grid(row=2, column=1, sticky=tk.EW, padx=10, pady=5)

        self.password_display = tk.Label(pass_f, textvariable=self.password_var, bg="#34495e", fg=self.fg_color, wraplength=200)
        self.password_display.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.show_password = False
        def toggle_password():
            self.show_password = not self.show_password
            self.update_password_display()

        self.eye_button = tk.Button(pass_f, text="👁", command=toggle_password, bg=self.accent_color, fg="white", width=3, padx=2)
        self.eye_button.pack(side=tk.LEFT, padx=5)

        tk.Button(pass_f, text="📋 Copy", command=self.copy_password, bg=self.accent_color, fg="white", width=8).pack(side=tk.LEFT, padx=5)

        tk.Label(details, text="URL:", bg=self.bg_color, fg=self.fg_color).grid(row=3, column=0, sticky=tk.W, pady=5)
        tk.Label(details, textvariable=self.url_var, bg="#34495e", fg=self.fg_color, wraplength=300).grid(row=3, column=1, sticky=tk.EW, padx=10, pady=5)

        tk.Label(details, text="Notes:", bg=self.bg_color, fg=self.fg_color).grid(row=4, column=0, sticky=tk.NW, pady=5)
        tk.Label(details, textvariable=self.notes_var, bg="#34495e", fg=self.fg_color, wraplength=300, justify=tk.LEFT).grid(row=4, column=1, sticky=tk.EW, padx=10, pady=5)

        tk.Label(details, text="Created:", bg=self.bg_color, fg=self.fg_color).grid(row=5, column=0, sticky=tk.W, pady=5)
        tk.Label(details, textvariable=self.created_var, bg="#34495e", fg="#95a5a6", wraplength=300).grid(row=5, column=1, sticky=tk.EW, padx=10, pady=5)

        details.columnconfigure(1, weight=1)

        detail_btns = tk.Frame(right, bg=self.bg_color)
        detail_btns.pack(fill=tk.X, pady=(10, 0))
        tk.Button(detail_btns, text="Clear Selection", command=self.clear_details,
                bg="#7f8c8d", fg="white", padx=15, pady=5).pack(side=tk.LEFT, padx=5)

    def set_status(self, text, color="#2ecc71"):
        """Update status label"""
        self.status_label.config(text=text, fg=color)
        self.root.update()

    def update_vault_display(self):
        """Update vault name display"""
        if self.current_vault_name:
            self.vault_name_label.config(text=f"✓ VAULT: {self.current_vault_name.upper()}", fg=self.success_color)
            self.start_auto_lock_timer()
        else:
            self.vault_name_label.config(text="⚠ NO VAULT LOADED", fg=self.danger_color)
            self.stop_auto_lock_timer()

    def start_auto_lock_timer(self):
        """Start auto-lock countdown timer"""
        self.stop_auto_lock = False
        self.auto_lock_thread = threading.Thread(target=self._auto_lock_countdown, daemon=True)
        self.auto_lock_thread.start()

    def stop_auto_lock_timer(self):
        """Stop auto-lock timer"""
        self.stop_auto_lock = True

    def _auto_lock_countdown(self):
        """Background thread for auto-lock countdown"""
        remaining = AUTO_LOCK_TIMEOUT
        while remaining > 0 and not self.stop_auto_lock:
            mins = remaining // 60
            secs = remaining % 60
            self.locktime_label.config(text=f"Auto-lock in: {mins}:{secs:02d}")
            time.sleep(1)
            remaining -= 1

        if remaining <= 0 and not self.stop_auto_lock and self.is_loaded:
            self.lock_vault()

    def update_password_display(self):
        """Toggle password visibility"""
        if self.show_password:
            self.password_var.set(self.actual_password)
            self.eye_button.config(text="🙈")
        else:
            self.password_var.set("•" * len(self.actual_password))
            self.eye_button.config(text="👁")

    def new_vault_dialog(self):
        """Create new vault dialog"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Create New Vault")
        dialog.geometry("500x350")
        dialog.transient(self.root)
        dialog.grab_set()

        bg = self.bg_color
        fg = self.fg_color
        dialog.configure(bg=bg)

        frame = tk.Frame(dialog, bg=bg)
        frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        tk.Label(frame, text="📝 Vault Name:", bg=bg, fg=fg, font=("Arial", 12, "bold")).pack(anchor=tk.W, pady=(0, 5))
        name_entry = tk.Entry(frame, font=("Arial", 12), width=40, bg="#34495e", fg=fg)
        name_entry.pack(fill=tk.X, pady=(0, 15))
        name_entry.focus()
        name_entry.insert(0, "My Passwords")

        tk.Label(frame, text="🔐 Master Password:", bg=bg, fg=fg, font=("Arial", 12, "bold")).pack(anchor=tk.W, pady=(0, 5))
        pwd_entry = tk.Entry(frame, font=("Arial", 12), show="•", width=40, bg="#34495e", fg=fg)
        pwd_entry.pack(fill=tk.X, pady=(0, 5))

        # Password strength indicator
        strength_frame = tk.Frame(frame, bg=bg)
        strength_frame.pack(fill=tk.X, pady=(0, 15))
        strength_label = tk.Label(strength_frame, text="Strength: —", bg=bg, fg=self.warning_color)
        strength_label.pack(side=tk.LEFT)

        def update_strength(*args):
            pwd = pwd_entry.get()
            is_valid, feedback = validate_password_strength(pwd)
            strength_bar = get_password_strength_bar(pwd)
            color = self.success_color if is_valid else self.danger_color
            strength_label.config(text=f"Strength: {strength_bar}", fg=color)

        pwd_entry.bind('<KeyRelease>', update_strength)

        tk.Label(frame, text="⚠ Strong password required (12+ chars, mixed case, numbers, symbols)",
                bg=bg, fg="#95a5a6", font=("Arial", 9)).pack(anchor=tk.W, pady=(0, 15))

        btn_frame = tk.Frame(frame, bg=bg)
        btn_frame.pack(fill=tk.X, pady=(10, 0))

        def create():
            vault_name = name_entry.get().strip()
            password = pwd_entry.get()

            if not vault_name or not password:
                messagebox.showwarning("Missing", "Vault name and password required")
                return

            if vault_name in self.vaults_config["vaults"]:
                messagebox.showerror("Error", f"Vault '{vault_name}' already exists")
                return

            try:
                is_valid, feedback = validate_password_strength(password)
                if not is_valid:
                    messagebox.showwarning("Weak Password", feedback)
                    return

                self.set_status("Creating vault...", self.warning_color)
                vault_path = Path.home() / ".local_vault" / f"{vault_name}.json"
                vault_path.parent.mkdir(parents=True, exist_ok=True)

                vault = VaultManager(vault_path)
                vault.init_vault(password, vault_name)

                self.vaults_config["vaults"][vault_name] = str(vault_path)
                self.save_vault_list()
                self.vault = vault
                self.current_vault_name = vault_name
                self.is_loaded = True
                self.refresh_entries()
                self.update_vault_display()
                self.set_status(f"✓ Vault '{vault_name}' created!", self.success_color)
                messagebox.showinfo("Success", f"Vault '{vault_name}' created!")
                dialog.destroy()
            except WeakPasswordError as e:
                messagebox.showwarning("Weak Password", str(e))
            except Exception as e:
                self.set_status("Error", self.danger_color)
                messagebox.showerror("Error", f"Failed: {str(e)}")
                log_audit_event("VAULT_CREATION_FAILED", str(e), False)

        tk.Button(btn_frame, text="✓ CREATE VAULT", command=create, bg=self.success_color, fg="white",
                font=("Arial", 12, "bold"), padx=30, pady=12).pack(side=tk.LEFT, padx=10)
        tk.Button(btn_frame, text="✕ Cancel", command=dialog.destroy, bg="#95a5a6", fg="white",
                font=("Arial", 11), padx=25, pady=10).pack(side=tk.LEFT, padx=10)

    def open_vault_dialog(self):
        """Open existing vault dialog"""
        if not self.vaults_config["vaults"]:
            messagebox.showinfo("No Vaults", "No vaults found. Create one first!")
            return

        dialog = tk.Toplevel(self.root)
        dialog.title("Open Vault")
        dialog.geometry("500x450")
        dialog.transient(self.root)
        dialog.grab_set()

        bg = self.bg_color
        fg = self.fg_color
        dialog.configure(bg=bg)

        frame = tk.Frame(dialog, bg=bg)
        frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        tk.Label(frame, text="📂 Select Vault:", bg=bg, fg=fg, font=("Arial", 12, "bold")).pack(anchor=tk.W, pady=(0, 10))

        listbox = tk.Listbox(frame, font=("Arial", 11), bg="#34495e", fg=fg, height=8)
        listbox.pack(fill=tk.BOTH, expand=True, pady=(0, 20))

        for vault_name in sorted(self.vaults_config["vaults"].keys()):
            listbox.insert(tk.END, vault_name)

        tk.Label(frame, text="🔐 Master Password:", bg=bg, fg=fg, font=("Arial", 12, "bold")).pack(anchor=tk.W, pady=(0, 5))
        pwd_entry = tk.Entry(frame, font=("Arial", 12), show="•", width=40, bg="#34495e", fg=fg)
        pwd_entry.pack(fill=tk.X, pady=(0, 20))
        pwd_entry.focus()

        btn_frame = tk.Frame(frame, bg=bg)
        btn_frame.pack(fill=tk.X, pady=(10, 0))

        def open_selected():
            selection = listbox.curselection()
            if not selection:
                messagebox.showwarning("No Selection", "Select a vault")
                return

            vault_name = listbox.get(selection[0])
            password = pwd_entry.get()

            if not password:
                messagebox.showwarning("Missing", "Password required")
                return

            try:
                self.set_status("Loading vault...", self.warning_color)
                vault_path = self.vaults_config["vaults"][vault_name]
                vault = VaultManager(Path(vault_path))

                vault.load_vault(password)
                self.vault = vault
                self.current_vault_name = vault_name
                self.is_loaded = True
                self.refresh_entries()
                self.update_vault_display()
                self.set_status(f"✓ Vault '{vault_name}' loaded!", self.success_color)
                messagebox.showinfo("Success", f"Vault '{vault_name}' loaded!")
                dialog.destroy()
            except (BruteForceDetectedError, VaultLockedError) as e:
                self.set_status("Vault Locked", self.danger_color)
                messagebox.showerror("Security", str(e))
                log_audit_event("VAULT_LOCK_TRIGGERED", str(e), False)
            except Exception as e:
                self.set_status("Failed", self.danger_color)
                messagebox.showerror("Error", f"Failed: {str(e)}")
                log_audit_event("VAULT_LOAD_FAILED", str(e), False)

        tk.Button(btn_frame, text="✓ OPEN VAULT", command=open_selected, bg=self.success_color, fg="white",
                font=("Arial", 12, "bold"), padx=30, pady=12).pack(side=tk.LEFT, padx=10)
        tk.Button(btn_frame, text="✕ Cancel", command=dialog.destroy, bg="#95a5a6", fg="white",
                font=("Arial", 11), padx=25, pady=10).pack(side=tk.LEFT, padx=10)

    def refresh_entries(self):
        """Refresh entries list"""
        if not self.is_loaded:
            return
        try:
            self.entries_listbox.delete(0, tk.END)
            self.clear_details()
            for entry in self.vault.list_entries():
                self.entries_listbox.insert(tk.END, entry)
        except VaultLockedError:
            self.lock_vault()
            messagebox.showwarning("Vault Locked", "Vault auto-locked due to inactivity")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load entries: {str(e)}")

    def filter_entries(self, *args):
        """Filter entries by search term"""
        if not self.is_loaded:
            return
        try:
            search = self.search_var.get().lower()
            self.entries_listbox.delete(0, tk.END)
            for entry in self.vault.list_entries():
                if search in entry.lower():
                    self.entries_listbox.insert(tk.END, entry)
        except VaultLockedError:
            self.lock_vault()

    def on_entry_selected(self, event):
        """Handle entry selection"""
        if not self.is_loaded:
            return
        try:
            sel = self.entries_listbox.curselection()
            if not sel:
                return
            name = self.entries_listbox.get(sel[0])
            data = self.vault.get_entry(name)
            if data:
                self.name_var.set(name)
                self.username_var.set(data.get("username", ""))
                self.actual_password = data.get("password", "")
                self.show_password = False
                self.update_password_display()
                self.url_var.set(data.get("url", ""))
                self.notes_var.set(data.get("notes", ""))
                self.created_var.set(data.get("created", ""))
        except VaultLockedError:
            self.lock_vault()

    def clear_details(self):
        """Clear entry details display"""
        for var in [self.name_var, self.username_var, self.password_var, self.url_var, self.notes_var, self.created_var]:
            var.set("")
        self.actual_password = ""

    def copy_password(self):
        """Copy password to clipboard with auto-clear"""
        pwd = self.actual_password
        if pwd:
            self.clipboard_manager.copy_to_clipboard(pwd)
            messagebox.showinfo("Copied", f"Password copied to clipboard!\n(Will auto-clear in {CLIPBOARD_CLEAR_TIMEOUT}s)")
            log_audit_event("PASSWORD_COPIED", "Password copied to clipboard")
        else:
            messagebox.showwarning("No Password", "No password selected")

    def add_entry_window(self):
        """Open add entry dialog"""
        if not self.is_loaded:
            messagebox.showwarning("Not Loaded", "Load or create a vault first")
            return
        AddEntryWindow(self.root, self.vault, self.refresh_entries)

    def edit_entry_window(self):
        """Open edit entry dialog"""
        if not self.is_loaded:
            messagebox.showwarning("Not Loaded", "Load vault first")
            return
        name = self.name_var.get()
        if not name:
            messagebox.showwarning("No Selection", "Select an entry to edit")
            return
        try:
            data = self.vault.get_entry(name)
            if data:
                AddEntryWindow(self.root, self.vault, self.refresh_entries, name, data)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def delete_entry(self):
        """Delete entry from vault"""
        if not self.is_loaded:
            messagebox.showwarning("Not Loaded", "Load vault first")
            return
        name = self.name_var.get()
        if not name:
            messagebox.showwarning("No Selection", "Select an entry to delete")
            return
        if messagebox.askyesno("Confirm Delete", f"Delete '{name}'? This cannot be undone."):
            try:
                self.vault.delete_entry(name)
                self.refresh_entries()
                messagebox.showinfo("Success", "Entry deleted!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed: {str(e)}")

    def export_vault(self):
        """Export vault to encrypted backup"""
        if not self.is_loaded:
            messagebox.showwarning("Not Loaded", "Load vault first")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("Encrypted Backups", "*.json"), ("All files", "*.*")],
            initialdir=str(Path.home() / "Desktop")
        )
        if path:
            # Use validation function for password strength check
            dialog = PasswordDialog(
                self.root,
                "Export Backup",
                "Backup Encryption Password:",
                validate_func=validate_password_strength
            )
            if dialog.result and not dialog.dialog_cancelled:
                try:
                    self.set_status("Exporting...", self.warning_color)
                    self.vault.export_vault(Path(path), dialog.result)
                    self.set_status("Exported!", self.success_color)
                    messagebox.showinfo("Success", f"Backup exported to:\n{path}")
                except Exception as e:
                    self.set_status("Export failed", self.danger_color)
                    messagebox.showerror("Error", f"Export failed: {str(e)}")

    def import_vault(self):
        """Import vault from encrypted backup - creates new vault with imported entries"""
        path = filedialog.askopenfilename(
            filetypes=[("Encrypted Backups", "*.json"), ("All files", "*.*")],
            initialdir=str(Path.home() / "Desktop")
        )
        if not path:
            return

        # First get backup decryption password
        backup_password_dialog = PasswordDialog(self.root, "Import Backup", "Backup Decryption Password:")
        if not backup_password_dialog.result or backup_password_dialog.dialog_cancelled:
            return

        backup_password = backup_password_dialog.result

        try:
            self.set_status("Decrypting backup...", self.warning_color)
            imported_data = self.vault.import_vault(Path(path), backup_password)
            entry_count = len(imported_data.get("entries", {}))

            # Now ask for new vault name and master password
            import_dialog = tk.Toplevel(self.root)
            import_dialog.title("Create Vault from Backup")
            import_dialog.geometry("500x350")
            import_dialog.transient(self.root)
            import_dialog.grab_set()

            bg = self.bg_color
            fg = self.fg_color
            import_dialog.configure(bg=bg)

            frame = tk.Frame(import_dialog, bg=bg)
            frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

            tk.Label(frame, text=f"📊 Backup contains {entry_count} entries",
                    bg=bg, fg="#2ecc71", font=("Arial", 11, "bold")).pack(anchor=tk.W, pady=(0, 15))

            tk.Label(frame, text="📝 New Vault Name:", bg=bg, fg=fg, font=("Arial", 12, "bold")).pack(anchor=tk.W, pady=(0, 5))
            name_entry = tk.Entry(frame, font=("Arial", 12), width=40, bg="#34495e", fg=fg)
            name_entry.pack(fill=tk.X, pady=(0, 15))
            name_entry.focus()
            name_entry.insert(0, "Imported Vault")

            tk.Label(frame, text="🔐 Master Password for New Vault:", bg=bg, fg=fg, font=("Arial", 12, "bold")).pack(anchor=tk.W, pady=(0, 5))
            pwd_entry = tk.Entry(frame, font=("Arial", 12), show="•", width=40, bg="#34495e", fg=fg)
            pwd_entry.pack(fill=tk.X, pady=(0, 5))

            strength_frame = tk.Frame(frame, bg=bg)
            strength_frame.pack(fill=tk.X, pady=(0, 15))
            strength_label = tk.Label(strength_frame, text="Strength: —", bg=bg, fg=self.warning_color)
            strength_label.pack(side=tk.LEFT)

            def update_strength(*args):
                pwd = pwd_entry.get()
                is_valid, feedback = validate_password_strength(pwd)
                strength_bar = get_password_strength_bar(pwd)
                color = self.success_color if is_valid else self.danger_color
                strength_label.config(text=f"Strength: {strength_bar}", fg=color)

            pwd_entry.bind('<KeyRelease>', update_strength)

            btn_frame = tk.Frame(frame, bg=bg)
            btn_frame.pack(fill=tk.X, pady=(20, 0))

            def save_imported():
                vault_name = name_entry.get().strip()
                password = pwd_entry.get()

                if not vault_name or not password:
                    messagebox.showwarning("Missing", "Vault name and password required")
                    return

                if vault_name in self.vaults_config["vaults"]:
                    messagebox.showerror("Error", f"Vault '{vault_name}' already exists")
                    return

                try:
                    is_valid, feedback = validate_password_strength(password)
                    if not is_valid:
                        messagebox.showwarning("Weak Password", feedback)
                        return

                    self.set_status("Creating vault with imported entries...", self.warning_color)

                    # Create new vault with imported entries
                    vault_path = Path.home() / ".local_vault" / f"{vault_name}.json"
                    vault_path.parent.mkdir(parents=True, exist_ok=True)

                    new_vault = VaultManager(vault_path)
                    new_vault.init_vault(password, vault_name)

                    # Decrypt entries from backup
                    # The content_salt is now included in the imported_data (added by import_vault)
                    decrypted_entries = {}
                    try:
                        content_salt_b64 = imported_data.get("_content_salt", "")
                        if not content_salt_b64:
                            messagebox.showerror("Error", "Cannot find content salt in backup. Backup may be corrupted.")
                            return

                        # Decrypt all entries using BACKUP PASSWORD (not new vault password)
                        decrypted_entries = new_vault.decrypt_backup_entries(
                            imported_data.get("entries", {}),
                            backup_password,  # Use backup password for decryption
                            content_salt_b64
                        )
                    except Exception as e:
                        messagebox.showerror("Error", f"Failed to decrypt backup entries: {str(e)}")
                        return  # Exit if decryption fails

                    # Add all decrypted entries to the new vault
                    successful_imports = 0
                    failed_imports = 0
                    failed_reasons = []

                    for entry_name, entry_data in decrypted_entries.items():
                        try:
                            username = entry_data.get("username", "")
                            entry_password = entry_data.get("password", "")
                            url = entry_data.get("url", "")
                            notes = entry_data.get("notes", "")

                            # Must have entry name and password (username is optional, can be empty)
                            if entry_name and entry_password:
                                # Use add_entry_from_import to skip password strength validation
                                # (imported passwords are already validated from source vault)
                                new_vault.add_entry_from_import(entry_name, username, entry_password, url, notes)
                                successful_imports += 1
                                print(f"✓ Imported: {entry_name}")
                            else:
                                failed_imports += 1
                                reason = ""
                                if not entry_password:
                                    reason = "no password"
                                elif not entry_name:
                                    reason = "no name"
                                failed_reasons.append(f"{entry_name or '(unnamed)'}: {reason}")
                                print(f"✗ Skipped {entry_name}: {reason}")

                        except Exception as e:
                            failed_imports += 1
                            error_msg = str(e)
                            failed_reasons.append(f"{entry_name}: {error_msg}")
                            print(f"✗ Failed to import '{entry_name}': {error_msg}")

                    # Register the vault
                    self.vaults_config["vaults"][vault_name] = str(vault_path)
                    self.save_vault_list()

                    # Load the newly created vault
                    self.vault = new_vault
                    self.current_vault_name = vault_name
                    self.is_loaded = True
                    self.refresh_entries()
                    self.update_vault_display()

                    self.set_status(f"✓ Vault '{vault_name}' created!", self.success_color)
                    result_msg = f"Vault '{vault_name}' created successfully!\n{successful_imports} entries imported"
                    if failed_imports > 0:
                        result_msg += f"\n({failed_imports} entries failed)"
                    messagebox.showinfo("Success", result_msg)
                    import_dialog.destroy()

                except WeakPasswordError as e:
                    messagebox.showwarning("Weak Password", str(e))
                except Exception as e:
                    self.set_status("Error", self.danger_color)
                    messagebox.showerror("Error", f"Failed to create vault: {str(e)}")
                    log_audit_event("VAULT_IMPORT_FAILED", str(e), False)

            tk.Button(btn_frame, text="✓ CREATE FROM BACKUP", command=save_imported,
                    bg=self.success_color, fg="white", font=("Arial", 12, "bold"), padx=30, pady=12).pack(side=tk.LEFT, padx=10)
            tk.Button(btn_frame, text="✕ Cancel", command=import_dialog.destroy,
                    bg="#95a5a6", fg="white", font=("Arial", 11), padx=25, pady=10).pack(side=tk.LEFT, padx=10)

        except Exception as e:
            self.set_status("Import failed", self.danger_color)
            messagebox.showerror("Error", f"Import failed: {str(e)}")

    def lock_vault(self):
        """Manually lock vault"""
        if self.is_loaded:
            self.vault.lock_vault()
            self.is_loaded = False
            self.current_vault_name = None
            self.refresh_entries()
            self.update_vault_display()
            self.set_status("Vault locked", self.warning_color)
            messagebox.showinfo("Locked", "Vault has been locked and cleared from memory")
            log_audit_event("VAULT_MANUALLY_LOCKED", "User locked vault")

    def delete_vault_dialog(self):
        """Delete vault with password verification"""
        if not self.vaults_config["vaults"]:
            messagebox.showinfo("No Vaults", "No vaults found")
            return

        dialog = tk.Toplevel(self.root)
        dialog.title("Delete Vault")
        dialog.geometry("500x400")
        dialog.transient(self.root)
        dialog.grab_set()

        bg = self.bg_color
        fg = self.fg_color
        dialog.configure(bg=bg)

        frame = tk.Frame(dialog, bg=bg)
        frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        tk.Label(frame, text="Select Vault to Delete:", bg=bg, fg=fg, font=("Arial", 12, "bold")).pack(anchor=tk.W, pady=(0, 10))

        listbox = tk.Listbox(frame, font=("Arial", 11), bg="#34495e", fg=fg, height=8)
        listbox.pack(fill=tk.BOTH, expand=True, pady=(0, 20))

        for vault_name in sorted(self.vaults_config["vaults"].keys()):
            listbox.insert(tk.END, vault_name)

        tk.Label(frame, text="Master Password:", bg=bg, fg=fg, font=("Arial", 12, "bold")).pack(anchor=tk.W, pady=(0, 5))
        pwd_entry = tk.Entry(frame, font=("Arial", 12), show="*", width=40, bg="#34495e", fg=fg)
        pwd_entry.pack(fill=tk.X, pady=(0, 20))

        warning_label = tk.Label(frame, text="Warning: This will permanently delete the vault. This cannot be undone.",
                bg=bg, fg=self.danger_color, font=("Arial", 9))
        warning_label.pack(anchor=tk.W, pady=(0, 10))

        btn_frame = tk.Frame(frame, bg=bg)
        btn_frame.pack(fill=tk.X, pady=(10, 0))

        def delete_selected():
            selection = listbox.curselection()
            if not selection:
                messagebox.showwarning("No Selection", "Select a vault to delete")
                return

            vault_name = listbox.get(selection[0])
            password = pwd_entry.get()

            if not password:
                messagebox.showwarning("Missing", "Password required")
                return

            try:
                vault_path = Path(self.vaults_config["vaults"][vault_name])
                vault_temp = VaultManager(vault_path)
                vault_temp.load_vault(password)

                if not messagebox.askyesno("Confirm Delete",
                        f"Really delete vault '{vault_name}'? This cannot be undone."):
                    return

                vault_path.unlink()
                del self.vaults_config["vaults"][vault_name]
                self.save_vault_list()

                if self.current_vault_name == vault_name:
                    self.is_loaded = False
                    self.current_vault_name = None
                    self.refresh_entries()
                    self.update_vault_display()

                messagebox.showinfo("Success", f"Vault '{vault_name}' deleted successfully")
                self.set_status(f"Vault '{vault_name}' deleted", self.success_color)
                dialog.destroy()

            except Exception as e:
                messagebox.showerror("Error", f"Failed to delete vault: {str(e)}")
                log_audit_event("VAULT_DELETE_FAILED", str(e), False)

        tk.Button(btn_frame, text="Delete Vault", command=delete_selected, bg=self.danger_color, fg="white",
                font=("Arial", 12, "bold"), padx=30, pady=12).pack(side=tk.LEFT, padx=10)
        tk.Button(btn_frame, text="Cancel", command=dialog.destroy, bg="#95a5a6", fg="white",
                font=("Arial", 11), padx=25, pady=10).pack(side=tk.LEFT, padx=10)

class AddEntryWindow:
    def __init__(self, parent, vault, callback, entry_name=None, entry_data=None):
        self.vault = vault
        self.callback = callback
        self.entry_name = entry_name

        self.win = tk.Toplevel(parent)
        self.win.title("Add Entry" if not entry_name else f"Edit: {entry_name}")
        self.win.geometry("550x500")
        self.win.transient(parent)
        self.win.grab_set()

        bg = "#2c3e50"
        fg = "#ecf0f1"
        self.win.configure(bg=bg)

        main = tk.Frame(self.win, bg=bg)
        main.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)

        tk.Label(main, text="Entry Name:", bg=bg, fg=fg).grid(row=0, column=0, sticky=tk.W, pady=8)
        self.name_entry = tk.Entry(main, font=("Arial", 10), width=40, bg="#34495e", fg=fg)
        self.name_entry.grid(row=0, column=1, sticky=tk.EW, pady=8)
        if entry_name:
            self.name_entry.insert(0, entry_name)
            self.name_entry.config(state=tk.DISABLED)

        tk.Label(main, text="Username:", bg=bg, fg=fg).grid(row=1, column=0, sticky=tk.W, pady=8)
        self.username_entry = tk.Entry(main, font=("Arial", 10), width=40, bg="#34495e", fg=fg)
        self.username_entry.grid(row=1, column=1, sticky=tk.EW, pady=8)
        if entry_data:
            self.username_entry.insert(0, entry_data.get("username", ""))

        tk.Label(main, text="Password:", bg=bg, fg=fg).grid(row=2, column=0, sticky=tk.W, pady=8)
        pwd_frame = tk.Frame(main, bg=bg)
        pwd_frame.grid(row=2, column=1, sticky=tk.EW, pady=8)

        self.password_entry = tk.Entry(pwd_frame, font=("Arial", 10), width=30, show="•", bg="#34495e", fg=fg)
        self.password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        if entry_data:
            self.password_entry.insert(0, entry_data.get("password", ""))

        def toggle_pwd_show():
            if self.password_entry.cget("show") == "•":
                self.password_entry.config(show="")
            else:
                self.password_entry.config(show="•")

        tk.Button(pwd_frame, text="👁", command=toggle_pwd_show, bg="#3498db", fg="white", width=2).pack(side=tk.LEFT, padx=5)

        # Password strength
        strength_label = tk.Label(main, text="Strength: —", bg=bg, fg="#f39c12")
        strength_label.grid(row=2, column=2, sticky=tk.W, padx=5)

        def update_strength(*args):
            pwd = self.password_entry.get()
            is_valid, _ = validate_password_strength(pwd)
            strength_bar = get_password_strength_bar(pwd)
            color = "#2ecc71" if is_valid else "#e74c3c"
            strength_label.config(text=strength_bar, fg=color)

        self.password_entry.bind('<KeyRelease>', update_strength)

        tk.Label(main, text="URL:", bg=bg, fg=fg).grid(row=3, column=0, sticky=tk.W, pady=8)
        self.url_entry = tk.Entry(main, font=("Arial", 10), width=40, bg="#34495e", fg=fg)
        self.url_entry.grid(row=3, column=1, sticky=tk.EW, pady=8)
        if entry_data:
            self.url_entry.insert(0, entry_data.get("url", ""))

        tk.Label(main, text="Notes:", bg=bg, fg=fg).grid(row=4, column=0, sticky=tk.NW, pady=8)
        self.notes_entry = tk.Text(main, font=("Arial", 10), width=40, height=6, bg="#34495e", fg=fg)
        self.notes_entry.grid(row=4, column=1, sticky=tk.EW, pady=8)
        if entry_data:
            self.notes_entry.insert(1.0, entry_data.get("notes", ""))

        btn_f = tk.Frame(main, bg=bg)
        btn_f.grid(row=5, column=0, columnspan=3, sticky=tk.EW, pady=20)

        tk.Button(btn_f, text="✓ SAVE ENTRY", command=self.save_entry, bg="#2ecc71", fg="white",
                font=("Arial", 12, "bold"), padx=30, pady=12).pack(side=tk.LEFT, padx=10)
        tk.Button(btn_f, text="✕ Cancel", command=self.win.destroy, bg="#95a5a6", fg="white",
                font=("Arial", 11), padx=25, pady=10).pack(side=tk.LEFT, padx=10)

        main.columnconfigure(1, weight=1)
        main.rowconfigure(4, weight=1)

    def save_entry(self):
        name = self.name_entry.get()
        username = self.username_entry.get()
        password = self.password_entry.get()
        url = self.url_entry.get()
        notes = self.notes_entry.get(1.0, tk.END).strip()

        if not name or not password:
            messagebox.showwarning("Missing Data", "Entry name and password are required")
            return

        try:
            is_valid, feedback = validate_password_strength(password)
            if not is_valid:
                messagebox.showwarning("Weak Password", feedback)
                return

            self.vault.add_entry(name, username, password, url, notes)
            messagebox.showinfo("Success", "Entry saved!")
            self.callback()
            self.win.destroy()
        except WeakPasswordError as e:
            messagebox.showwarning("Weak Password", str(e))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save: {str(e)}")


class PasswordDialog:
    def __init__(self, parent, title, prompt, validate_func=None):
        """
        Password dialog with optional validation.
        validate_func: Optional function that takes password and returns (is_valid, message)
        """
        self.result = None
        self.validate_func = validate_func
        self.dialog_cancelled = False

        self.dialog = tk.Toplevel(parent)
        self.dialog.title(title)
        self.dialog.geometry("450x220")
        self.dialog.transient(parent)
        self.dialog.grab_set()

        bg = "#2c3e50"
        fg = "#ecf0f1"
        self.dialog.configure(bg=bg)

        main = tk.Frame(self.dialog, bg=bg)
        main.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)

        tk.Label(main, text=prompt, bg=bg, fg=fg, font=("Arial", 11)).pack(anchor=tk.W, pady=(0, 10))

        self.password_var = tk.StringVar()
        self.password_entry = tk.Entry(main, textvariable=self.password_var, font=("Arial", 11), show="•", width=40)
        self.password_entry.pack(fill=tk.X, pady=(0, 10))
        self.password_entry.focus()

        # Error/feedback label
        self.feedback_label = tk.Label(main, text="", bg=bg, fg="#e74c3c", font=("Arial", 9), wraplength=400, justify=tk.LEFT)
        self.feedback_label.pack(anchor=tk.W, pady=(0, 15))

        btn_f = tk.Frame(main, bg=bg)
        btn_f.pack(fill=tk.X)

        def on_ok():
            password = self.password_var.get()

            # Validate if validation function provided
            if self.validate_func:
                is_valid, message = self.validate_func(password)
                if not is_valid:
                    self.feedback_label.config(text=message, fg="#e74c3c")
                    self.password_entry.delete(0, tk.END)
                    self.password_entry.focus()
                    return

            self.result = password
            self.dialog.destroy()

        def on_cancel():
            self.dialog_cancelled = True
            self.dialog.destroy()

        tk.Button(btn_f, text="OK", command=on_ok, bg="#2ecc71", fg="white", padx=20, pady=10).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_f, text="Cancel", command=on_cancel, bg="#95a5a6", fg="white", padx=20, pady=10).pack(side=tk.LEFT, padx=5)

        self.password_entry.bind('<Return>', lambda e: on_ok())
        self.dialog.wait_window()


def main():
    root = tk.Tk()
    app = PasswordManagerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()

