#!/usr/bin/env python3
"""
Eyrie Password Manager v1.0.1
A secure, terminal-based password management system with encryption,
Two-Factor Authentication, and comprehensive credential management.

Author: Kur0Sh1r0 (A1SBERG)
License: GNU General Public License
"""

# ==============================================================================
# STANDARD LIBRARY IMPORTS
# ==============================================================================
import sys
import os
import argparse
import time
import json
import base64
import shutil
import re
from datetime import datetime

# ==============================================================================
# THIRD-PARTY LIBRARY IMPORTS
# ==============================================================================
from prompt_toolkit import prompt
from prompt_toolkit.shortcuts import clear
from prompt_toolkit.validation import Validator, ValidationError
from prompt_toolkit.completion import WordCompleter, Completer, Completion
from prompt_toolkit.history import InMemoryHistory, FileHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.key_binding import KeyBindings

# ==============================================================================
# CUSTOM MODULE IMPORTS
# ==============================================================================
from modules import crypto, database, password_generator, ui, validation, export_import, tfa

# ==============================================================================
# CONSTANTS AND GLOBAL CONFIGURATION
# ==============================================================================

# ASCII Art Banner for visual branding
BANNER = r"""
__/\\\\\\\\\\\\\\\__________________________________________________        
 _\/\\\///////////___________________________________________________       
  _\/\\\________________/\\\__/\\\________________/\\\________________      
   _\/\\\\\\\\\\\_______\//\\\/\\\___/\\/\\\\\\\__\///______/\\\\\\\\__     
    _\/\\\///////_________\//\\\\\___\/\\\/////\\\__/\\\___/\\\/////\\\_    
     _\/\\\_________________\//\\\____\/\\\___\///__\/\\\__/\\\\\\\\\\\__   
      _\/\\\______________/\\_/\\\_____\/\\\_________\/\\\_\//\\///////___  
       _\/\\\\\\\\\\\\\\\_\//\\\\/______\/\\\_________\/\\\__\//\\\\\\\\\\_ 
        _\///////////////___\////________\///__________\///____\//////////__ v1.0.1
                                                        - A1SBERG
"""

# Interactive command help menu
MAIN_MENU_INTERACTIVE = f"""
{BANNER}
Welcome to Eyrie Password Manager!
Here are the available commands you can use:

'add_entry' (ae) - Create new credential entry (prompts for service, username, password)
'list_entry' (le) - Display all stored credentials with IDs and titles
'get_entry' (ge) - Retrieve specific entry details by ID (shows password)
'update_entry' (ue) - Update specific entry details by ID
'delete_entry' (de) - Remove entry permanently (requires confirmation)
'password_history' (ph) - View password history for an entry (shows masked passwords)
'reveal_version' (rv) - Reveal plaintext password of specific history version (requires master password)
'clear_history' (ch) - Clear password history for an entry (requires confirmation)
'gen_passwd' (gp) - Generate secure random password (configurable length)
'ch_master_passwd' (cmp)- Change master vault password (re-encrypts all entries)
'vault_info' (vi) - View vault statistics and metadata
'export_vault' (ev) - Create encrypted backup of entire vault
'setup_2fa' (2fa) - Enable Two-Factor Authentication for this vault
'disable_2fa' (d2fa) - Disable Two-Factor Authentication
'show_2fa' (s2fa) - Show 2FA status and recovery codes
'help' (h) - Show this help message
'exit' (quit, q) - Exit the program

Type 'help' or 'h' for this menu anytime.
Use ↑/↓ arrows for command history.
"""

# Command aliases for user convenience (full names and abbreviations)
COMMAND_ALIASES = {
    'add_entry': 'add_entry',
    'list_entry': 'list_entry', 
    'get_entry': 'get_entry',
    'update_entry': 'update_entry',
    'delete_entry': 'delete_entry',
    'password_history': 'password_history',
    'reveal_version': 'reveal_version',
    'clear_history': 'clear_history',
    'gen_passwd': 'gen_passwd',
    'ch_master_passwd': 'ch_master_passwd',
    'vault_info': 'vault_info',
    'export_vault': 'export_vault',
    'setup_2fa': 'setup_2fa',
    'disable_2fa': 'disable_2fa',
    'show_2fa': 'show_2fa',
    'help': 'help',
    'exit': 'exit',
    'quit': 'exit',
    
    # Abbreviations
    'ae': 'add_entry',
    'le': 'list_entry',
    'ge': 'get_entry',
    'ue': 'update_entry',
    'de': 'delete_entry',
    'ph': 'password_history',
    'rv': 'reveal_version',
    'ch': 'clear_history',
    'gp': 'gen_passwd',
    'cmp': 'ch_master_passwd',
    'vi': 'vault_info',
    'ev': 'export_vault',
    '2fa': 'setup_2fa',
    'd2fa': 'disable_2fa',
    's2fa': 'show_2fa',
    'h': 'help',
    'q': 'exit',
}

# Reverse mapping for command completion and help display
REVERSE_ALIASES = {}
for alias, command in COMMAND_ALIASES.items():
    if command not in REVERSE_ALIASES:
        REVERSE_ALIASES[command] = [command]
    if alias != command:
        REVERSE_ALIASES[command].append(alias)

# ==============================================================================
# VALIDATORS
# ==============================================================================

class NumberValidator(Validator):
    """Validator for numeric input fields."""
    
    def validate(self, document):
        """Ensure input contains only digits."""
        text = document.text
        if text and not text.isdigit():
            raise ValidationError(message='Please enter a valid number')

# ==============================================================================
# MAIN EYRIE CLASS
# ==============================================================================

class Eyrie:
    """
    Main application controller for Eyrie Password Manager.
    
    This class manages the complete lifecycle of the password manager including:
    - Vault initialization and authentication
    - Session management
    - Command routing and execution
    - Cryptographic operations
    - 2FA management
    """
    
    def __init__(self):
        """Initialize a new Eyrie session with default settings."""
        self.db = None              # Database connection object
        self.master_key = None      # Current session encryption key
        self.session_start = None   # Session timestamp for timeout tracking
        self.device_id = tfa.tfa_manager.get_device_id()  # Unique device identifier for 2FA
        self.history = InMemoryHistory()  # Command history for current session
        self.auto_suggest = AutoSuggestFromHistory()  # Command suggestions
        self.bindings = KeyBindings()  # Custom key bindings
    
    # ==========================================================================
    # COMMAND RESOLUTION AND PROMPT FORMATTING
    # ==========================================================================
    
    def _resolve_command(self, command_input):
        """
        Resolve user input to a valid command using aliases and prefix matching.
        
        Args:
            command_input (str): Raw user input command
            
        Returns:
            str or None: Resolved command name or None if invalid/ambiguous
        """
        if not command_input:
            return None
            
        command_input = command_input.strip().lower()
        
        # Exact alias match
        if command_input in COMMAND_ALIASES:
            return COMMAND_ALIASES[command_input]
        
        # Prefix matching for tab completion
        matches = [cmd for cmd in COMMAND_ALIASES.keys() 
                  if cmd.startswith(command_input)]
        
        if len(matches) == 1:
            return COMMAND_ALIASES[matches[0]]
        elif len(matches) > 1:
            print(f"[-] Ambiguous command '{command_input}'. Could be: {', '.join(matches)}")
            return None
        
        # No matches found
        print(f"[-] Unknown command: '{command_input}'")
        print(f"[i] Type 'help' or 'h' for available commands")
        return None
    
    def _format_prompt(self):
        """Format the interactive prompt with session context."""
        if self.db and self.master_key:
            session_minutes = int((time.time() - self.session_start) / 60)
            vault_name = os.path.basename(self.db.db_path)
            if vault_name.endswith('.eyr'):
                vault_name = vault_name[:-4]
            
            return f"eyrie@{vault_name}/> "
        
        return "eyrie@unauthorized/> "
    
    # ==========================================================================
    # VAULT MANAGEMENT
    # ==========================================================================
    
    def initialize_vault(self, vault_path="vault.eyr"):
        """
        Create a new encrypted vault with master password.
        
        Args:
            vault_path (str): Path to create the vault file
            
        Returns:
            bool: True if vault creation succeeded
        """
        # Check if vault already exists
        if os.path.exists(vault_path):
            print(f"[-] Vault file '{vault_path}' already exists!")
            print("[i] If you want to use an existing vault, use 'unlock' instead.")
            print("[i] If you want to create a new vault, choose a different name or path.")
            return False
        
        # Also check for backup files with .enc extension
        backup_path = vault_path
        if not backup_path.endswith('.enc'):
            backup_path = vault_path.replace('.eyr', '.enc') if vault_path.endswith('.eyr') else f"{vault_path}.enc"

        if os.path.exists(backup_path):
            print(f"[-] Warning: A backup file '{backup_path}' exists in this location!")
            print("[i] To avoid confusion, consider using a different directory for your new vault.")
            proceed = prompt("Continue anyway? [y/N]: ").strip().lower()
            if proceed != 'y':
                return False
                
        # Master password creation with validation
        while True:
            master_pwd = prompt(
                "Create master password (minimum 12 characters): ",
                is_password=True
            )
            confirm_pwd = prompt(
                "Confirm master password: ",
                is_password=True
            )
            
            if master_pwd != confirm_pwd:
                print("[-] Passwords do not match")
                continue
            
            is_valid, message = validation.validate_password_strength(master_pwd)
            if not is_valid:
                print(f"[-] Password validation failed: {message}")
                continue
            break
        
        print("[+] Deriving encryption key...")
        self.master_key, salt = crypto.derive_master_key(master_pwd)
        
        # Initialize database with encrypted vault
        self.db = database.VaultDatabase(vault_path)
        
        if self.db.initialize_vault(self.master_key, salt):
            self.session_start = time.time()
            crypto.secure_erase(master_pwd)  # Securely clear password from memory
            print(f"[+] Eyrie vault successfully created: {vault_path}")
            return True
        
        print("[-] Vault initialization failed")
        return False
    
    def unlock_vault(self, vault_path="vault.eyr"):
        """
        Authenticate and unlock an existing vault.
        
        Args:
            vault_path (str): Path to the vault file
            
        Returns:
            bool: True if authentication succeeded
        """
        # Validate vault existence
        if not os.path.exists(vault_path):
            print(f"[-] Eyrie vault not found: {vault_path}")
            return False
        
        # Rate limiting to prevent brute force attacks
        if not validation.check_rate_limit(vault_path):
            print("[-] Rate limit exceeded. Please wait before retrying.")
            return False
        
        attempts = 0
        max_attempts = 5
        
        # Authentication loop with attempt limiting
        while attempts < max_attempts:
            master_pwd = prompt(
                "Master password: ",
                is_password=True
            )
            
            # Temporary connection for key verification
            temp_db = database.VaultDatabase(vault_path)
            temp_db.connect()
            
            try:
                if not temp_db.eyr_file or not temp_db.eyr_file.load():
                    print("[-] Invalid vault file format")
                    temp_db.close()
                    return False
                
                # Extract cryptographic salt from vault metadata
                metadata = temp_db.eyr_file.metadata
                if not metadata:
                    print("[-] Vault metadata missing")
                    temp_db.close()
                    return False
                    
                salt_b64 = metadata.get('salt')
                if not salt_b64:
                    print("[-] Encryption salt missing")
                    temp_db.close()
                    return False
                    
                salt = base64.b64decode(salt_b64)
                test_key, _ = crypto.derive_master_key(master_pwd, salt)
                
            except Exception as e:
                print(f"[-] Vault read error: {e}")
                temp_db.close()
                return False
            finally:
                temp_db.close()
            
            # Verify master key against vault
            self.db = database.VaultDatabase(vault_path)
            self.db.connect()
            
            if self.db.eyr_file and self.db.eyr_file.load():
                if self.db.verify_master_key(test_key):
                    # Check if 2FA is enabled
                    tfa_settings = self.db.get_tfa_settings(test_key)
                    
                    if tfa_settings and tfa_settings.get('enabled'):
                        print("[+] 2FA enabled for this vault")
                        
                        # Check if device is already trusted
                        trusted_devices = tfa_settings.get('trusted_devices', [])
                        is_trusted = tfa.tfa_manager.is_trusted_device(self.device_id, trusted_devices)
                        
                        if not is_trusted:
                            # Require 2FA verification for untrusted devices
                            if not self._verify_2fa(test_key):
                                print("[-] 2FA verification failed")
                                crypto.secure_erase_key(test_key)
                                crypto.secure_erase(master_pwd)
                                return False
                            
                            # Option to trust the current device
                            trust = prompt("Trust this device? (No 2FA required for 30 days) [Y/n]: ").strip().lower()
                            if trust != 'n':
                                self.db.update_trusted_device(test_key, self.device_id, add=True)
                                print("[+] Device trusted for 30 days")
                            else:
                                print("[+] Device not trusted - 2FA will be required next time")
                    
                    # Authentication successful
                    self.master_key = test_key
                    self.session_start = time.time()
                    validation.clear_failed_attempts(vault_path)
                    crypto.secure_erase(master_pwd)
                    clear()  # Clear screen for security
                    print(BANNER)
                    print("[+] Eyrie vault successfully unlocked")
                    return True
            
            # Authentication failed
            attempts += 1
            remaining = max_attempts - attempts
            print(f"[-] Authentication failed. Attempts remaining: {remaining}")
            validation.record_failed_attempt(vault_path)
        
        print("[-] Maximum authentication attempts reached")
        return False
    
    # ==========================================================================
    # TWO-FACTOR AUTHENTICATION MANAGEMENT
    # ==========================================================================
    
    def _verify_2fa(self, master_key: bytes) -> bool:
        """
        Verify Two-Factor Authentication using TOTP or recovery codes.
        
        Args:
            master_key (bytes): The master encryption key
            
        Returns:
            bool: True if 2FA verification succeeded
        """
        print("[+] Two-Factor Authentication Required")
        print("Options:")
        print("  1. Enter TOTP code from authenticator app")
        print("  2. Use recovery code")
        
        choice = prompt("Select option [1/2]: ").strip()
        
        # TOTP code verification
        if choice == "1":
            for attempt in range(3):
                code = prompt(f"Enter 6-digit code (attempt {attempt + 1}/3): ").strip().replace(" ", "")
                
                if not code.isdigit() or len(code) != 6:
                    print("[-] Invalid code format")
                    continue
                
                if self.db.verify_totp_code(master_key, code):
                    print("[+] 2FA verification successful")
                    return True
                else:
                    print("[-] Invalid 2FA code")
            
            print("[-] Too many failed attempts")
            return False
        
        # Recovery code verification
        elif choice == "2":
            code = prompt("Enter recovery code: ").strip().replace(" ", "").upper()
            
            if len(code) != 8:
                print("[-] Invalid recovery code format")
                return False
            
            is_valid, should_disable = self.db.verify_recovery_code(master_key, code)
            
            if is_valid:
                print("[+] Recovery code accepted")
                if should_disable:
                    print("[!] Warning: No more recovery codes remaining")
                    disable = prompt("Disable 2FA? [y/N]: ").strip().lower()
                    if disable == 'y':
                        self.db.disable_tfa(master_key)
                        print("[+] 2FA disabled")
                return True
            else:
                print("[-] Invalid recovery code")
                return False
        
        else:
            print("[-] Invalid option")
            return False
    
    def setup_2fa(self):
        """
        Enable Two-Factor Authentication for the current vault.
        
        Returns:
            bool: True if 2FA setup completed successfully
        """
        if not self._check_session():
            return False
        
        # Ensure vault supports 2FA metadata
        print("[+] Ensuring vault has 2FA metadata fields...")
        if not self.db.add_tfa_fields_if_missing(self.master_key):
            print("[-] Could not add 2FA fields to vault metadata")
            return False
        
        # Check if 2FA is already enabled
        tfa_settings = self.db.get_tfa_settings(self.master_key)
        if tfa_settings and tfa_settings.get('enabled'):
            print("[-] 2FA is already enabled")
            disable = prompt("Disable 2FA? [y/N]: ").strip().lower()
            if disable == 'y':
                return self.disable_2fa()
            return False
        
        # 2FA Setup Process
        print("="*60)
        print("Two-Factor Authentication Setup")
        print("="*60)
        
        # Get vault name for username
        vault_name = os.path.basename(self.db.db_path)
        if vault_name.endswith('.eyr'):
            vault_name = vault_name[:-4]
        
        try:
            vault_info = self.db.get_vault_info(self.master_key)
            if vault_info and 'name' in vault_info:
                friendly_name = vault_info['name']
            else:
                friendly_name = vault_name
        except:
            friendly_name = vault_name
        
        # Use the complete setup method that includes file saving
        try:
            secret, recovery_codes, qr_code, saved_file = tfa.tfa_manager.setup_two_factor_auth(
                friendly_name
            )
            
            print(f"Secret: {secret}")
            print(f"\nScan QR code with authenticator app:")
            print("-" * 46)
            
            if qr_code:
                print(qr_code)
            else:
                print("[-] Could not generate QR code. Please use manual setup.")
                print(f"Manual entry:")
                print(f"Secret: {secret}")
                print(f"Account: {friendly_name}")
                print(f"Issuer: Eyrie Password Manager")
                print(f"Algorithm: SHA1")
                print(f"Digits: 6")
                print(f"Interval: 30 seconds")
            
            print("-" * 46)
            
            # Display recovery codes with security warning
            print("\n" + "-"*60)
            print("EMERGENCY RECOVERY CODES (SAVE THESE SECURELY):")
            print("-"*60)
            for i, code in enumerate(recovery_codes, 1):
                print(f"  {i:2}. {code}")
            
            print(f"\n[i] IMPORTANT:")
            print(f"1. Recovery codes saved to: {saved_file}")
            print(f"2. Save this file in a secure location!")
            print(f"3. You will need these if you lose access to your authenticator app.")
            print(f"4. Each code can be used only once.")
            print("-"*60)
            
        except Exception as e:
            print(f"[-] 2FA setup error: {e}")
            return False
        
        # Verify setup with a test code
        print("To complete setup, enter a code from your authenticator app:")
        
        for attempt in range(3):
            test_code = prompt(f"Verification code (attempt {attempt + 1}/3): ").strip()
            
            if tfa.tfa_manager.verify_totp_code(secret, test_code):
                print("[+] TOTP code verified successfully!")
                
                # Enable 2FA in the vault
                print("[+] Enabling 2FA in vault...")
                if self.db.enable_tfa(self.master_key, secret, recovery_codes):
                    print("[+] Two-Factor Authentication enabled successfully!")
                    
                    # Option to trust current device
                    trust = prompt("\nTrust this device? (No 2FA required for 30 days) [Y/n]: ").strip().lower()
                    if trust != 'n':
                        self.db.update_trusted_device(self.master_key, self.device_id, add=True)
                        print("[+] Device trusted for 30 days")
                    
                    print("\n[+] Setup complete! Your vault is now protected by 2FA.")
                    return True
                else:
                    print("[-] Failed to enable 2FA in database")
                    return False
            
            print("[-] Invalid code")
        
        print("[-] Too many failed attempts. 2FA setup cancelled.")
        return False
    
    def disable_2fa(self):
        """
        Disable Two-Factor Authentication for the current vault.
        
        Returns:
            bool: True if 2FA was successfully disabled
        """
        if not self._check_session():
            return False
        
        # Security warning
        print("!"*60)
        print("WARNING: Disabling Two-Factor Authentication")
        print("This will remove all 2FA protection from your vault.")
        print("!"*60)
        
        # Require master password confirmation
        master_password = prompt(
            "Enter master password to confirm: ",
            is_password=True
        )

        if master_password == "":
            print("[-] Master password incorrect. Disabling cancelled.")
            return False
        
        # Verify master password
        temp_db = database.VaultDatabase(self.db.db_path)
        temp_db.connect()
        
        try:
            if not temp_db.eyr_file or not temp_db.eyr_file.load():
                print("[-] Vault access error")
                return False
            
            metadata = temp_db.eyr_file.metadata
            if not metadata:
                print("[-] Metadata retrieval failed")
                return False
            
            salt_b64 = metadata.get('salt')
            if not salt_b64:
                print("[-] Cryptographic salt missing")
                return False
            
            salt = base64.b64decode(salt_b64)
            verification_key, _ = crypto.derive_master_key(master_password, salt)
            
            if verification_key != self.master_key:
                print("[-] Master password incorrect. Disabling cancelled.")
                crypto.secure_erase(master_password)
                crypto.secure_erase_key(verification_key)
                return False
            
            temp_db.close()
            
        except Exception as e:
            print(f"[-] Verification error: {e}")
            crypto.secure_erase(master_password)
            if 'temp_db' in locals():
                temp_db.close()
            return False
        
        # Securely clear verification data
        crypto.secure_erase(master_password)
        crypto.secure_erase_key(verification_key)
        
        # Final confirmation
        confirmation = prompt(
            "Are you sure you want to disable 2FA? [y/N]: "
        ).strip().lower()
        
        if confirmation != 'y':
            print("[-] 2FA disable cancelled")
            return False
        
        # Disable 2FA in database
        if self.db.disable_tfa(self.master_key):
            print("[+] Two-Factor Authentication disabled")
            print("[!] Your vault is no longer protected by 2FA")
            return True
        else:
            print("[-] Failed to disable 2FA")
            return False
    
    def show_2fa_status(self):
        """Display current 2FA configuration and status."""
        if not self._check_session():
            return
        
        tfa_settings = self.db.get_tfa_settings(self.master_key)
        
        if not tfa_settings:
            print("[-] Could not retrieve 2FA settings")
            return
        
        # Display 2FA status report
        print("="*60)
        print("Two-Factor Authentication Status")
        print("="*60)
        
        enabled = tfa_settings.get('enabled', False)
        status_icon = "✓" if enabled else "✗"
        print(f"Status: {status_icon} {'ENABLED' if enabled else 'DISABLED'}")
        
        if enabled:
            # Last used timestamp
            last_used = tfa_settings.get('last_used')
            if last_used:
                try:
                    last_used_str = datetime.fromtimestamp(last_used).strftime("%Y-%m-d %H:%M:%S")
                    print(f"Last used: {last_used_str}")
                except:
                    pass
            
            # Trusted devices information
            trusted_devices = tfa_settings.get('trusted_devices', [])
            is_trusted = tfa.tfa_manager.is_trusted_device(self.device_id, trusted_devices)
            print(f"This device: {'Trusted' if is_trusted else 'Not trusted'}")
            
            print(f"\nTrusted devices: {len(trusted_devices)}")
            if trusted_devices:
                current_time = time.time()
                for device in trusted_devices[:5]:
                    device_id = device.get('device_id', 'Unknown')
                    expires = device.get('expires', 0)
                    days_left = max(0, int((expires - current_time) / 86400))
                    is_current = device_id == self.device_id
                    device_marker = " (Current)" if is_current else ""
                    print(f"  • {device_id[:8]}...{device_marker}")
                    print(f"    Expires in: {days_left} days")
                
                if len(trusted_devices) > 5:
                    print(f"  ... and {len(trusted_devices) - 5} more")
            
            # Recovery codes status
            recovery_codes = tfa_settings.get('recovery_codes', [])
            unused_codes = [c for c in recovery_codes if not c.get('used', False)]
            
            print(f"\nRecovery codes:")
            print(f"  Unused: {len(unused_codes)}")
            print(f"  Used: {len(recovery_codes) - len(unused_codes)}")
            
            if unused_codes:
                print("\nUnused recovery codes:")
                for i, code_info in enumerate(unused_codes, 1):
                    code = code_info.get('code', 'Unknown')
                    print(f"  {i:2}. {code}")
                
                if len(unused_codes) < 3:
                    print(f"\n[!] WARNING: Only {len(unused_codes)} recovery codes remaining!")
                    print("    Generate new codes or disable 2FA if you lose your authenticator.")
            else:
                print("\n[!] WARNING: No recovery codes remaining!")
                print("    If you lose your authenticator, you will be locked out.")
                print("    Consider disabling 2FA or setting it up again.")
        else:
            print("[-] 2FA is not enabled for this vault.")
            print("Use 'setup_2fa' to enable Two-Factor Authentication.")
        
        print("="*60)
    
    # ==========================================================================
    # CREDENTIAL MANAGEMENT
    # ==========================================================================
    
    def add_entry(self):
        """
        Add a new credential entry to the vault.
        
        Returns:
            bool: True if entry was successfully added
        """
        if not self._check_session():
            return False
        
        # Collect entry data from user with validation loops
        while True:
            title = prompt("Service/Application: ").strip()
            if not title:
                print("[-] Title required")
                continue
            break
        
        while True:
            username = prompt("Username/Email: ").strip()
            if not username:
                print("[-] Username required")
                continue
            break
        
        url = prompt("URL (optional): ").strip()
        
        category = prompt("Category [General]: ").strip() or "General"
        
        entry_data = {
            'title': title,
            'username': username,
            'url': url,
            'category': category
        }
        
        # Password generation/entry options
        print("Password generation options:")
        print("  1. Manual password entry")
        print("  2. Generate secure password")
        choice = prompt("Selection [1/2]: ").strip()
        
        if choice == "2":
            # Generate secure password
            while True:
                length_input = prompt("Password length [16]: ").strip()
                length = int(length_input) if length_input.isdigit() else 16
                
                if length < 8:
                    print("[-] Minimum password length is 8 characters")
                    continue
                break
            
            try:
                entry_data['password'] = password_generator.generate_secure_password(length)
                
                # Display password partially masked by default
                # Show first 3 characters and last 3 characters, mask the middle
                if len(entry_data['password']) <= 6:
                    # If password is too short, show as fully masked
                    masked_display = '*' * length
                    print(f"[+] Generated password: {masked_display}")
                else:
                    # Show first 3 chars, asterisks for middle, last 3 chars
                    first_part = entry_data['password'][:3]
                    last_part = entry_data['password'][-3:]
                    masked_middle = '*' * (len(entry_data['password']) - 6)
                    masked_display = f"{first_part}{masked_middle}{last_part}"
                    print(f"[+] Generated password: {masked_display}")
                
                if ui.copy_to_clipboard(entry_data['password']):
                    print("[+] Password automatically copied to clipboard (30 second retention)")
            except password_generator.PasswordGenerationError as e:
                print(f"[-] {e}")
                return False
        else:
            # Manual password entry with validation
            while True:
                password = prompt("Password: ", is_password=True)
                if not password:
                    print("[-] Password cannot be empty")
                    continue
                
                # Check password strength
                is_valid, message = validation.validate_password_strength(password)
                if not is_valid:
                    print(f"[-] Weak password: {message}")
                    print("[i] Use option 2 to generate a strong password")
                    use_weak = prompt("Use weak password anyway? [y/N]: ").strip().lower()
                    if use_weak != 'y':
                        continue
                
                entry_data['password'] = password
                # Don't show the manually entered password at all for security
                print("[+] Password entered and saved securely")
                if ui.copy_to_clipboard(entry_data['password']):
                    print("[+] Password automatically copied to clipboard (30 second retention)")
                break

        # Validate entry data
        is_valid, message = validation.validate_entry_data(entry_data)
        if not is_valid:
            print(f"[-] {message}")
            return False

        # Store entry in database
        entry_id = self.db.add_entry(self.master_key, entry_data)
        
        if entry_id:
            print(f"[+] Entry successfully created (ID: {entry_id})")
            crypto.secure_erase(entry_data.get('password', ''))
            return True
        
        return False
    
    def get_entry(self, entry_id=None, show_password=True):
        """
        Retrieve and display a credential entry.
        
        Args:
            entry_id (int, optional): Entry ID to retrieve
            show_password (bool): Whether to display the password
        """
        if not self._check_session():
            return
        
        if entry_id is None:
            entry_id = prompt("Entry ID: ", validator=NumberValidator()).strip()
            if not entry_id.isdigit():
                print("[-] Invalid entry identifier")
                return
        
        entry = self.db.get_entry(self.master_key, int(entry_id))
        
        if entry:
            # Format timestamps for display
            created_at = entry.get('created_at')
            updated_at = entry.get('updated_at')
            
            if created_at and isinstance(created_at, (int, float)):
                try:
                    entry['created_at'] = datetime.fromtimestamp(created_at).strftime("%Y-%m-%d %H:%M:%S")
                except (ValueError, TypeError, OSError):
                    pass
            
            if updated_at and isinstance(updated_at, (int, float)):
                try:
                    entry['updated_at'] = datetime.fromtimestamp(updated_at).strftime("%Y-%m-%d %H:%M:%S")
                except (ValueError, TypeError, OSError):
                    pass
            
            # Display entry and copy password to clipboard
            ui.display_entry(entry, show_password)
            
            if show_password and entry.get('password'):
                if ui.copy_to_clipboard(entry['password']):
                    print("[+] Password automatically copied to clipboard (30 second retention)")
        else:
            print("[-] Entry not found")
    
    def list_entries(self):
        """Display all credential entries, optionally filtered by category."""
        if not self._check_session():
            return
        
        category = prompt("Filter by category (leave empty for all): ").strip()
        
        if category:
            # Use the flexible category matching
            entries = self.db.get_entries_by_category(self.master_key, category)
            if entries:
                # Find the actual category name used in the matched entries
                actual_category = entries[0].get('category', category.title())
                print(f"[+] Entries in Category: '{actual_category}' (matched '{category}')")
            else:
                print(f"[-] No entries found matching category: '{category}'")
                
                # Show suggestions for similar categories
                suggestions = self.db.get_category_suggestions(self.master_key, category)
                if suggestions:
                    print(f"[i] Similar categories found: {', '.join(suggestions[:5])}")
                    if len(suggestions) > 5:
                        print(f"    ... and {len(suggestions) - 5} more")
                return
        else:
            entries = self.db.list_entries(self.master_key)
            print(f"[+] All Entries")
        
        if entries:
            ui.display_entries_table(entries)
            print(f"\n[+] Total entries: {len(entries)}")
            
            # Display category summary with flexible grouping
            if not category:
                categories = {}
                for entry in entries:
                    cat = entry.get('category', 'General')
                    # Normalize category for grouping similar ones
                    normalized_cat = self._normalize_category_name(cat)
                    if normalized_cat not in categories:
                        categories[normalized_cat] = {
                            'count': 0,
                            'display_names': set(),
                            'original_name': cat if cat else 'General'
                        }
                    categories[normalized_cat]['count'] += 1
                    categories[normalized_cat]['display_names'].add(cat.strip() if cat else 'General')
                
                if categories:
                    print("[+] Categories summary:")
                    for normalized_cat in sorted(categories.keys()):
                        cat_info = categories[normalized_cat]
                        # Use the most common original name or the first one
                        display_name = cat_info['original_name']
                        if len(cat_info['display_names']) > 1:
                            display_name = f"{display_name} (and variations)"
                        print(f"  {display_name}: {cat_info['count']}")
        else:
            print("[-] No entries found")
    
    def update_entry(self):
        """
        Update an existing credential entry.
        
        Returns:
            bool: True if entry was successfully updated
        """
        if not self._check_session():
            return False
        
        # Get entry ID to update
        entry_id = prompt("Entry ID to update: ", validator=NumberValidator()).strip()
        if not entry_id.isdigit():
            print("[-] Invalid entry identifier")
            return False
        
        # Retrieve current entry
        current_entry = self.db.get_entry(self.master_key, int(entry_id), formatted=False)
        if not current_entry:
            print("[-] Entry not found")
            return False
        
        print("[i] Leave field blank to preserve current value")
        
        # Collect updated data with current values as defaults
        updated_data = {
            'title': prompt(f"Service name [{current_entry['title']}]: ").strip() or current_entry['title'],
            'username': prompt(f"Username [{current_entry['username']}]: ").strip() or current_entry['username'],
            'url': prompt(f"URL [{current_entry.get('url', '')}]: ").strip() or current_entry.get('url', ''),
            'category': prompt(f"Category [{current_entry.get('category', 'General')}]: ").strip() or current_entry.get('category', 'General')
        }
        
        # Password update logic
        pwd_update = prompt("Update password? [y/N]: ").strip().lower()
        if pwd_update == 'y':
            generate_new = prompt("Generate new password? [y/N]: ").strip().lower()
            if generate_new == 'y':
                # Generate new secure password
                while True:
                    length_input = prompt("Password length [16]: ").strip()
                    length = int(length_input) if length_input.isdigit() else 16
                    
                    if length < 8:
                        print("[-] Minimum password length is 8 characters")
                        continue
                    break
                
                try:
                    new_password = password_generator.generate_secure_password(length)
                    
                    # Check password reuse
                    history = self.db.get_password_history(self.master_key, int(entry_id))
                    if history:
                        current_entry_full = self.db.get_entry(self.master_key, int(entry_id), formatted=False)
                        if current_entry_full and 'password_history' in current_entry_full:
                            for item in current_entry_full['password_history']:
                                if item.get('password') == new_password:
                                    masked_new = self._mask_password_partial(new_password)
                                    print(f"[!] Warning: Password {masked_new} was previously used for this entry!")
                                    reuse = prompt("Use it anyway? [y/N]: ").strip().lower()
                                    if reuse != 'y':
                                        print("[-] Password update cancelled")
                                        return False
                    
                    updated_data['password'] = new_password
                    print(f"[+] New password: {updated_data['password']}")
                    if ui.copy_to_clipboard(updated_data['password']):
                        print("[+] Password automatically copied to clipboard (30 second retention)")
                except password_generator.PasswordGenerationError as e:
                    print(f"[-] {e}")
                    return False
            else:
                # Manual password entry with reuse check
                new_password = prompt(
                    "New password: ",
                    is_password=True
                )
                
                if not new_password:
                    print("[-] Password cannot be empty")
                    return False
                
                current_entry_full = self.db.get_entry(self.master_key, int(entry_id), formatted=False)
                if current_entry_full and 'password_history' in current_entry_full:
                    for item in current_entry_full['password_history']:
                        if item.get('password') == new_password:
                            masked_new = self._mask_password_partial(new_password)
                            print(f"[!] Warning: Password {masked_new} was previously used for this entry!")
                            reuse = prompt("Use it anyway? [y/N]: ").strip().lower()
                            if reuse != 'y':
                                print("[-] Password update cancelled")
                                return False
                
                updated_data['password'] = new_password
                if ui.copy_to_clipboard(updated_data['password']):
                    print("[+] Password automatically copied to clipboard (30 second retention)")
        else:
            updated_data['password'] = current_entry.get('password', '')
        
        # Validate and apply update
        is_valid, message = validation.validate_entry_data(updated_data)
        if not is_valid:
            print(f"[-] {message}")
            return False
        
        if self.db.update_entry(self.master_key, int(entry_id), updated_data):
            print(f"[+] Entry {entry_id} successfully updated")
            crypto.secure_erase(updated_data.get('password', ''))
            crypto.secure_erase(current_entry.get('password', ''))
            return True
        
        return False
    
    # ==========================================================================
    # PASSWORD HISTORY MANAGEMENT
    # ==========================================================================
    
    def password_history(self):
        """Display password change history for a specific entry."""
        if not self._check_session():
            return
        
        entry_id = prompt("Entry ID: ", validator=NumberValidator()).strip()
        if not entry_id.isdigit():
            print("[-] Invalid entry identifier")
            return
        
        entry_id_int = int(entry_id)
        
        entry = self.db.get_entry(self.master_key, entry_id_int)
        if not entry:
            print(f"[-] Entry {entry_id} not found")
            return
        
        print(f"[+] Password History for: {entry.get('title', 'Untitled')}")
        print(f"    Username: {entry.get('username', 'N/A')}")
        print(f"    Current password: {'*' * len(entry.get('password', ''))}")
        print("=" * 60)
        
        history = self.db.get_password_history(self.master_key, entry_id_int)
        
        if not history or len(history) == 0:
            print("[-] No password history found for this entry")
            print("[i] History is automatically saved when passwords are changed")
            return
        
        print(f"Password History ({len(history)} entries):")
        print("-" * 60)
        
        # Display history entries with masked passwords
        for item in history:
            version = item.get('version', '?')
            changed_at = item.get('changed_at_formatted', 'Unknown date')
            masked_password = item.get('masked_password', '****')
            length = item.get('length', 0)
            
            print(f"\nVersion {version}:")
            print(f"  Changed: {changed_at}")
            print(f"  Password: {masked_password}")
            print(f"  Length: {length} characters")
        
        print("\n" + "=" * 60)
        print("[i] Note: Passwords are partially masked for security")
        print("[!] Do not reuse old passwords for security reasons.")
    
    def reveal_version(self):
        """
        Reveal a specific password from history (requires master password).
        
        Returns:
            bool: True if password was successfully revealed
        """
        if not self._check_session():
            return False
        
        entry_id = prompt("Entry ID: ", validator=NumberValidator()).strip()
        if not entry_id.isdigit():
            print("[-] Invalid entry identifier")
            return False
        
        entry_id_int = int(entry_id)
        
        # Retrieve entry details
        entry = self.db.get_entry(self.master_key, entry_id_int)
        if not entry:
            print(f"[-] Entry {entry_id} not found")
            return False
        
        print(f"[i] Entry: {entry.get('title', 'Untitled')}")
        print(f"     Username: {entry.get('username', 'N/A')}")
        
        # Get password history with actual passwords
        history = self.db.get_password_history_with_passwords(self.master_key, entry_id_int)
        if not history or len(history) == 0:
            print("[-] No password history found for this entry")
            return False
        
        # Display available history versions
        print(f"\n[+] Available password history versions ({len(history)}):")
        print("-" * 60)
        
        for i, item in enumerate(history, 1):
            version = item.get('version', i)
            changed_at = item.get('changed_at_formatted', 'Unknown date')
            length = item.get('length', 0)
            is_current = item.get('is_current', False)
            
            status = "[CURRENT]" if is_current else f"Version {version}"
            print(f"  {i:2}. {status} - Changed: {changed_at} - Length: {length} chars")
        
        print("-" * 60)
        
        # Select version to reveal
        version_input = prompt("Enter version number to reveal (or 0 to cancel): ").strip()
        if not version_input.isdigit():
            print("[-] Invalid version number")
            return False
        
        version_num = int(version_input)
        if version_num == 0:
            print("[-] Operation cancelled")
            return False
        
        if version_num < 1 or version_num > len(history):
            print(f"[-] Version must be between 1 and {len(history)}")
            return False
        
        selected_version = history[version_num - 1]
        version_display = selected_version.get('version', version_num)
        
        # Security warning and confirmation
        print(f"\n[!] You are about to reveal password for:")
        print(f"    Entry: {entry.get('title', 'Untitled')}")
        print(f"    Version: {version_display}")
        print(f"    Changed: {selected_version.get('changed_at_formatted', 'Unknown date')}")
        
        master_password = prompt(
            "Enter master password to confirm: ",
            is_password=True
        )
        
        if master_password == "":
            print("[-] Master password incorrect. Viewing cancelled.")
            return False

        # Verify master password
        temp_db = database.VaultDatabase(self.db.db_path)
        temp_db.connect()
        
        try:
            if not temp_db.eyr_file or not temp_db.eyr_file.load():
                print("[-] Vault access error")
                temp_db.close()
                return False
            
            metadata = temp_db.eyr_file.metadata
            if not metadata:
                print("[-] Metadata retrieval failed")
                temp_db.close()
                return False
            
            salt_b64 = metadata.get('salt')
            if not salt_b64:
                print("[-] Cryptographic salt missing")
                temp_db.close()
                return False
            
            salt = base64.b64decode(salt_b64)
            verification_key, _ = crypto.derive_master_key(master_password, salt)
            
            if verification_key != self.master_key:
                print("[-] Master password incorrect. Viewing cancelled.")
                crypto.secure_erase(master_password)
                crypto.secure_erase_key(verification_key)
                temp_db.close()
                return False
            
            temp_db.close()
            
        except Exception as e:
            print(f"[-] Verification error: {e}")
            crypto.secure_erase(master_password)
            if 'temp_db' in locals():
                temp_db.close()
            return False
        
        crypto.secure_erase(master_password)
        crypto.secure_erase_key(verification_key)
        
        # Reveal and display the password
        revealed_password = selected_version.get('password', '')
        if not revealed_password:
            print("[-] Could not retrieve password for this version")
            return False
        
        print("="*60)
        print(f"[+] REVEALED PASSWORD - Version {version_display}")
        print("="*60)
        print(f"Password: {revealed_password}")
        print(f"Length: {len(revealed_password)} characters")
        print("="*60)
        
        # Optional clipboard copy
        copy_choice = prompt("Copy to clipboard? [y/N]: ").strip().lower()
        if copy_choice == 'y':
            if ui.copy_to_clipboard(revealed_password):
                print("[+] Password copied to clipboard (30 second retention)")
            else:
                print("[-] Failed to copy to clipboard")
        
        # Security warning
        print("\n[!] SECURITY WARNING:")
        print("    - This is an old password that should NOT be used")
        print("    - Do not reuse old passwords for security reasons")
        print("    - Consider changing if this password is still in use")
        
        return True
    
    def clear_history(self):
        """
        Clear password history for a specific entry.
        
        Returns:
            bool: True if history was successfully cleared
        """
        if not self._check_session():
            return False
        
        entry_id = prompt("Entry ID: ", validator=NumberValidator()).strip()
        if not entry_id.isdigit():
            print("[-] Invalid entry identifier")
            return False
        
        entry_id_int = int(entry_id)
        
        entry = self.db.get_entry(self.master_key, entry_id_int)
        if not entry:
            print(f"[-] Entry {entry_id} not found")
            return False
        
        print(f"[i] Entry: {entry.get('title', 'Untitled')}")
        print(f"     Username: {entry.get('username', 'N/A')}")
        
        history = self.db.get_password_history(self.master_key, entry_id_int)
        history_count = len(history) if history else 0
        
        print(f"[!] This will clear {history_count} password history entries.")
        
        # Require master password confirmation
        master_password = prompt(
            "Enter master password to confirm: ",
            is_password=True
        )

        if master_password == "":
            print("[-] Master password incorrect. Clearing cancelled.")
            return False
        
        temp_db = database.VaultDatabase(self.db.db_path)
        temp_db.connect()

        if master_password == "":
            print("[-] Master password incorrect. Clearing cancelled.")
            return False
        
        try:
            if not temp_db.eyr_file or not temp_db.eyr_file.load():
                print("[-] Vault access error")
                temp_db.close()
                return False
            
            metadata = temp_db.eyr_file.metadata
            if not metadata:
                print("[-] Metadata retrieval failed")
                temp_db.close()
                return False
            
            salt_b64 = metadata.get('salt')
            if not salt_b64:
                print("[-] Cryptographic salt missing")
                temp_db.close()
                return False
            
            salt = base64.b64decode(salt_b64)
            verification_key, _ = crypto.derive_master_key(master_password, salt)
            
            if verification_key != self.master_key:
                print("[-] Master password incorrect. Clearing cancelled.")
                crypto.secure_erase(master_password)
                crypto.secure_erase_key(verification_key)
                temp_db.close()
                return False
            
            temp_db.close()
            
        except Exception as e:
            print(f"[-] Verification error: {e}")
            crypto.secure_erase(master_password)
            if 'temp_db' in locals():
                temp_db.close()
            return False
        
        crypto.secure_erase(master_password)
        crypto.secure_erase_key(verification_key)
        
        # Final confirmation
        confirmation = prompt(
            f"[!] This action cannot be undone!\n"
            f"Clear password history for entry {entry_id}? [y/N]: "
        ).strip().lower()
        
        if confirmation != 'y':
            print("[-] History clear cancelled")
            return False
        
        if self.db.clear_password_history(self.master_key, entry_id_int):
            print(f"[+] Password history cleared for entry {entry_id}")
            return True
        
        print("[-] Failed to clear password history")
        return False
    
    # ==========================================================================
    # ENTRY DELETION
    # ==========================================================================
    
    def delete_entry(self):
        """
        Permanently delete a credential entry.
        
        Returns:
            bool: True if entry was successfully deleted
        """
        if not self._check_session():
            return False
        
        entry_id = prompt("Entry ID to delete: ", validator=NumberValidator()).strip()
        if not entry_id.isdigit():
            print("[-] Invalid entry identifier")
            return False
        
        entry_id_int = int(entry_id)
        
        entry = self.db.get_entry(self.master_key, entry_id_int)
        if not entry:
            print(f"[-] Entry {entry_id} not found")
            return False
        
        print(f"[i] Entry to delete: {entry.get('title', 'Untitled')}")
        print(f"Username: {entry.get('username', 'N/A')}")
        print(f"Category: {entry.get('category', 'General')}")
        
        # Require master password confirmation
        master_password = prompt(
            "Enter master password to confirm deletion: ",
            is_password=True
        )
        
        if master_password == "":
            print("[-] Master password incorrect. Deletion cancelled.")
            return False

        temp_db = database.VaultDatabase(self.db.db_path)
        temp_db.connect()
        
        try:
            if not temp_db.eyr_file or not temp_db.eyr_file.load():
                print("[-] Vault access error")
                temp_db.close()
                return False
            
            metadata = temp_db.eyr_file.metadata
            if not metadata:
                print("[-] Metadata retrieval failed")
                temp_db.close()
                return False
            
            salt_b64 = metadata.get('salt')
            if not salt_b64:
                print("[-] Cryptographic salt missing")
                temp_db.close()
                return False
            
            salt = base64.b64decode(salt_b64)
            verification_key, _ = crypto.derive_master_key(master_password, salt)
            
            if verification_key != self.master_key:
                print("[-] Master password incorrect. Deletion cancelled.")
                crypto.secure_erase(master_password)
                crypto.secure_erase_key(verification_key)
                temp_db.close()
                return False
            
            temp_db.close()
            
        except Exception as e:
            print(f"[-] Verification error: {e}")
            crypto.secure_erase(master_password)
            if 'temp_db' in locals():
                temp_db.close()
            return False
        
        crypto.secure_erase(master_password)
        if 'verification_key' in locals():
            crypto.secure_erase_key(verification_key)
        
        # Final confirmation
        confirmation = prompt(
            f"[!] This action cannot be undone!\n"
            f"Confirm deletion of entry {entry_id}? [y/N]: "
        ).strip().lower()
        
        if confirmation != 'y':
            print("Deletion cancelled")
            return False
        
        if self.db.delete_entry(entry_id_int):
            print(f"[+] Entry {entry_id} successfully deleted")
            return True
        
        print("[-] Entry deletion failed")
        return False
    
    # ==========================================================================
    # PASSWORD GENERATION
    # ==========================================================================
    
    def generate_password(self):
        """Generate and display a secure random password."""
        while True:
            length_input = prompt("Password length [16]: ").strip()
            length = int(length_input) if length_input.isdigit() else 16
        
            if length < 8:
                print("[-] Minimum password length is 8 characters")
                continue
            break
    
        try:
            password = password_generator.generate_secure_password(length)
        
            # Display password partially masked by default
            # Show first 3 characters and last 3 characters, mask the middle
            if len(password) <= 6:
                # If password is too short, show as fully masked
                masked_display = '*' * length
                print(f"Generated password: {masked_display}")
            else:
                # Show first 3 chars, asterisks for middle, last 3 chars
                first_part = password[:3]
                last_part = password[-3:]
                masked_middle = '*' * (len(password) - 6)
                masked_display = f"{first_part}{masked_middle}{last_part}"
                print(f"Generated password: {masked_display}")
        
            strength_info = password_generator.estimate_password_strength(password)
            print(f"Security assessment: {strength_info['strength']}")
        
            if ui.copy_to_clipboard(password):
                print("[+] Password automatically copied to clipboard (30 second retention)")
        
            # Optional: Ask if user wants to see the full password
            reveal = prompt("Reveal full password? [y/N]: ").strip().lower()
            if reveal == 'y':
                print(f"Full password: {password}")
            
        except password_generator.PasswordGenerationError as e:
            print(f"[-] {e}")
            return
    
    # ==========================================================================
    # VAULT IMPORT/EXPORT
    # ==========================================================================
    
    def export_vault(self, vault_path, backup_path, backup_password, confirm_password=None):
        """
        Create an encrypted backup of the vault.
        
        Args:
            vault_path (str): Source vault path
            backup_path (str): Destination backup path
            backup_password (str): Encryption password for backup
            confirm_password (str, optional): Password confirmation
            
        Returns:
            bool: True if export succeeded
        """
        print(f"Source vault: {vault_path}")
        print(f"Backup file: {backup_path}")
        
        if confirm_password and backup_password != confirm_password:
            print("[-] Backup passwords do not match")
            return False
        
        # Use current session or authenticate separately
        if self.db and self.db.db_path == vault_path and self._check_session():
            export_db = self.db
            export_key = self.master_key
            print("[+] Using authenticated session")
        else:
            print(f"[+] Authenticating vault: {vault_path}")
            export_db, export_key = self._unlock_for_operation(vault_path)
            if not export_db or not export_key:
                print("[-] Vault authentication failed")
                return False
        
        # Perform export operation
        if export_import.export_vault(export_db, backup_password, backup_path):
            print(f"[+] Eyrie vault export completed: {backup_path}")
            print(f"[i] Backup size: {os.path.getsize(backup_path) / 1024:.1f} KB")
            print("[i] Store backup password securely")
            
            if export_db != self.db:
                export_db.close()
            return True
        
        print("[-] Export operation failed")
        if export_db != self.db:
            export_db.close()
        return False
    
    def import_vault(self, backup_path, backup_password, target_vault=None):
        """
        Restore a vault from an encrypted backup.
        
        Args:
            backup_path (str): Backup file path
            backup_password (str): Backup decryption password
            target_vault (str, optional): Destination vault path
            
        Returns:
            bool: True if import succeeded
        """
        print(f"Backup source: {backup_path}")
        
        if not os.path.exists(backup_path):
            print("[-] Backup file not found")
            return False
        
        temp_db_path = "import_temp.eyr"
        import_db = database.VaultDatabase(temp_db_path)
        
        if export_import.import_vault(import_db, backup_password, backup_path):
            print("[+] Backup successfully imported")
            print("[+] Verifying vault integrity...")
            try:
                import_db.connect()
                if not import_db.eyr_file or not import_db.eyr_file.load():
                    print("[-] Imported vault corrupted")
                    os.remove(temp_db_path)
                    return False
                
                metadata = import_db.eyr_file.metadata
                if not metadata or 'salt' not in metadata:
                    print("[-] Invalid vault metadata")
                    os.remove(temp_db_path)
                    return False
                
                print("[+] Vault verification passed")
                
            except Exception as e:
                print(f"[-] Verification error: {e}")
                os.remove(temp_db_path)
                return False
            finally:
                import_db.close()
            
            vault_path = target_vault if target_vault else "vault.eyr"
            
            # Handle existing vault overwrite
            if os.path.exists(vault_path) and not target_vault:
                print(f"[!] Overwrites existing vault: {vault_path}")
                confirmation = prompt("Confirm overwrite? [y/N]: ").strip().lower()
                if confirmation != 'y':
                    os.remove(temp_db_path)
                    print("Import operation cancelled")
                    return False
            
            shutil.copy2(temp_db_path, vault_path)
            os.remove(temp_db_path)
            
            print(f"[+] Eyrie vault imported to: {vault_path}")
            print("[*] Note: Imported vault retains original master credentials")
            return True
        
        else:
            print("[-] Import operation failed")
            print("Potential causes:")
            print("  1. Incorrect backup password")
            print("  2. Backup file corruption")
            print("  3. Version incompatibility")
            
            if os.path.exists(temp_db_path):
                os.remove(temp_db_path)
            return False
    
    # ==========================================================================
    # MASTER PASSWORD MANAGEMENT
    # ==========================================================================
    
    def change_master_password(self):
        """
        Change the master password and re-encrypt all vault data.
        
        Returns:
            bool: True if password change succeeded
        """
        if not self._check_session():
            return False

        # Verify current password
        current_password = prompt(
            "Current master password: ",
            is_password=True
        )
        
        if current_password == "":
            print("[-] Current password incorrect")
            return False

        temp_db = database.VaultDatabase(self.db.db_path)
        temp_db.connect()
        
        try:
            if not temp_db.eyr_file or not temp_db.eyr_file.load():
                print("[-] Vault access error")
                return False
            
            metadata = temp_db.eyr_file.metadata
            if not metadata:
                print("[-] Metadata retrieval failed")
                return False
                
            salt_b64 = metadata.get('salt')
            if not salt_b64:
                print("[-] Cryptographic salt missing")
                return False
                
            salt = base64.b64decode(salt_b64)
            verification_key, _ = crypto.derive_master_key(current_password, salt)
            
        except Exception as e:
            print(f"[-] Key derivation error: {e}")
            return False
        finally:
            temp_db.close()
        
        if not self.db.verify_master_key(verification_key):
            print("[-] Current password incorrect")
            crypto.secure_erase(current_password)
            crypto.secure_erase_key(verification_key)
            return False
        
        # Get and validate new password
        while True:
            new_password = prompt(
                "New master password (minimum 12 characters): ",
                is_password=True
            )
            confirm_password = prompt(
                "Confirm new master password: ",
                is_password=True
            )
            
            if new_password != confirm_password:
                print("[-] Password mismatch")
                continue
            
            is_valid, message = validation.validate_master_password(new_password)
            if not is_valid:
                print(f"[-] Password requirements not met: {message}")
                continue
            break
        
        # Derive new key and re-encrypt vault
        print("[+] Re-encrypting vault data...")
        new_master_key, _ = crypto.derive_master_key(new_password, salt)
        
        if self.db.change_master_key(self.master_key, new_master_key):
            self.master_key = new_master_key
            print("[+] Eyrie master credentials successfully updated")
        else:
            print("[-] Password rotation failed")
        
        # Securely clear sensitive data
        crypto.secure_erase(current_password)
        crypto.secure_erase(new_password)
        crypto.secure_erase_key(verification_key)
        return True
    
    # ==========================================================================
    # VAULT INFORMATION
    # ==========================================================================
    
    def vault_info(self):
        """Display vault statistics and metadata."""
        if not self._check_session():
            return
        
        vault_metadata = self.db.get_vault_info(self.master_key)
        if vault_metadata:
            ui.display_vault_info(vault_metadata)
        else:
            print("[-] Vault information unavailable")
    
    # ==========================================================================
    # UTILITY METHODS
    # ==========================================================================
    
    def _unlock_for_operation(self, vault_path):
        """
        Authenticate a vault for a specific operation (export/import).
        
        Args:
            vault_path (str): Path to vault file
            
        Returns:
            tuple: (database object, master key) or (None, None) if failed
        """
        if not os.path.exists(vault_path):
            print(f"[-] Eyrie vault not found: {vault_path}")
            return None, None
        
        if not validation.check_rate_limit(vault_path):
            print("[-] Authentication rate limit exceeded")
            return None, None
        
        attempts = 0
        max_attempts = 5
        
        while attempts < max_attempts:
            master_password = prompt(
                f"Master password for {vault_path}: ",
                is_password=True
            )
            
            temp_db = database.VaultDatabase(vault_path)
            temp_db.connect()
            
            try:
                if not temp_db.eyr_file or not temp_db.eyr_file.load():
                    print("[-] Invalid vault format")
                    temp_db.close()
                    continue
                
                metadata = temp_db.eyr_file.metadata
                if not metadata:
                    print("[-] Metadata missing")
                    temp_db.close()
                    continue
                    
                salt_b64 = metadata.get('salt')
                if not salt_b64:
                    print("[-] Cryptographic salt missing")
                    temp_db.close()
                    continue
                    
                salt = base64.b64decode(salt_b64)
                verification_key, _ = crypto.derive_master_key(master_password, salt)
                
            except Exception as e:
                print(f"[-] Vault read error: {e}")
                temp_db.close()
                continue
            finally:
                temp_db.close()
            
            operation_db = database.VaultDatabase(vault_path)
            operation_db.connect()
            
            if operation_db.eyr_file and operation_db.eyr_file.load():
                if operation_db.verify_master_key(verification_key):
                    validation.clear_failed_attempts(vault_path)
                    crypto.secure_erase(master_password)
                    print(f"[+] Eyrie vault authenticated for operation")
                    return operation_db, verification_key
            
            attempts += 1
            remaining = max_attempts - attempts
            print(f"[-] Authentication failed. Attempts remaining: {remaining}")
            validation.record_failed_attempt(vault_path)
        
        print("[-] Maximum authentication attempts reached")
        return None, None
    
    def _check_session(self):
        """
        Verify the current session is valid and not expired.
        
        Returns:
            bool: True if session is valid
        """
        if not self.db or not self.master_key:
            print("[-] Eyrie vault authentication required")
            return False
        
        # 8-hour session timeout
        if time.time() - self.session_start > 28800:
            print("[-] Session expired. Re-authentication required.")
            self.db = None
            self.master_key = None
            return False
        
        return True
    
    def _normalize_category_name(self, category: str) -> str:
        """
        Normalize category name for flexible matching.
        
        Args:
            category (str): Original category name
            
        Returns:
            str: Normalized category name
        """
        if not category:
            return ""
        
        import re
        
        # Convert to lowercase
        normalized = category.lower().strip()
        
        # Replace common separators with spaces
        separators = ['-', '_', '.', ',', ';', '/', '\\', '|']
        for sep in separators:
            normalized = normalized.replace(sep, ' ')
        
        # Remove all non-alphanumeric characters except spaces
        normalized = re.sub(r'[^a-z0-9\s]', '', normalized)
        
        # Normalize multiple spaces to single space
        normalized = re.sub(r'\s+', ' ', normalized).strip()
        
        # Sort words alphabetically for consistent matching
        words = normalized.split()
        if len(words) > 1:
            words_sorted = sorted(words)
            normalized = ' '.join(words_sorted)
        
        return normalized
    
    def _mask_password_partial(self, password: str) -> str:
        """
        Partially mask a password for display (shows first 2 and last 2 chars).
        
        Args:
            password (str): Password to mask
            
        Returns:
            str: Partially masked password
        """
        if not password:
            return ""
        
        length = len(password)
        
        if length <= 4:
            return "*" * length
        
        first_part = password[:2]
        last_part = password[-2:] if length > 4 else ""
        masked_middle = "*" * (length - 4) if length > 4 else ""
        
        return f"{first_part}{masked_middle}{last_part}"
    
    def cleanup(self):
        """Securely clean up sensitive data and close connections."""
        if self.master_key:
            crypto.secure_erase_key(self.master_key)
        if self.db:
            self.db.close()

# ==============================================================================
# MAIN ENTRY POINT
# ==============================================================================

def main():
    """Main entry point for the Eyrie Password Manager."""
    # Command-line argument parser setup
    parser = argparse.ArgumentParser(
        description="Eyrie is a comprehensive password management toolkit that allows secure storage, organization, and handling of sensitive credentials. It includes utilities for creating, editing, and displaying entries, validating passwords, emails, and URLs, performing secure backup and restore operations, exporting and importing data, and safely managing clipboard and authentication attempts.",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    subparsers = parser.add_subparsers(
        dest='command', 
        help='Available operations'
    )
    
    # Vault initialization command
    init_parser = subparsers.add_parser(
        'init', 
        help='Initialize new encrypted Eyrie vault'
    )
    init_parser.add_argument(
        '--vault', 
        default='vault.eyr', 
        help='Vault file path (default: vault.eyr)'
    )
    
    # Vault unlock command
    unlock_parser = subparsers.add_parser(
        'unlock', 
        help='Authenticate and unlock Eyrie vault for interactive management'
    )
    unlock_parser.add_argument(
        '--vault', 
        default='vault.eyr', 
        help='Vault file path (default: vault.eyr)'
    )
    
    # Password generation command
    gen_parser = subparsers.add_parser('generate', help='Generate secure password')
    gen_parser.add_argument(
        '--length', 
        type=int, 
        default=16, 
        help='Password length (default: 16)'
    )
    gen_parser.add_argument(
        '--reveal',
        action='store_true',
        help='Show the full generated password (default: partially masked)'
    )
    
    # Vault export command
    export_parser = subparsers.add_parser(
        'export', 
        help='Create encrypted Eyrie vault backup'
    )
    export_parser.add_argument(
        '--vault', 
        default='vault.eyr', 
        help='Source vault file'
    )
    export_parser.add_argument(
        '--backup-path', 
        default='vault_backup.enc', 
        help='Backup destination path'
    )
    export_parser.add_argument(
        '--password', 
        help='Backup encryption password'
    )
    export_parser.add_argument(
        '--confirm-password', 
        help='Backup password confirmation'
    )
    
    # Vault import command
    import_parser = subparsers.add_parser(
        'import', 
        help='Restore Eyrie vault from backup'
    )
    import_parser.add_argument(
        '--backup-path', 
        required=True, 
        help='Backup file path'
    )
    import_parser.add_argument(
        '--password', 
        help='Backup decryption password'
    )
    import_parser.add_argument(
        '--target-vault', 
        default='vault.eyr', 
        help='Destination vault path'
    )
    
    # Master password change command
    change_parser = subparsers.add_parser(
        'change-master', 
        help='Rotate Eyrie master credentials'
    )
    change_parser.add_argument(
        '--vault', 
        default='vault.eyr', 
        help='Vault file path (default: vault.eyr)'
    )
    
    # 2FA management command group
    tfa_parser = subparsers.add_parser('2fa', help='Two-Factor Authentication management')
    tfa_subparsers = tfa_parser.add_subparsers(dest='tfa_command', help='2FA commands')
    
    setup_parser = tfa_subparsers.add_parser('setup', help='Setup 2FA for vault')
    setup_parser.add_argument('--vault', default='vault.eyr', help='Vault file path')
    
    disable_parser = tfa_subparsers.add_parser('disable', help='Disable 2FA for vault')
    disable_parser.add_argument('--vault', default='vault.eyr', help='Vault file path')
    
    status_parser = tfa_subparsers.add_parser('status', help='Show 2FA status')
    status_parser.add_argument('--vault', default='vault.eyr', help='Vault file path')
    
    # Parse command-line arguments
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Initialize Eyrie application
    eyrie = Eyrie()
    
    try:
        # Handle different commands
        if args.command == 'init':
            # Check if vault already exists before initialization
            if os.path.exists(args.vault):
                print(f"[-] Error: Vault file '{args.vault}' already exists!")
                print("[i] Use 'unlock' to access an existing vault")
                print("[i] Use a different path/name to create a new vault")
                return
            eyrie.initialize_vault(args.vault)
        
        elif args.command == 'unlock':
            if eyrie.unlock_vault(args.vault):
                # Interactive command loop
                while True:
                    try:
                        selection = prompt(
                            eyrie._format_prompt(),
                            history=eyrie.history,
                            auto_suggest=eyrie.auto_suggest,
                            key_bindings=eyrie.bindings
                        ).strip()
                        
                        if selection == "":
                            continue
                        
                        resolved_command = eyrie._resolve_command(selection)
                        
                        if not resolved_command:
                            continue
                        
                        # Command routing
                        if resolved_command == 'help':
                            print(MAIN_MENU_INTERACTIVE)
                        elif resolved_command == 'add_entry':
                            eyrie.add_entry()
                        elif resolved_command == 'list_entry':
                            eyrie.list_entries()
                        elif resolved_command == 'get_entry':
                            eyrie.get_entry()
                        elif resolved_command == 'update_entry':
                            eyrie.update_entry()
                        elif resolved_command == 'delete_entry':
                            eyrie.delete_entry()
                        elif resolved_command == 'password_history':
                            eyrie.password_history()
                        elif resolved_command == 'reveal_version':
                            eyrie.reveal_version()
                        elif resolved_command == 'clear_history':
                            eyrie.clear_history()
                        elif resolved_command == 'gen_passwd':
                            eyrie.generate_password()
                        elif resolved_command == 'ch_master_passwd':
                            eyrie.change_master_password()
                        elif resolved_command == 'vault_info':
                            eyrie.vault_info()
                        elif resolved_command == 'setup_2fa':
                            eyrie.setup_2fa()
                        elif resolved_command == 'disable_2fa':
                            eyrie.disable_2fa()
                        elif resolved_command == 'show_2fa':
                            eyrie.show_2fa_status()
                        elif resolved_command == 'export_vault':
                            backup_path = prompt("Backup destination: ").strip()
                            if backup_path:
                                backup_password = prompt(
                                    "Backup password: ",
                                    is_password=True
                                )
                                confirm_password = prompt(
                                    "Confirm backup password: ",
                                    is_password=True
                                )
                                eyrie.export_vault(
                                    args.vault, 
                                    backup_path, 
                                    backup_password, 
                                    confirm_password
                                )
                        elif resolved_command == 'exit':
                            print("[+] Eyrie vault secured")
                            break
                        else:
                            print(f"[-] Command not implemented: {resolved_command}")
                    
                    except KeyboardInterrupt:
                        print("\n[i] Press Ctrl+D to exit or type 'exit'")
                    except EOFError:
                        print("[+] Eyrie vault secured")
                        break
        
        elif args.command == 'generate':
            if args.length:
                success, result = password_generator.generate_password_safe(args.length)
                
                if not success:
                    print(f"[-] {result}")
                    return
                
                password = result
                
                # Display password partially masked by default, or full if --reveal flag is used
                if args.reveal:
                    # Show full password if --reveal flag is used
                    print(f"Generated password: {password}")
                else:
                    # Show partially masked by default
                    if len(password) <= 6:
                        # If password is too short, show as fully masked
                        masked_display = '*' * len(password)
                    else:
                        # Show first 3 chars, asterisks for middle, last 3 chars
                        first_part = password[:3]
                        last_part = password[-3:]
                        masked_middle = '*' * (len(password) - 6)
                        masked_display = f"{first_part}{masked_middle}{last_part}"
                    print(f"Generated password: {masked_display}")
                
                strength_analysis = password_generator.estimate_password_strength(password)
                print(f"Security rating: {strength_analysis['strength']}")
                
                if ui.copy_to_clipboard(password):
                    print("[+] Password automatically copied to clipboard (30 second retention)")
            else:
                eyrie.generate_password()
        
        elif args.command == 'export':
            vault_path = args.vault
            backup_path = args.backup_path
            
            if not os.path.exists(vault_path):
                print(f"[-] Eyrie vault not found: {vault_path}")
                return
            
            if args.password:
                backup_password = args.password
                confirm_password = args.confirm_password
            else:
                print(f"[i] Vault Path: {vault_path}")
                backup_password = prompt(
                    "Backup password: ",
                    is_password=True
                )
                confirm_password = prompt(
                    "Confirm backup password: ",
                    is_password=True
                )
            
            operation_result = eyrie.export_vault(
                vault_path, 
                backup_path, 
                backup_password, 
                confirm_password
            )

            if args.password:
                crypto.secure_erase(backup_password)
                if args.confirm_password:
                    crypto.secure_erase(confirm_password)
        
        elif args.command == 'import':
            backup_path = args.backup_path
            
            if not os.path.exists(backup_path):
                print(f"[-] Backup file not found: {backup_path}")
                return
            
            if args.password:
                backup_password = args.password
            else:
                backup_password = prompt(
                    "Backup password: ",
                    is_password=True
                )
            
            operation_result = eyrie.import_vault(
                backup_path, 
                backup_password, 
                args.target_vault
            )
            
            if args.password:
                crypto.secure_erase(backup_password)
        
        elif args.command == 'change-master':
            if eyrie.unlock_vault(args.vault):
                eyrie.change_master_password()
        
        elif args.command == '2fa':
            if args.tfa_command == 'setup':
                if eyrie.unlock_vault(args.vault):
                    eyrie.setup_2fa()
            elif args.tfa_command == 'disable':
                if eyrie.unlock_vault(args.vault):
                    eyrie.disable_2fa()
            elif args.tfa_command == 'status':
                if eyrie.unlock_vault(args.vault):
                    eyrie.show_2fa_status()
            else:
                tfa_parser.print_help()
        
        else:
            parser.print_help()
    
    except KeyboardInterrupt:
        print("\n[-] Operation terminated and Vault locked.")
    except Exception as e:
        print(f"\n[-] System error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        eyrie.cleanup()

if __name__ == "__main__":
    main()