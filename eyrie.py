#!/usr/bin/env python3
"""
Eyrie Password Manager v1.1.0
A secure, terminal-based password management system with encryption,
and comprehensive credential management.

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
from modules import crypto, database, password_generator, ui, validation, export_import, notes

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
        _\///////////////___\////________\///__________\///____\//////////__ v1.1.0
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
'add_note' (an) - Create new secure note (prompts for title, category, content)
'list_notes' (ln) - Display all stored notes with IDs and titles
'get_note' (gn) - Retrieve specific note details by ID (shows content)
'update_note' (un) - Update specific note details by ID
'search_notes' (sn) - Search notes by title, content, or category
'delete_note' (dn) - Remove note permanently (requires confirmation)
'password_history' (ph) - View password history for an entry (shows masked passwords)
'reveal_version' (rv) - Reveal plaintext password of specific history version (requires master password)
'clear_history' (ch) - Clear password history for an entry (requires confirmation)
'gen_passwd' (gp) - Generate secure random password (configurable length)
'ch_master_passwd' (cmp)- Change master vault password (re-encrypts all entries)
'vault_info' (vi) - View vault statistics and metadata
'export_vault' (ev) - Create encrypted backup of entire vault
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
    'add_note': 'add_note',
    'list_notes': 'list_notes',
    'get_note': 'get_note',
    'update_note': 'update_note',
    'search_notes': 'search_notes',
    'delete_note': 'delete_note',
    'password_history': 'password_history',
    'reveal_version': 'reveal_version',
    'clear_history': 'clear_history',
    'gen_passwd': 'gen_passwd',
    'ch_master_passwd': 'ch_master_passwd',
    'vault_info': 'vault_info',
    'export_vault': 'export_vault',
    'help': 'help',
    'exit': 'exit',
    'quit': 'exit',
    
    # Abbreviations
    'ae': 'add_entry',
    'le': 'list_entry',
    'ge': 'get_entry',
    'ue': 'update_entry',
    'de': 'delete_entry',
    'an': 'add_note',
    'ln': 'list_notes',
    'gn': 'get_note',
    'un': 'update_note',
    'sn': 'search_notes',
    'dn': 'delete_note',
    'ph': 'password_history',
    'rv': 'reveal_version',
    'ch': 'clear_history',
    'gp': 'gen_passwd',
    'cmp': 'ch_master_passwd',
    'vi': 'vault_info',
    'ev': 'export_vault',
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

class EYRIDValidator(Validator):
    """Validator for EYR ID fields (format: EYR-XXXXXX where X is uppercase letter or digit)."""
    
    def validate(self, document):
        """Ensure input matches EYR ID format: EYR- followed by 6 uppercase letters/digits."""
        text = document.text.strip()
        
        if not text:
            return  # Allow empty input for optional fields
        
        # Check if it matches the pattern: EYR-XXXXXX
        pattern = r'^EYR-[A-Z0-9]{6}$'
        if not re.match(pattern, text):
            raise ValidationError(
                message='Please enter a valid EYR ID (format: EYR-XXXXXX where X is uppercase letter or digit)'
            )

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
    """
    
    def __init__(self):
        """Initialize a new Eyrie session with default settings."""
        self.db = None              # Database connection object
        self.master_key = None      # Current session encryption key
        self.session_start = None   # Session timestamp for timeout tracking
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
    
    def unlock_vault(self, vault_path="vault.eyr", master_password=None):
        """
        Authenticate and unlock an existing vault.
        
        Args:
            vault_path (str): Path to the vault file
            master_password (str, optional): Master password (if provided, no prompt)
            
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
            if master_password is None:
                master_pwd = prompt(
                    "Master password: ",
                    is_password=True
                )
            else:
                master_pwd = master_password
                attempts = max_attempts  # Only one attempt when password is provided
            
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
                    # Authentication successful
                    self.master_key = test_key
                    self.session_start = time.time()
                    validation.clear_failed_attempts(vault_path)
                    crypto.secure_erase(master_pwd)
                    if master_password is None:
                        clear()  # Clear screen for security
                        print(BANNER)
                    print("[+] Eyrie vault successfully unlocked")
                    return True
            
            # Authentication failed
            attempts += 1
            if master_password is None:
                remaining = max_attempts - attempts
                print(f"[-] Authentication failed. Attempts remaining: {remaining}")
                validation.record_failed_attempt(vault_path)
        
        print("[-] Maximum authentication attempts reached")
        return False
    
    # ==========================================================================
    # CREDENTIAL MANAGEMENT - INTERACTIVE
    # ==========================================================================
    
    def add_entry(self, title=None, username=None, password=None, url=None, category=None, generate_password=False, password_length=16):
        """
        Add a new credential entry to the vault.
        
        Args:
            title (str, optional): Service/application name
            username (str, optional): Username/email
            password (str, optional): Password (if not provided, will prompt or generate)
            url (str, optional): URL
            category (str, optional): Category (default: "General")
            generate_password (bool): Whether to generate password
            password_length (int): Length for generated password
            
        Returns:
            bool: True if entry was successfully added
        """
        if not self._check_session():
            return False
        
        entry_data = {}
        
        # Interactive mode - collect data from user
        if title is None and username is None and password is None and url is None and category is None:
            # Fully interactive mode - prompt for everything
            while True:
                title = prompt("Service/Application: ").strip()
                if not title:
                    print("[-] Title required")
                    continue
                break
            entry_data['title'] = title
            
            while True:
                username = prompt("Username/Email: ").strip()
                if not username:
                    print("[-] Username required")
                    continue
                break
            entry_data['username'] = username
            
            url = prompt("URL (optional): ").strip()
            if url:
                entry_data['url'] = url
            
            category = prompt("Category [General]: ").strip() or "General"
            entry_data['category'] = category
            
            # Password handling
            if not generate_password:
                # Interactive password selection
                print("Password generation options:")
                print("  1. Manual password entry")
                print("  2. Generate secure password")
                choice = prompt("Selection [1/2]: ").strip()
                
                if choice == "2":
                    generate_password = True
            
            if generate_password:
                # Generate secure password
                if password_length is None:
                    while True:
                        length_input = prompt("Password length [16]: ").strip()
                        length = int(length_input) if length_input.isdigit() else 16
                        
                        if length < 8:
                            print("[-] Minimum password length is 8 characters")
                            continue
                        password_length = length
                        break
                
                try:
                    password = password_generator.generate_secure_password(password_length)
                    entry_data['password'] = password
                    
                    # Display password partially masked by default
                    masked_display = self._mask_password_partial(password)
                    print(f"[+] Generated password: {masked_display}")
                    
                    if ui.copy_to_clipboard(password):
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
                    print("[+] Password entered and saved securely")
                    if ui.copy_to_clipboard(password):
                        print("[+] Password automatically copied to clipboard (30 second retention)")
                    break
        else:
            # Parameter mode - only set what's provided
            if title is not None:
                entry_data['title'] = title
            if username is not None:
                entry_data['username'] = username
            if password is not None:
                entry_data['password'] = password
            if url is not None:
                entry_data['url'] = url
            if category is not None:
                entry_data['category'] = category
            
            # Handle missing required fields
            if 'title' not in entry_data:
                print("[-] Title is required")
                return False
            if 'username' not in entry_data:
                print("[-] Username is required")
                return False
            if 'password' not in entry_data:
                # Handle password if not provided but generate_password is True
                if generate_password:
                    try:
                        password = password_generator.generate_secure_password(password_length)
                        entry_data['password'] = password
                        
                        masked_display = self._mask_password_partial(password)
                        print(f"[+] Generated password: {masked_display}")
                        
                        if ui.copy_to_clipboard(password):
                            print("[+] Password automatically copied to clipboard (30 second retention)")
                    except password_generator.PasswordGenerationError as e:
                        print(f"[-] {e}")
                        return False
                else:
                    print("[-] Password is required")
                    return False
        
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
            entry_id (str, optional): Entry ID to retrieve
            show_password (bool): Whether to display the password
        """
        if not self._check_session():
            return
        
        if entry_id is None:
            entry_id = prompt("Entry ID: ", validator=EYRIDValidator()).strip()
        
        entry = self.db.get_entry(self.master_key, entry_id)
        
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
    
    def list_entries(self, category=None):
        """
        Display all credential entries, optionally filtered by category.
        
        Args:
            category (str, optional): Category to filter by
        """
        if not self._check_session():
            return
        
        # Handle 'all' category
        if category and category.lower() == 'all':
            category = None
        
        # Handle 'all' category from prompt
        if category and category.lower() == 'all':
            category = None
        
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
    
    def update_entry(self, entry_id=None, title=None, username=None, password=None, url=None, category=None, generate_password=False, password_length=16):
        """
        Update an existing credential entry.
        
        Args:
            entry_id (str, optional): Entry ID to update
            title (str, optional): New service/application name
            username (str, optional): New username/email
            password (str, optional): New password (empty to keep current)
            url (str, optional): New URL
            category (str, optional): New category
            generate_password (bool): Whether to generate new password
            password_length (int): Length for generated password
            
        Returns:
            bool: True if entry was successfully updated
        """
        if not self._check_session():
            return False
        
        # Get entry ID to update
        if entry_id is None:
            entry_id = prompt("Entry ID to update: ", validator=EYRIDValidator()).strip()
        
        if not entry_id:
            print("[-] Entry ID required")
            return False
        
        # Retrieve current entry
        current_entry = self.db.get_entry(self.master_key, entry_id, formatted=False)
        if not current_entry:
            print("[-] Entry not found")
            return False
        
        updated_data = {}
        
        # Interactive mode
        if title is None and username is None and password is None and url is None and category is None:
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
                    if password_length is None:
                        while True:
                            length_input = prompt("Password length [16]: ").strip()
                            length = int(length_input) if length_input.isdigit() else 16
                            
                            if length < 8:
                                print("[-] Minimum password length is 8 characters")
                                continue
                            password_length = length
                            break
                    
                    try:
                        new_password = password_generator.generate_secure_password(password_length)
                        
                        # Check password reuse
                        history = self.db.get_password_history(self.master_key, entry_id)
                        if history:
                            current_entry_full = self.db.get_entry(self.master_key, entry_id, formatted=False)
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
                        masked_display = self._mask_password_partial(new_password)
                        print(f"[+] New password: {masked_display}")
                        if ui.copy_to_clipboard(new_password):
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
                    
                    current_entry_full = self.db.get_entry(self.master_key, entry_id, formatted=False)
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
                    if ui.copy_to_clipboard(new_password):
                        print("[+] Password automatically copied to clipboard (30 second retention)")
            else:
                updated_data['password'] = current_entry.get('password', '')
        else:
            # Parameter mode - only update provided fields
            updated_data = {
                'title': title if title is not None else current_entry['title'],
                'username': username if username is not None else current_entry['username'],
                'url': url if url is not None else current_entry.get('url', ''),
                'category': category if category is not None else current_entry.get('category', 'General')
            }
            
            # Handle password update
            if password is not None:
                updated_data['password'] = password
            elif generate_password:
                try:
                    if password_length is None:
                        password_length = 16
                    new_password = password_generator.generate_secure_password(password_length)
                    updated_data['password'] = new_password
                except password_generator.PasswordGenerationError as e:
                    print(f"[-] {e}")
                    return False
            else:
                updated_data['password'] = current_entry.get('password', '')
        
        # Validate and apply update
        is_valid, message = validation.validate_entry_data(updated_data)
        if not is_valid:
            print(f"[-] {message}")
            return False
        
        if self.db.update_entry(self.master_key, entry_id, updated_data):
            print(f"[+] Entry {entry_id} successfully updated")
            crypto.secure_erase(updated_data.get('password', ''))
            crypto.secure_erase(current_entry.get('password', ''))
            return True
        
        return False

    # ==========================================================================
    # SECURE NOTES MANAGEMENT - INTERACTIVE
    # ==========================================================================

    def add_note(self, title=None, category=None, content=None):
        """
        Add a new secure note to the vault.

        Args:
            title (str, optional): Note title
            category (str, optional): Note category
            content (str, optional): Note content
            
        Returns:
            bool: True if note was successfully added
        """
        if not self._check_session():
            return False
    
        try:
            if title is None and category is None and content is None:
                # Use the notes module to create note from interactive input
                note_data = notes.create_note_from_input()
                if not note_data:
                    print("[-] Note creation cancelled")
                    return False
            else:
                # Parameter mode
                if title is None:
                    title = prompt("Note title: ").strip()
                    if not title:
                        print("[-] Title required")
                        return False
                
                if category is None:
                    category = prompt("Category [Notes]: ").strip() or "Notes"
                
                if content is None:
                    content = prompt("Note content (multi-line, end with Ctrl+D): ", multiline=True).strip()
                    if not content:
                        print("[-] Content required")
                        return False
                
                note_data = {
                    'title': title,
                    'category': category,
                    'content': content
                }
        
            # Store note in database
            entry_id = self.db.add_note(self.master_key, note_data)
        
            if entry_id:
                print(f"[+] Note successfully created (ID: {entry_id})")
                return True
        
            return False
        
        except Exception as e:
            print(f"[-] Error adding note: {e}")
            return False

    def list_notes(self, category=None):
        """
        Display all notes, optionally filtered by category.
        
        Args:
            category (str, optional): Category to filter by
        """
        if not self._check_session():
            return
    
        # Handle 'all' category
        if category and category.lower() == 'all':
            category = None
    
        # Handle 'all' category from prompt
        if category and category.lower() == 'all':
            category = None
    
        if category:
            # Use the flexible category matching
            notes_list = self.db.get_notes_by_category(self.master_key, category)
            if notes_list:
                # Find the actual category name used in the matched notes
                actual_category = notes_list[0].get('category', category.title())
                print(f"[+] Notes in Category: '{actual_category}' (matched '{category}')")
            else:
                print(f"[-] No notes found matching category: '{category}'")
            
                # Show suggestions for similar categories
                suggestions = self.db.get_category_suggestions(self.master_key, category)
                if suggestions:
                    print(f"[i] Similar categories found: {', '.join(suggestions[:5])}")
                    if len(suggestions) > 5:
                        print(f"    ... and {len(suggestions) - 5} more")
                return
        else:
            notes_list = self.db.list_notes(self.master_key)
            print(f"[+] All Notes")
    
        if notes_list:
            notes.display_notes_table(notes_list)
        else:
            print("[-] No notes found")

    def get_note(self, entry_id=None):
        """
        Retrieve and display a secure note.
    
        Args:
            entry_id (str, optional): Entry ID to retrieve
        """
        if not self._check_session():
            return
    
        if entry_id is None:
            entry_id = prompt("Note ID: ", validator=EYRIDValidator()).strip()
            if not entry_id:
                print("[-] Note ID required")
                return
    
        note = self.db.get_note(self.master_key, entry_id)
    
        if note:
            # Format timestamps for display
            created_at = note.get('created_at')
            updated_at = note.get('updated_at')
        
            if created_at and isinstance(created_at, (int, float)):
                try:
                    note['created_at'] = datetime.fromtimestamp(created_at).strftime("%Y-%m-%d %H:%M:%S")
                except (ValueError, TypeError, OSError):
                    pass
        
            if updated_at and isinstance(updated_at, (int, float)):
                try:
                    note['updated_at'] = datetime.fromtimestamp(updated_at).strftime("%Y-%m-%d %H:%M:%S")
                except (ValueError, TypeError, OSError):
                    pass
        
            # Display note and offer to copy content
            notes.display_note_entry(note, show_content=True)
        else:
            print("[-] Note not found or invalid note ID")

    def search_notes(self, search_term=None):
        """
        Search notes by title, content, or category.
        
        Args:
            search_term (str, optional): Search term
        """
        if not self._check_session():
            return
    
        if search_term is None:
            search_term = prompt("Search term: ").strip()
        
        if not search_term:
            print("[-] Search term required")
            return
    
        results = self.db.search_notes(self.master_key, search_term)
    
        if results:
            print(f"[+] Found {len(results)} note(s) matching '{search_term}':")
            print("-" * 60)
        
            for i, note in enumerate(results, 1):
                title = note.get('title', 'Untitled')
                category = note.get('category', 'Notes')
                created = note.get('created_at', '')
            
                print(f"{i:2}. ID: {note.get('id', 'N/A')}")
                print(f"    Title: {title}")
                print(f"    Category: {category}")
                print(f"    Created: {created}")
                print()
        
            # Option to view a specific note
            view_choice = prompt("Enter number to view note, or press Enter to continue: ").strip()
            if view_choice.isdigit():
                idx = int(view_choice) - 1
                if 0 <= idx < len(results):
                    note_id = results[idx].get('id')
                    if note_id:
                        self.get_note(note_id)
        else:
            print(f"[-] No notes found matching '{search_term}'")

    def update_note(self, entry_id=None, title=None, category=None, content=None):
        """
        Update an existing secure note.
    
        Args:
            entry_id (str, optional): Note ID to update
            title (str, optional): New title
            category (str, optional): New category
            content (str, optional): New content
            
        Returns:
            bool: True if note was successfully updated
        """
        if not self._check_session():
            return False
    
        # Get note ID to update
        if entry_id is None:
            entry_id = prompt("Note ID to update: ", validator=EYRIDValidator()).strip()
        
        if not entry_id:
            print("[-] Note ID required")
            return False
    
        # Retrieve current note
        current_note = self.db.get_note(self.master_key, entry_id, formatted=False)
        if not current_note:
            print("[-] Note not found")
            return False
    
        updated_data = {}
        
        # Interactive mode
        if title is None and category is None and content is None:
            print("[i] Leave field blank to preserve current value")
            print("[i] Type 'SAME' to keep current content")
        
            # Collect updated data with current values as defaults
            updated_data = {
                'title': prompt(f"Note title [{current_note['title']}]: ").strip() or current_note['title'],
                'category': prompt(f"Category [{current_note.get('category', 'Notes')}]: ").strip() or current_note.get('category', 'Notes')
            }
        
            # Content update
            content_update = prompt("Update content? [y/N]: ").strip().lower()
            if content_update == 'y':
                # Use the notes module to edit content
                current_content = current_note.get('content', '')
                new_content = notes.edit_note_content(current_content)
                if new_content is None:
                    print("[-] Content update cancelled")
                    return False
                updated_data['content'] = new_content
            else:
                updated_data['content'] = current_note.get('content', '')
        else:
            # Parameter mode - only update provided fields
            updated_data = {
                'title': title if title is not None else current_note['title'],
                'category': category if category is not None else current_note.get('category', 'Notes'),
                'content': content if content is not None else current_note.get('content', '')
            }
    
        # Validate and apply update
        if not updated_data.get('title'):
            print("[-] Title cannot be empty")
            return False
    
        if not updated_data.get('content'):
            print("[-] Content cannot be empty")
            return False
    
        # Check content size
        content_size = len(updated_data['content'].encode('utf-8'))
        max_size = 10 * 1024  # 10KB
        if content_size > max_size:
            print(f"[-] Note content exceeds {max_size/1024:.0f}KB limit")
            return False
    
        if self.db.update_note(self.master_key, entry_id, updated_data):
            print(f"[+] Note {entry_id} successfully updated")
            return True
    
        return False

    def delete_note(self, entry_id=None):
        """
        Permanently delete a secure note.
    
        Args:
            entry_id (str, optional): Note ID to delete
            
        Returns:
            bool: True if note was successfully deleted
        """
        if not self._check_session():
            return False
    
        if entry_id is None:
            entry_id = prompt("Note ID to delete: ", validator=EYRIDValidator()).strip()
        
        if not entry_id:
            print("[-] Note ID required")
            return False
    
        note = self.db.get_note(self.master_key, entry_id)
        if not note:
            print(f"[-] Note {entry_id} not found")
            return False
    
        print(f"[i] Note to delete: {note.get('title', 'Untitled')}")
        print(f"Category: {note.get('category', 'Notes')}")
    
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
            f"Confirm deletion of note {entry_id}? [y/N]: "
        ).strip().lower()
    
        if confirmation != 'y':
            print("Deletion cancelled")
            return False
    
        if self.db.delete_note(entry_id):
            print(f"[+] Note {entry_id} successfully deleted")
            return True
    
        print("[-] Note deletion failed")
        return False
    
    # ==========================================================================
    # PASSWORD HISTORY MANAGEMENT
    # ==========================================================================
    
    def password_history(self, entry_id=None):
        """
        Display password change history for a specific entry.
        
        Args:
            entry_id (str, optional): Entry ID
        """
        if not self._check_session():
            return
        
        if entry_id is None:
            entry_id = prompt("Entry ID: ", validator=EYRIDValidator()).strip()
        
        if not entry_id:
            print("[-] Entry ID required")
            return
        
        entry = self.db.get_entry(self.master_key, entry_id)
        if not entry:
            print(f"[-] Entry {entry_id} not found")
            return
        
        print(f"[+] Password History for: {entry.get('title', 'Untitled')}")
        print(f"    Username: {entry.get('username', 'N/A')}")
        print(f"    Current password: {'*' * len(entry.get('password', ''))}")
        print("=" * 60)
        
        history = self.db.get_password_history(self.master_key, entry_id)
        
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
    
    def reveal_version(self, entry_id=None, version=None):
        """
        Reveal a specific password from history (requires master password).
        
        Args:
            entry_id (str, optional): Entry ID
            version (int, optional): Version number
            
        Returns:
            bool: True if password was successfully revealed
        """
        if not self._check_session():
            return False
        
        if entry_id is None:
            entry_id = prompt("Entry ID: ", validator=EYRIDValidator()).strip()
        
        if not entry_id:
            print("[-] Entry ID required")
            return False
        
        # Retrieve entry details
        entry = self.db.get_entry(self.master_key, entry_id)
        if not entry:
            print(f"[-] Entry {entry_id} not found")
            return False
        
        print(f"[i] Entry: {entry.get('title', 'Untitled')}")
        print(f"     Username: {entry.get('username', 'N/A')}")
        
        # Get password history with actual passwords
        history = self.db.get_password_history_with_passwords(self.master_key, entry_id)
        if not history or len(history) == 0:
            print("[-] No password history found for this entry")
            return False
        
        # Display available history versions
        print(f"\n[+] Available password history versions ({len(history)}):")
        print("-" * 60)
        
        for i, item in enumerate(history, 1):
            version_num = item.get('version', i)
            changed_at = item.get('changed_at_formatted', 'Unknown date')
            length = item.get('length', 0)
            is_current = item.get('is_current', False)
            
            status = "[CURRENT]" if is_current else f"Version {version_num}"
            print(f"  {i:2}. {status} - Changed: {changed_at} - Length: {length} chars")
        
        print("-" * 60)
        
        # Select version to reveal
        if version is None:
            version_input = prompt("Enter version number to reveal (or 0 to cancel): ").strip()
            if not version_input.isdigit():
                print("[-] Invalid version number")
                return False
            
            version_num = int(version_input)
        else:
            version_num = version
        
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
    
    def clear_history(self, entry_id=None):
        """
        Clear password history for a specific entry.
        
        Args:
            entry_id (str, optional): Entry ID
            
        Returns:
            bool: True if history was successfully cleared
        """
        if not self._check_session():
            return False
        
        if entry_id is None:
            entry_id = prompt("Entry ID: ", validator=EYRIDValidator()).strip()
        
        if not entry_id:
            print("[-] Entry ID required")
            return False
        
        entry = self.db.get_entry(self.master_key, entry_id)
        if not entry:
            print(f"[-] Entry {entry_id} not found")
            return False
        
        print(f"[i] Entry: {entry.get('title', 'Untitled')}")
        print(f"     Username: {entry.get('username', 'N/A')}")
        
        history = self.db.get_password_history(self.master_key, entry_id)
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
        
        if self.db.clear_password_history(self.master_key, entry_id):
            print(f"[+] Password history cleared for entry {entry_id}")
            return True
        
        print("[-] Failed to clear password history")
        return False
    
    # ==========================================================================
    # ENTRY DELETION
    # ==========================================================================
    
    def delete_entry(self, entry_id=None):
        """
        Permanently delete a credential entry.
        
        Args:
            entry_id (str, optional): Entry ID to delete
            
        Returns:
            bool: True if entry was successfully deleted
        """
        if not self._check_session():
            return False
        
        if entry_id is None:
            entry_id = prompt("Entry ID to delete: ", validator=EYRIDValidator()).strip()
        
        if not entry_id:
            print("[-] Entry ID required")
            return False
        
        entry = self.db.get_entry(self.master_key, entry_id)
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
        
        if self.db.delete_entry(entry_id):
            print(f"[+] Entry {entry_id} successfully deleted")
            return True
        
        print("[-] Entry deletion failed")
        return False
    
    # ==========================================================================
    # PASSWORD GENERATION
    # ==========================================================================
    
    def generate_password(self, length=None, reveal=False):
        """
        Generate and display a secure random password.
        
        Args:
            length (int, optional): Password length
            reveal (bool): Whether to show full password
        """
        if length is None:
            while True:
                length_input = prompt("Password length [16]: ").strip()
                length = int(length_input) if length_input.isdigit() else 16
            
                if length < 8:
                    print("[-] Minimum password length is 8 characters")
                    continue
                break
    
        try:
            password = password_generator.generate_secure_password(length)
        
            # Display password partially masked by default, or full if reveal is True
            if reveal:
                # Show full password if reveal flag is True
                print(f"Generated password: {password}")
            else:
                # Show partially masked by default
                if len(password) <= 6:
                    # If password is too short, show as fully masked
                    masked_display = '*' * length
                    print(f"Generated password: {masked_display}")
                else:
                    # Show first 3 chars, asterisks for middle, last 3 chars
                    first_part = password[:3]
                    last_part = password[-3:]
                    masked_middle = '*' * (len(password) - 6) if len(password) > 6 else ""
                    masked_display = f"{first_part}{masked_middle}{last_part}"
                    print(f"Generated password: {masked_display}")
        
            strength_info = password_generator.estimate_password_strength(password)
            print(f"Security assessment: {strength_info['strength']}")
        
            if ui.copy_to_clipboard(password):
                print("[+] Password automatically copied to clipboard (30 second retention)")
            
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
        description="Eyrie is a comprehensive password management toolkit that allows secure storage, organization, and handling of sensitive credentials.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 eyrie.py init --vault myvault.eyr
  python3 eyrie.py unlock --vault vault.eyr
  python3 eyrie.py add-entry --help
  python3 eyrie.py export --vault vault.eyr --backup-path backup.enc
        """
    )
    subparsers = parser.add_subparsers(
        dest='command', 
        help='Available operations',
        metavar='COMMAND'
    )
    
    # Vault initialization command
    init_parser = subparsers.add_parser(
        'init', 
        help='Initialize new encrypted Eyrie vault',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="""
Initialize a new encrypted Eyrie vault.
This command creates a new vault file and sets up the master password.
        """,
        epilog="""
Example:
  python3 eyrie.py init --vault myvault.eyr
        """
    )
    init_parser.add_argument(
        '--vault', 
        default='vault.eyr', 
        help='Vault file path (default: vault.eyr)'
    )
    
    # Vault unlock command
    unlock_parser = subparsers.add_parser(
        'unlock', 
        help='Authenticate and unlock Eyrie vault for interactive management',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="""
Authenticate and unlock an existing Eyrie vault.
This command starts an interactive session for managing your vault.
        """,
        epilog="""
Examples:
  python3 eyrie.py unlock --vault vault.eyr
  python3 eyrie.py unlock --vault myvault.eyr --password your_master_password
        """
    )
    unlock_parser.add_argument(
        '--vault', 
        default='vault.eyr', 
        help='Vault file path (default: vault.eyr)'
    )
    unlock_parser.add_argument(
        '--password',
        help='Master password (if provided, no interactive prompt)'
    )
    
    # Add entry command
    add_entry_parser = subparsers.add_parser(
        'add-entry',
        help='Add new credential entry',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="""
Add a new credential entry to the vault.
This command allows you to store passwords for services, applications, or websites.
        """,
        epilog="""
Examples:
  python3 eyrie.py add-entry --vault vault.eyr --password masterpass --title "GitHub" --username user@example.com --category "Development"
  python3 eyrie.py add-entry --vault vault.eyr --password masterpass --title "Gmail" --username user@gmail.com --generate --length 20
        """
    )
    add_entry_parser.add_argument(
        '--vault',
        default='vault.eyr',
        help='Vault file path (default: vault.eyr)'
    )
    add_entry_parser.add_argument(
        '--password',
        required=True,
        help='Master password (required)'
    )
    add_entry_parser.add_argument(
        '--title',
        required=True,
        help='Service/application name (required)'
    )
    add_entry_parser.add_argument(
        '--username',
        required=True,
        help='Username/email (required)'
    )
    add_entry_parser.add_argument(
        '--entry-password',
        dest='entry_password',
        help='Password for the entry (leave empty to generate or prompt)'
    )
    add_entry_parser.add_argument(
        '--url',
        help='URL (optional)'
    )
    add_entry_parser.add_argument(
        '--category',
        default='General',
        help='Category (default: General)'
    )
    add_entry_parser.add_argument(
        '--generate',
        action='store_true',
        help='Generate secure password'
    )
    add_entry_parser.add_argument(
        '--length',
        type=int,
        default=16,
        help='Password length when generating (default: 16)'
    )
    
    # Get entry command
    get_entry_parser = subparsers.add_parser(
        'get-entry',
        help='Retrieve and display credential entry',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="""
Retrieve and display a credential entry from the vault.
This command shows the details of a specific entry including the password.
        """,
        epilog="""
Example:
  python3 eyrie.py get-entry --vault vault.eyr --password masterpass --id EYR-ABC123
        """
    )
    get_entry_parser.add_argument(
        '--vault',
        default='vault.eyr',
        help='Vault file path (default: vault.eyr)'
    )
    get_entry_parser.add_argument(
        '--password',
        required=True,
        help='Master password (required)'
    )
    get_entry_parser.add_argument(
        '--id',
        required=True,
        help='Entry ID to retrieve (required)'
    )
    get_entry_parser.add_argument(
        '--no-password',
        action='store_true',
        help='Do not show password'
    )
    
    # List entries command
    list_entries_parser = subparsers.add_parser(
        'list-entries',
        help='List all credential entries',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="""
List all credential entries in the vault.
This command displays all stored entries, optionally filtered by category.
        """,
        epilog="""
Examples:
  python3 eyrie.py list-entries --vault vault.eyr --password masterpass
  python3 eyrie.py list-entries --vault vault.eyr --password masterpass --category "Social Media"
  python3 eyrie.py list-entries --vault vault.eyr --password masterpass --category all
        """
    )
    list_entries_parser.add_argument(
        '--vault',
        default='vault.eyr',
        help='Vault file path (default: vault.eyr)'
    )
    list_entries_parser.add_argument(
        '--password',
        required=True,
        help='Master password (required)'
    )
    list_entries_parser.add_argument(
        '--category',
        help='Filter by category (use "all" to show all entries)'
    )
    
    # Update entry command
    update_entry_parser = subparsers.add_parser(
        'update-entry',
        help='Update existing credential entry',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="""
Update an existing credential entry in the vault.
This command allows you to modify any field of an existing entry.
        """,
        epilog="""
Examples:
  python3 eyrie.py update-entry --vault vault.eyr --password masterpass --id EYR-ABC123 --title "New Title"
  python3 eyrie.py update-entry --vault vault.eyr --password masterpass --id EYR-ABC123 --generate --length 24
        """
    )
    update_entry_parser.add_argument(
        '--vault',
        default='vault.eyr',
        help='Vault file path (default: vault.eyr)'
    )
    update_entry_parser.add_argument(
        '--password',
        required=True,
        help='Master password (required)'
    )
    update_entry_parser.add_argument(
        '--id',
        required=True,
        help='Entry ID to update (required)'
    )
    update_entry_parser.add_argument(
        '--title',
        help='New service/application name'
    )
    update_entry_parser.add_argument(
        '--username',
        help='New username/email'
    )
    update_entry_parser.add_argument(
        '--entry-password',
        dest='entry_password',
        help='New password (leave empty to keep current)'
    )
    update_entry_parser.add_argument(
        '--url',
        help='New URL'
    )
    update_entry_parser.add_argument(
        '--category',
        help='New category'
    )
    update_entry_parser.add_argument(
        '--generate',
        action='store_true',
        help='Generate new secure password'
    )
    update_entry_parser.add_argument(
        '--length',
        type=int,
        default=16,
        help='Password length when generating (default: 16)'
    )
    
    # Delete entry command
    delete_entry_parser = subparsers.add_parser(
        'delete-entry',
        help='Delete credential entry',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="""
Permanently delete a credential entry from the vault.
This action cannot be undone and requires master password confirmation.
        """,
        epilog="""
Example:
  python3 eyrie.py delete-entry --vault vault.eyr --password masterpass --id EYR-ABC123
        """
    )
    delete_entry_parser.add_argument(
        '--vault',
        default='vault.eyr',
        help='Vault file path (default: vault.eyr)'
    )
    delete_entry_parser.add_argument(
        '--password',
        required=True,
        help='Master password (required)'
    )
    delete_entry_parser.add_argument(
        '--id',
        required=True,
        help='Entry ID to delete (required)'
    )
    delete_entry_parser.add_argument(
        '--force',
        action='store_true',
        help='Force deletion without confirmation'
    )
    
    # Add note command
    add_note_parser = subparsers.add_parser(
        'add-note',
        help='Add new secure note',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="""
Add a new secure note to the vault.
This command allows you to store encrypted text notes.
        """,
        epilog="""
Examples:
  python3 eyrie.py add-note --vault vault.eyr --password masterpass --title "Private Key" --category "Security"
  python3 eyrie.py add-note --vault vault.eyr --password masterpass --title "Recovery Codes" --content-file codes.txt
        """
    )
    add_note_parser.add_argument(
        '--vault',
        default='vault.eyr',
        help='Vault file path (default: vault.eyr)'
    )
    add_note_parser.add_argument(
        '--password',
        required=True,
        help='Master password (required)'
    )
    add_note_parser.add_argument(
        '--title',
        required=True,
        help='Note title (required)'
    )
    add_note_parser.add_argument(
        '--category',
        default='Notes',
        help='Note category (default: Notes)'
    )
    add_note_parser.add_argument(
        '--content',
        help='Note content'
    )
    add_note_parser.add_argument(
        '--content-file',
        help='Read note content from file'
    )
    
    # Get note command
    get_note_parser = subparsers.add_parser(
        'get-note',
        help='Retrieve and display secure note',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="""
Retrieve and display a secure note from the vault.
This command shows the details of a specific note including its content.
        """,
        epilog="""
Example:
  python3 eyrie.py get-note --vault vault.eyr --password masterpass --id EYR-DEF456
        """
    )
    get_note_parser.add_argument(
        '--vault',
        default='vault.eyr',
        help='Vault file path (default: vault.eyr)'
    )
    get_note_parser.add_argument(
        '--password',
        required=True,
        help='Master password (required)'
    )
    get_note_parser.add_argument(
        '--id',
        required=True,
        help='Note ID to retrieve (required)'
    )
    
    # List notes command
    list_notes_parser = subparsers.add_parser(
        'list-notes',
        help='List all secure notes',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="""
List all secure notes in the vault.
This command displays all stored notes, optionally filtered by category.
        """,
        epilog="""
Examples:
  python3 eyrie.py list-notes --vault vault.eyr --password masterpass
  python3 eyrie.py list-notes --vault vault.eyr --password masterpass --category "Security"
  python3 eyrie.py list-notes --vault vault.eyr --password masterpass --category all
        """
    )
    list_notes_parser.add_argument(
        '--vault',
        default='vault.eyr',
        help='Vault file path (default: vault.eyr)'
    )
    list_notes_parser.add_argument(
        '--password',
        required=True,
        help='Master password (required)'
    )
    list_notes_parser.add_argument(
        '--category',
        help='Filter by category (use "all" to show all notes)'
    )
    
    # Update note command
    update_note_parser = subparsers.add_parser(
        'update-note',
        help='Update existing secure note',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="""
Update an existing secure note in the vault.
This command allows you to modify any field of an existing note.
        """,
        epilog="""
Examples:
  python3 eyrie.py update-note --vault vault.eyr --password masterpass --id EYR-DEF456 --title "Updated Title"
  python3 eyrie.py update-note --vault vault.eyr --password masterpass --id EYR-DEF456 --content-file new_content.txt
        """
    )
    update_note_parser.add_argument(
        '--vault',
        default='vault.eyr',
        help='Vault file path (default: vault.eyr)'
    )
    update_note_parser.add_argument(
        '--password',
        required=True,
        help='Master password (required)'
    )
    update_note_parser.add_argument(
        '--id',
        required=True,
        help='Note ID to update (required)'
    )
    update_note_parser.add_argument(
        '--title',
        help='New title'
    )
    update_note_parser.add_argument(
        '--category',
        help='New category'
    )
    update_note_parser.add_argument(
        '--content',
        help='New content'
    )
    update_note_parser.add_argument(
        '--content-file',
        help='Read new content from file'
    )
    
    # Search notes command
    search_notes_parser = subparsers.add_parser(
        'search-notes',
        help='Search notes by title, content, or category',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="""
Search notes by title, content, or category.
This command searches through all notes for the specified term.
        """,
        epilog="""
Example:
  python3 eyrie.py search-notes --vault vault.eyr --password masterpass --term "password"
        """
    )
    search_notes_parser.add_argument(
        '--vault',
        default='vault.eyr',
        help='Vault file path (default: vault.eyr)'
    )
    search_notes_parser.add_argument(
        '--password',
        required=True,
        help='Master password (required)'
    )
    search_notes_parser.add_argument(
        '--term',
        required=True,
        help='Search term (required)'
    )
    
    # Delete note command
    delete_note_parser = subparsers.add_parser(
        'delete-note',
        help='Delete secure note',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="""
Permanently delete a secure note from the vault.
This action cannot be undone and requires master password confirmation.
        """,
        epilog="""
Example:
  python3 eyrie.py delete-note --vault vault.eyr --password masterpass --id EYR-DEF456
        """
    )
    delete_note_parser.add_argument(
        '--vault',
        default='vault.eyr',
        help='Vault file path (default: vault.eyr)'
    )
    delete_note_parser.add_argument(
        '--password',
        required=True,
        help='Master password (required)'
    )
    delete_note_parser.add_argument(
        '--id',
        required=True,
        help='Note ID to delete (required)'
    )
    delete_note_parser.add_argument(
        '--force',
        action='store_true',
        help='Force deletion without confirmation'
    )
    
    # Password generation command
    gen_parser = subparsers.add_parser(
        'generate', 
        help='Generate secure password',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="""
Generate a secure random password.
This command creates cryptographically secure passwords.
        """,
        epilog="""
Examples:
  python3 eyrie.py generate --length 20
  python3 eyrie.py generate --length 16 --reveal
        """
    )
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
        help='Create encrypted Eyrie vault backup',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="""
Create an encrypted backup of the vault.
This command creates a portable, encrypted backup file that can be restored later.
        """,
        epilog="""
Example:
  python3 eyrie.py export --vault vault.eyr --backup-path backup.enc --password backup_password
        """
    )
    export_parser.add_argument(
        '--vault', 
        default='vault.eyr', 
        help='Source vault file (default: vault.eyr)'
    )
    export_parser.add_argument(
        '--backup-path', 
        default='vault_backup.enc', 
        help='Backup destination path (default: vault_backup.enc)'
    )
    export_parser.add_argument(
        '--password', 
        required=True,
        help='Backup encryption password (required)'
    )
    export_parser.add_argument(
        '--confirm-password', 
        help='Backup password confirmation'
    )
    
    # Vault import command
    import_parser = subparsers.add_parser(
        'import', 
        help='Restore Eyrie vault from backup',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="""
Restore a vault from an encrypted backup.
This command imports a previously exported backup file.
        """,
        epilog="""
Example:
  python3 eyrie.py import --backup-path backup.enc --password backup_password --target-vault restored.eyr
        """
    )
    import_parser.add_argument(
        '--backup-path', 
        required=True, 
        help='Backup file path (required)'
    )
    import_parser.add_argument(
        '--password', 
        required=True,
        help='Backup decryption password (required)'
    )
    import_parser.add_argument(
        '--target-vault', 
        default='vault.eyr', 
        help='Destination vault path (default: vault.eyr)'
    )
    
    # Master password change command
    change_parser = subparsers.add_parser(
        'change-master', 
        help='Rotate Eyrie master credentials',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="""
Change the master password and re-encrypt all vault data.
This operation requires the current master password.
        """,
        epilog="""
Example:
  python3 eyrie.py change-master --vault vault.eyr
        """
    )
    change_parser.add_argument(
        '--vault', 
        default='vault.eyr', 
        help='Vault file path (default: vault.eyr)'
    )
    
    # Vault info command
    info_parser = subparsers.add_parser(
        'vault-info',
        help='Display vault statistics and metadata',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="""
Display vault statistics and metadata.
This command shows information about the vault including entry counts and creation date.
        """,
        epilog="""
Example:
  python3 eyrie.py vault-info --vault vault.eyr --password masterpass
        """
    )
    info_parser.add_argument(
        '--vault',
        default='vault.eyr',
        help='Vault file path (default: vault.eyr)'
    )
    info_parser.add_argument(
        '--password',
        required=True,
        help='Master password (required)'
    )
    
    # Parse command-line arguments
    if len(sys.argv) == 1:
        parser.print_help()
        return
    
    args = parser.parse_args()
    
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
            if eyrie.unlock_vault(args.vault, args.password):
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
                        elif resolved_command == 'add_note':
                            eyrie.add_note()
                        elif resolved_command == 'list_notes':
                            eyrie.list_notes()
                        elif resolved_command == 'get_note':
                            eyrie.get_note()
                        elif resolved_command == 'update_note':
                            eyrie.update_note()
                        elif resolved_command == 'search_notes':
                            eyrie.search_notes()
                        elif resolved_command == 'delete_note':
                            eyrie.delete_note()
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
        
        elif args.command == 'add-entry':
            if eyrie.unlock_vault(args.vault, args.password):
                success = eyrie.add_entry(
                    title=args.title,
                    username=args.username,
                    password=args.entry_password,
                    url=args.url,
                    category=args.category,
                    generate_password=args.generate,
                    password_length=args.length
                )
        
        elif args.command == 'get-entry':
            if eyrie.unlock_vault(args.vault, args.password):
                eyrie.get_entry(entry_id=args.id, show_password=not args.no_password)
        
        elif args.command == 'list-entries':
            if eyrie.unlock_vault(args.vault, args.password):
                eyrie.list_entries(category=args.category)
        
        elif args.command == 'update-entry':
            if eyrie.unlock_vault(args.vault, args.password):
                success = eyrie.update_entry(
                    entry_id=args.id,
                    title=args.title,
                    username=args.username,
                    password=args.entry_password,
                    url=args.url,
                    category=args.category,
                    generate_password=args.generate,
                    password_length=args.length
                )
        
        elif args.command == 'delete-entry':
            if eyrie.unlock_vault(args.vault, args.password):
                if args.force:
                    print("[-] Force deletion not yet implemented in this version")
                    success = eyrie.delete_entry(entry_id=args.id)
                else:
                    success = eyrie.delete_entry(entry_id=args.id)
        
        elif args.command == 'add-note':
            if eyrie.unlock_vault(args.vault, args.password):
                # Read content from file if specified
                content = None
                if args.content_file:
                    try:
                        with open(args.content_file, 'r') as f:
                            content = f.read()
                    except Exception as e:
                        print(f"[-] Error reading content file: {e}")
                        return
                
                success = eyrie.add_note(
                    title=args.title,
                    category=args.category,
                    content=content or args.content
                )
        
        elif args.command == 'get-note':
            if eyrie.unlock_vault(args.vault, args.password):
                eyrie.get_note(entry_id=args.id)
        
        elif args.command == 'list-notes':
            if eyrie.unlock_vault(args.vault, args.password):
                eyrie.list_notes(category=args.category)
        
        elif args.command == 'update-note':
            if eyrie.unlock_vault(args.vault, args.password):
                # Read content from file if specified
                content = None
                if args.content_file:
                    try:
                        with open(args.content_file, 'r') as f:
                            content = f.read()
                    except Exception as e:
                        print(f"[-] Error reading content file: {e}")
                        return
                
                success = eyrie.update_note(
                    entry_id=args.id,
                    title=args.title,
                    category=args.category,
                    content=content or args.content
                )
        
        elif args.command == 'search-notes':
            if eyrie.unlock_vault(args.vault, args.password):
                eyrie.search_notes(search_term=args.term)
        
        elif args.command == 'delete-note':
            if eyrie.unlock_vault(args.vault, args.password):
                if args.force:
                    print("[-] Force deletion not yet implemented in this version")
                    success = eyrie.delete_note(entry_id=args.id)
                else:
                    success = eyrie.delete_note(entry_id=args.id)
        
        elif args.command == 'vault-info':
            if eyrie.unlock_vault(args.vault, args.password):
                eyrie.vault_info()
        
        elif args.command == 'generate':
            eyrie.generate_password(length=args.length, reveal=args.reveal)
        
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