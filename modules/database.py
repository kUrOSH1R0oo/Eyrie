"""
Eyrie Database Operations - EYR Vault Format

This module provides the database interface for the Eyrie password manager,
handling all CRUD operations on the encrypted EYR vault format. It manages
entry encryption/decryption, metadata operations, and Two-Factor Authentication
integration with secure data persistence.
"""

import json
import base64
import os
import time
import shutil
import re
from typing import List, Dict, Optional, Tuple, Any
from datetime import datetime

# Local cryptographic module imports
from .crypto import (
    derive_master_key, encrypt_entry, decrypt_entry, 
    generate_salt, compute_hmac, verify_hmac,
    KEY_SIZE, encrypt_data, decrypt_data
)
from .eyr_format import EYRFile  # EYR file format handler

# ==============================================================================
# VAULT DATABASE CLASS
# ==============================================================================

class VaultDatabase:
    """
    Secure vault database interface using the EYR encrypted file format.
    
    This class serves as the main interface between the application logic
    and the encrypted vault storage, providing methods for:
    - Vault initialization and master key verification
    - CRUD operations on password entries
    - Two-Factor Authentication management
    - Password history tracking and retrieval
    - Vault metadata and statistics
    
    The class handles all cryptographic operations at the database level,
    ensuring data remains encrypted at rest and is only decrypted in memory
    when necessary for operations.
    """
    
    def __init__(self, db_path: str = "vault.eyr"):
        """
        Initialize vault database interface.
        
        Args:
            db_path (str): Path to the EYR vault file. Defaults to "vault.eyr"
                          in the current directory.
        
        Note:
            The database connection is lazy-initialized. Actual file operations
            occur when connect() is called.
        """
        self.db_path = db_path        # Path to the vault file
        self.eyr_file = None          # EYRFile instance for low-level operations
        self.next_entry_id = 1        # Next available entry ID
    
    # ==========================================================================
    # DATABASE CONNECTION MANAGEMENT
    # ==========================================================================
    
    def connect(self) -> None:
        """
        Establish connection to the EYR vault file.
        
        This method initializes the EYRFile handler and prepares it for
        operations. It should be called before any vault operations.
        
        Note:
            This method is idempotent - calling it multiple times will not
            create multiple connections.
        """
        if not self.eyr_file:
            self.eyr_file = EYRFile(self.db_path)
    
    def close(self) -> None:
        """
        Close the EYR file connection and release resources.
        
        This method should be called when the database is no longer needed
        to ensure proper cleanup and file handles are released.
        """
        if self.eyr_file:
            self.eyr_file.close()
            self.eyr_file = None
    
    # ==========================================================================
    # UTILITY AND FORMATTING METHODS
    # ==========================================================================
    
    @staticmethod
    def format_timestamp(timestamp: Optional[float]) -> str:
        """
        Format a Unix timestamp into a human-readable date string (YYYY/MM/DD).
        
        Args:
            timestamp (float, optional): Unix timestamp to format. Can be None.
        
        Returns:
            str: Formatted date string, or empty string if timestamp is None
                 or formatting fails.
        
        Example:
            >>> format_timestamp(1672531199)  # Jan 1, 2023
            '2023/01/01'
        """
        if timestamp is None:
            return ""
        
        try:
            dt = datetime.fromtimestamp(timestamp)
            return dt.strftime("%Y/%m/%d")
        except (ValueError, TypeError, OSError):
            # Return empty string on formatting errors
            return ""
    
    @staticmethod
    def format_datetime(timestamp: Optional[float]) -> str:
        """
        Format a Unix timestamp into a full datetime string (YYYY/MM/DD HH:MM:SS).
        
        Args:
            timestamp (float, optional): Unix timestamp to format.
        
        Returns:
            str: Formatted datetime string, or empty string on error.
        
        Example:
            >>> format_datetime(1672531199)
            '2023/01/01 23:59:59'
        """
        if timestamp is None:
            return ""
        
        try:
            dt = datetime.fromtimestamp(timestamp)
            return dt.strftime("%Y/%m/%d %H:%M:%S")
        except (ValueError, TypeError, OSError):
            return ""
    
    @staticmethod
    def mask_password_partial(password: str) -> str:
        """
        Partially mask a password for display while revealing some characters.
        
        Shows the first 2 and last 2 characters, masking the middle.
        This provides a balance between security and usability for verification.
        
        Args:
            password (str): Original password to mask.
        
        Returns:
            str: Partially masked password.
        
        Examples:
            >>> mask_password_partial("password123")
            'pa*******23'
            >>> mask_password_partial("abc")
            '***'
            >>> mask_password_partial("")
            ''
        
        Security Note:
            This is only for display purposes. Never log or store partially
            masked passwords as they can be subject to brute-force attacks.
        """
        if not password:
            return ""
        
        length = len(password)
        
        # For very short passwords (≤4 chars), show as all asterisks
        if length <= 4:
            return "*" * length
        
        # Extract first 2 characters
        first_part = password[:2]
        # Extract last 2 characters (if length > 4)
        last_part = password[-2:] if length > 4 else ""
        # Create masked middle section
        masked_middle = "*" * (length - 4) if length > 4 else ""
        
        return f"{first_part}{masked_middle}{last_part}"
    
    # ==========================================================================
    # CATEGORY NORMALIZATION METHODS
    # ==========================================================================
    
    def _normalize_category_name(self, category: str) -> str:
        """
        Normalize category name for flexible matching.
        
        Args:
            category (str): Original category name
        
        Returns:
            str: Normalized category name for comparison
        
        Normalization steps:
        1. Convert to lowercase
        2. Remove extra whitespace
        3. Replace common separators with spaces
        4. Remove all non-alphanumeric characters (except spaces)
        5. Normalize multiple spaces to single space
        6. Sort words alphabetically (optional, for "media social" vs "social media")
        """
        if not category:
            return ""
        
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
        
        # Sort words alphabetically for better matching
        # This helps match "media social" with "social media"
        words = normalized.split()
        if len(words) > 1:
            words_sorted = sorted(words)
            normalized = ' '.join(words_sorted)
        
        return normalized
    
    def get_category_suggestions(self, master_key: bytes, search_category: str) -> List[str]:
        """
        Get list of categories similar to the search term.
        
        Args:
            master_key (bytes): Master encryption key
            search_category (str): Category to find suggestions for
        
        Returns:
            List[str]: List of similar category names
        """
        suggestions = set()
        
        try:
            self.connect()
            
            if not self.eyr_file.load():
                return list(suggestions)
            
            entry_ids = self.eyr_file.list_entries()
            
            # Normalize search category
            normalized_search = self._normalize_category_name(search_category)
            
            for entry_id in entry_ids:
                entry = self.get_entry(master_key, entry_id, formatted=False)
                if entry:
                    entry_category = entry.get('category', '')
                    if entry_category:
                        normalized_entry = self._normalize_category_name(entry_category)
                        
                        # Check for partial matches or similar categories
                        if (normalized_search in normalized_entry or 
                            normalized_entry in normalized_search or
                            self._are_categories_similar(normalized_search, normalized_entry)):
                            suggestions.add(entry_category.strip())
        
        except Exception as e:
            print(f"[-] Error getting category suggestions: {e}")
        
        return sorted(list(suggestions))
    
    def _are_categories_similar(self, cat1: str, cat2: str, threshold: float = 0.7) -> bool:
        """
        Check if two category names are similar using fuzzy matching.
        
        Args:
            cat1 (str): First category
            cat2 (str): Second category
            threshold (float): Similarity threshold (0.0 to 1.0)
        
        Returns:
            bool: True if categories are similar
        """
        try:
            # Simple word overlap similarity
            words1 = set(cat1.split())
            words2 = set(cat2.split())
            
            if not words1 or not words2:
                return False
            
            intersection = len(words1.intersection(words2))
            union = len(words1.union(words2))
            
            if union == 0:
                return False
            
            similarity = intersection / union
            return similarity >= threshold
            
        except Exception:
            return False
    
    # ==========================================================================
    # VAULT INITIALIZATION AND VERIFICATION
    # ==========================================================================
    
    def initialize_vault(self, master_key: bytes, salt: bytes) -> bool:
        """
        Initialize a new encrypted vault with provided cryptographic parameters.
        
        Creates a new EYR vault file with metadata and a verification token
        encrypted with the master key. This establishes the vault structure.
        
        Args:
            master_key (bytes): 64-byte derived master encryption key
            salt (bytes): Cryptographic salt used for key derivation
        
        Returns:
            bool: True if vault creation succeeded, False otherwise.
        
        Security Notes:
            - A verification token is encrypted and stored for future key validation
            - Salt is stored in base64 format for persistence
            - Metadata includes creation timestamp and algorithm parameters
            - 2FA fields are initialized with default values
        """
        self.connect()
        
        # Generate a random verification token (256 bits)
        verification_token = os.urandom(32)
        
        # Extract encryption portion of master key (first 32 bytes)
        encryption_key = master_key[:KEY_SIZE]
        # Encrypt the verification token with AES-GCM
        nonce, ciphertext, tag = encrypt_data(encryption_key, verification_token)
        
        # Build vault metadata dictionary
        metadata = {
            'version': '1.0.1',  # Vault format version
            'created_at': time.time(),  # Creation timestamp
            'salt': base64.b64encode(salt).decode('ascii'),  # Store salt as base64
            
            # Key derivation parameters (for reference and future compatibility)
            'key_derivation_params': {
                'algorithm': 'argon2id',
                'key_size': KEY_SIZE * 2,  # 64 bytes total (32 encryption + 32 auth)
                'salt_size': len(salt)
            },
            
            # Verification data for master key validation
            'verification_token': base64.b64encode(ciphertext).decode('ascii'),
            'verification_nonce': base64.b64encode(nonce).decode('ascii'),
            'verification_tag': base64.b64encode(tag).decode('ascii'),
            
            # Entry counter for generating unique entry IDs
            'entry_counter': 1,
            
            # Two-Factor Authentication fields (initialized to defaults)
            'tfa_enabled': False,
            'tfa_secret': None,
            'tfa_recovery_codes': [],
            'tfa_trusted_devices': [],
            'tfa_last_used': None
        }
        
        # Create the vault file with metadata
        if self.eyr_file.create(metadata):
            print(f"[+] EYR vault created: {self.db_path}")
            self.next_entry_id = 1
            return True
        
        print("[-] Failed to create EYR vault")
        return False
    
    def add_tfa_fields_if_missing(self, master_key: bytes) -> bool:
        """
        Add 2FA metadata fields to an existing vault for backward compatibility.
        
        Older vaults may not have 2FA fields. This method ensures they exist
        with default values.
        
        Args:
            master_key (bytes): Master encryption key (for consistency)
        
        Returns:
            bool: True if fields were added or already exist, False on error.
        
        Note:
            The master_key parameter is included for interface consistency
            but is not used in this method.
        """
        try:
            self.connect()
            
            # Load existing vault data
            if not self.eyr_file.load():
                return False
            
            metadata = self.eyr_file.metadata
            if not metadata:
                return False
            
            # Check each 2FA field and add if missing
            needs_update = False
            
            if 'tfa_enabled' not in metadata:
                metadata['tfa_enabled'] = False
                needs_update = True
            
            if 'tfa_secret' not in metadata:
                metadata['tfa_secret'] = None
                needs_update = True
            
            if 'tfa_recovery_codes' not in metadata:
                metadata['tfa_recovery_codes'] = []
                needs_update = True
            
            if 'tfa_trusted_devices' not in metadata:
                metadata['tfa_trusted_devices'] = []
                needs_update = True
            
            if 'tfa_last_used' not in metadata:
                metadata['tfa_last_used'] = None
                needs_update = True
            
            # Only update if fields were added
            if needs_update:
                self.eyr_file.metadata = metadata
                result = self.eyr_file.update_metadata()
                return result
            
            return True  # Fields already exist
            
        except Exception as e:
            print(f"[-] Error adding 2FA fields: {e}")
            return False
    
    def verify_master_key(self, master_key: bytes) -> bool:
        """
        Validate a master key against the vault's verification token.
        
        Attempts to decrypt the stored verification token using the provided
        key. Success indicates the key is correct.
        
        Args:
            master_key (bytes): Key to verify against the vault.
        
        Returns:
            bool: True if the key successfully decrypts the verification token.
        
        Security Notes:
            - Uses constant-time decryption to avoid timing attacks
            - Verifies both successful decryption AND correct token length
            - Returns False on any error to avoid information leakage
        """
        if not self.eyr_file or not self.eyr_file.load():
            return False
        
        try:
            if not self.eyr_file.metadata:
                return False
                
            metadata = self.eyr_file.metadata
            
            # Validate required metadata fields exist
            required_fields = ['version', 'created_at', 'salt', 
                             'verification_token', 'verification_nonce', 'verification_tag']
            for field in required_fields:
                if field not in metadata:
                    return False
            
            # Extract verification data from metadata
            verification_token_b64 = metadata['verification_token']
            verification_nonce_b64 = metadata['verification_nonce']
            verification_tag_b64 = metadata['verification_tag']
            
            if not verification_token_b64 or not verification_nonce_b64 or not verification_tag_b64:
                return False
            
            # Decode base64-encoded verification data
            try:
                ciphertext = base64.b64decode(verification_token_b64)
                nonce = base64.b64decode(verification_nonce_b64)
                tag = base64.b64decode(verification_tag_b64)
            except (ValueError, TypeError):
                return False  # Invalid base64 data
            
            # Validate master key length
            if len(master_key) < KEY_SIZE:
                return False
                
            # Extract encryption portion of master key
            encryption_key = master_key[:KEY_SIZE]
            # Attempt to decrypt verification token
            decrypted = decrypt_data(encryption_key, nonce, ciphertext, tag)
            
            # Key is valid if decryption succeeds and returns exactly 32 bytes
            return decrypted is not None and len(decrypted) == 32
            
        except Exception as e:
            # Log error but don't expose details to caller
            print(f"[-] Key verification error: {e}")
            return False
    
    # ==========================================================================
    # TWO-FACTOR AUTHENTICATION MANAGEMENT
    # ==========================================================================
    
    def get_tfa_settings(self, master_key: bytes) -> Optional[Dict]:
        """
        Retrieve Two-Factor Authentication settings from vault metadata.
        
        Args:
            master_key (bytes): Master encryption key (for consistency)
        
        Returns:
            Optional[Dict]: Dictionary containing 2FA settings, or None on error.
            
            Dictionary structure:
            {
                'enabled': bool,
                'secret': str or None,
                'recovery_codes': List[Dict],
                'trusted_devices': List[Dict],
                'last_used': float or None
            }
        """
        try:
            self.connect()
            
            if not self.eyr_file.load():
                return None
            
            metadata = self.eyr_file.metadata
            if not metadata:
                return None
            
            # Extract 2FA settings from metadata
            tfa_settings = {
                'enabled': metadata.get('tfa_enabled', False),
                'secret': metadata.get('tfa_secret'),
                'recovery_codes': metadata.get('tfa_recovery_codes', []),
                'trusted_devices': metadata.get('tfa_trusted_devices', []),
                'last_used': metadata.get('tfa_last_used')
            }
            
            return tfa_settings
            
        except Exception as e:
            print(f"[-] Error retrieving 2FA settings: {e}")
            return None
    
    def update_tfa_settings(self, master_key: bytes, tfa_settings: Dict) -> bool:
        """
        Update 2FA settings in vault metadata.
        
        Args:
            master_key (bytes): Master encryption key (for consistency)
            tfa_settings (Dict): Updated 2FA settings dictionary
        
        Returns:
            bool: True if update succeeded, False otherwise.
        
        Note:
            This method attempts a standard metadata update first, with a
            fallback to vault recreation if the standard method fails.
        """
        try:
            self.connect()
            
            if not self.eyr_file:
                return False
            
            if not self.eyr_file.load():
                return False
            
            # Update metadata with provided 2FA settings
            metadata = self.eyr_file.metadata
            if not metadata:
                return False
            
            metadata['tfa_enabled'] = tfa_settings.get('enabled', False)
            metadata['tfa_secret'] = tfa_settings.get('secret')
            metadata['tfa_recovery_codes'] = tfa_settings.get('recovery_codes', [])
            metadata['tfa_trusted_devices'] = tfa_settings.get('trusted_devices', [])
            metadata['tfa_last_used'] = tfa_settings.get('last_used', time.time())
            
            # Save updated metadata
            self.eyr_file.metadata = metadata
            
            # Try standard metadata update
            result = self.eyr_file.update_metadata()
            
            if not result:
                # Fallback: recreate vault with updated metadata if standard update fails
                result = self._fallback_update_metadata(metadata)
                
                # Reconnect after fallback operation
                if result:
                    self.connect()
            
            return result
            
        except Exception as e:
            print(f"[-] Error updating 2FA settings: {e}")
            import traceback
            traceback.print_exc()
            return False

    def _fallback_update_metadata(self, metadata: Dict) -> bool:
        """
        Fallback method to update metadata by recreating the vault.
        
        This is a last resort when the standard metadata update fails,
        potentially due to file corruption or format issues.
        
        Args:
            metadata (Dict): Updated metadata to apply
        
        Returns:
            bool: True if vault was successfully recreated with new metadata.
        
        Security Note:
            Creates a temporary backup during the operation and restores it
            if the recreation fails.
        """
        try:
            # Create a temporary backup of the current vault
            temp_backup = f"{self.db_path}.backup"
            shutil.copy2(self.db_path, temp_backup)
            
            try:
                # Close current connection
                self.close()
                
                # Get the current vault entries before recreation
                old_eyr = EYRFile(self.db_path)
                if not old_eyr.load():
                    return False
                
                # Extract all existing entries
                entry_ids = old_eyr.list_entries()
                entries_data = {}
                for entry_id in entry_ids:
                    entry_data = old_eyr.get_entry(entry_id)
                    if entry_data:
                        entries_data[entry_id] = entry_data
                
                old_eyr.close()
                
                # Create new vault with updated metadata
                new_eyr = EYRFile(self.db_path)
                
                # Merge existing metadata with updates
                if os.path.exists(self.db_path):
                    old_eyr2 = EYRFile(self.db_path)
                    if old_eyr2.load():
                        old_metadata = old_eyr2.metadata.copy() if old_eyr2.metadata else {}
                        old_metadata.update(metadata)  # Apply updates
                        old_eyr2.close()
                    else:
                        old_metadata = metadata
                else:
                    old_metadata = metadata
                
                # Create new vault file with merged metadata
                if not new_eyr.create(old_metadata):
                    return False
                
                # Restore all entries to the new vault
                for entry_id, entry_data in entries_data.items():
                    new_eyr.add_entry(entry_id, entry_data)
                
                new_eyr.close()
                
                return True  # Recreation successful
                
            except Exception:
                # Restore from backup if recreation failed
                if os.path.exists(temp_backup):
                    shutil.copy2(temp_backup, self.db_path)
                return False
            finally:
                # Clean up temporary backup file
                if os.path.exists(temp_backup):
                    try:
                        os.remove(temp_backup)
                    except:
                        pass  # Ignore cleanup errors
                    
        except Exception:
            return False  # Overall fallback operation failed
    
    def enable_tfa(self, master_key: bytes, secret: str, recovery_codes: List[str]) -> bool:
        """
        Enable Two-Factor Authentication for the vault.
        
        Args:
            master_key (bytes): Master encryption key
            secret (str): TOTP secret for authenticator apps
            recovery_codes (List[str]): List of emergency recovery codes
        
        Returns:
            bool: True if 2FA was successfully enabled.
        
        Note:
            Recovery codes are stored with metadata including usage status
            and expiration (1 year from creation).
        """
        try:
            # Prepare recovery codes with metadata
            recovery_code_objs = []
            for code in recovery_codes:
                recovery_code_objs.append({
                    'code': code, 
                    'used': False,  # Track if code has been used
                    'expires': time.time() + 86400 * 365  # Expire in 1 year
                })
            
            # Build 2FA settings dictionary
            tfa_settings = {
                'enabled': True,
                'secret': secret,
                'recovery_codes': recovery_code_objs,
                'trusted_devices': [],  # Start with no trusted devices
                'last_used': time.time()  # Set initial usage timestamp
            }
            
            return self.update_tfa_settings(master_key, tfa_settings)
            
        except Exception as e:
            print(f"[-] Error enabling 2FA: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def disable_tfa(self, master_key: bytes) -> bool:
        """
        Disable Two-Factor Authentication for the vault.
        
        Args:
            master_key (bytes): Master encryption key
        
        Returns:
            bool: True if 2FA was successfully disabled.
        
        Note:
            This removes all 2FA configuration including secret and recovery codes.
        """
        try:
            # Reset all 2FA settings to defaults
            tfa_settings = {
                'enabled': False,
                'secret': None,
                'recovery_codes': [],
                'trusted_devices': [],
                'last_used': None
            }
            
            return self.update_tfa_settings(master_key, tfa_settings)
            
        except Exception as e:
            print(f"[-] Error disabling 2FA: {e}")
            return False
    
    def verify_totp_code(self, master_key: bytes, code: str) -> bool:
        """
        Verify a TOTP (Time-based One-Time Password) code.
        
        Args:
            master_key (bytes): Master encryption key (to access 2FA settings)
            code (str): 6-digit TOTP code from authenticator app
        
        Returns:
            bool: True if the code is valid, False otherwise.
        
        Note:
            Delegates actual TOTP verification to the tfa_manager module.
        """
        try:
            # Retrieve 2FA settings from vault
            tfa_settings = self.get_tfa_settings(master_key)
            if not tfa_settings or not tfa_settings['enabled']:
                return False  # 2FA not enabled
            
            secret = tfa_settings.get('secret')
            if not secret:
                return False  # No secret configured
            
            # Delegate verification to TFA manager
            from .tfa import tfa_manager
            return tfa_manager.verify_totp_code(secret, code)
            
        except Exception as e:
            print(f"[-] Error verifying TOTP code: {e}")
            return False
    
    def verify_recovery_code(self, master_key: bytes, code: str) -> Tuple[bool, bool]:
        """
        Verify a 2FA recovery code and update its status.
        
        Args:
            master_key (bytes): Master encryption key
            code (str): Recovery code to verify
        
        Returns:
            Tuple[bool, bool]: 
                - First bool: True if code is valid
                - Second bool: True if 2FA should be disabled (no remaining codes)
        
        Note:
            Valid recovery codes are marked as used after verification.
            If all recovery codes are used, suggests disabling 2FA.
        """
        try:
            # Get current 2FA settings
            tfa_settings = self.get_tfa_settings(master_key)
            if not tfa_settings:
                return False, False
            
            from .tfa import tfa_manager
            recovery_codes = tfa_settings.get('recovery_codes', [])
            
            # Verify code and get updated code list
            is_valid, updated_codes = tfa_manager.verify_recovery_code(code, recovery_codes)
            
            if is_valid:
                # Count remaining unused codes
                unused_codes = [c for c in updated_codes if not c.get('used', False)]
                
                # Update vault with marked code
                tfa_settings['recovery_codes'] = updated_codes
                self.update_tfa_settings(master_key, tfa_settings)
                
                # Suggest disabling 2FA if no recovery codes remain
                should_disable = len(unused_codes) == 0
                return True, should_disable
            
            return False, False
            
        except Exception as e:
            print(f"[-] Error verifying recovery code: {e}")
            return False, False
    
    def update_trusted_device(self, master_key: bytes, device_id: str, add: bool = True) -> bool:
        """
        Add or remove a trusted device for 2FA bypass.
        
        Args:
            master_key (bytes): Master encryption key
            device_id (str): Unique device identifier
            add (bool): True to add device, False to remove
        
        Returns:
            bool: True if operation succeeded.
        
        Note:
            Trusted devices bypass 2FA for a configured period (e.g., 30 days).
        """
        try:
            # Get current 2FA settings
            tfa_settings = self.get_tfa_settings(master_key)
            if not tfa_settings:
                return False
            
            from .tfa import tfa_manager
            trusted_devices = tfa_settings.get('trusted_devices', [])
            
            # Update trusted devices list
            if add:
                trusted_devices = tfa_manager.add_trusted_device(device_id, trusted_devices)
            else:
                trusted_devices = tfa_manager.remove_trusted_device(device_id, trusted_devices)
            
            # Update settings with new device list
            tfa_settings['trusted_devices'] = trusted_devices
            tfa_settings['last_used'] = time.time()  # Update last used timestamp
            
            return self.update_tfa_settings(master_key, tfa_settings)
            
        except Exception as e:
            print(f"[-] Error updating trusted device: {e}")
            return False
    
    # ==========================================================================
    # ENTRY MANAGEMENT - CRUD OPERATIONS
    # ==========================================================================
    
    def add_entry(self, master_key: bytes, entry_data: dict) -> Optional[int]:
        """
        Add a new password entry to the vault.
        
        Args:
            master_key (bytes): Master encryption key
            entry_data (dict): Entry data including title, username, password, etc.
        
        Returns:
            Optional[int]: Assigned entry ID if successful, None otherwise.
        
        Security Notes:
            - Entry data is encrypted with entry-specific additional authenticated data
            - Password history is initialized as empty (only populated on changes)
            - Timestamps are added for creation and modification tracking
        """
        try:
            self.connect()
            
            if not self.eyr_file.load():
                return None
            
            # Get next available entry ID from metadata
            entry_id = self.eyr_file.metadata.get('entry_counter', 1)
            
            # Add timestamps to entry data
            current_time = time.time()
            entry_data_with_timestamps = entry_data.copy()
            entry_data_with_timestamps['created_at'] = current_time
            entry_data_with_timestamps['updated_at'] = current_time
            
            # Initialize empty password history
            # Current password is NOT added to history here - only old passwords go in history
            entry_data_with_timestamps['password_history'] = []
            
            # Encrypt the complete entry data
            encrypted = encrypt_entry(master_key, entry_data_with_timestamps, entry_id)
            
            # Build storage structure with additional metadata
            entry_storage = {
                'encrypted_data': encrypted,  # The encrypted entry
                'category': entry_data.get('category', 'General'),
                'created_at': current_time,
                'updated_at': current_time
            }
            
            # Serialize to JSON and encode to bytes
            entry_json = json.dumps(entry_storage, ensure_ascii=False)
            entry_bytes = entry_json.encode('utf-8')
            
            # Store entry in vault
            if self.eyr_file.add_entry(entry_id, entry_bytes):
                # Increment entry counter in metadata
                self.eyr_file.metadata['entry_counter'] = entry_id + 1
                self.eyr_file.update_metadata()
                
                print(f"[+] Entry added (ID: {entry_id})")
                return entry_id
            
            return None  # Entry addition failed
            
        except Exception as e:
            print(f"[-] Error adding entry: {e}")
            return None
    
    def get_entry(self, master_key: bytes, entry_id: int, formatted: bool = True) -> Optional[dict]:
        """
        Retrieve and decrypt an entry by ID.
        
        Args:
            master_key (bytes): Master encryption key
            entry_id (int): Entry identifier
            formatted (bool): If True, include formatted timestamps
        
        Returns:
            Optional[dict]: Decrypted entry data with metadata, or None if not found.
        
        Note:
            The entry includes both raw timestamps (for internal use) and
            optionally formatted timestamps (for display).
        """
        try:
            self.connect()
            
            if not self.eyr_file.load():
                return None
            
            # Retrieve raw entry bytes from vault
            entry_bytes = self.eyr_file.get_entry(entry_id)
            if not entry_bytes:
                return None
            
            # Parse storage structure
            entry_storage = json.loads(entry_bytes.decode('utf-8'))
            encrypted_data = entry_storage.get('encrypted_data', {})
            
            # Decrypt entry data
            entry_data = decrypt_entry(master_key, encrypted_data)
            if not entry_data:
                return None
            
            # Add metadata fields
            entry_data['id'] = entry_id
            entry_data['category'] = entry_storage.get('category', 'General')
            
            # Handle timestamps with storage data taking precedence
            storage_created = entry_storage.get('created_at')
            decrypted_created = entry_data.get('created_at')
            entry_data['created_at'] = storage_created if storage_created is not None else decrypted_created
            entry_data['updated_at'] = entry_storage.get('updated_at', entry_data.get('updated_at'))
            
            # Store raw timestamps for internal use
            entry_data['created_raw'] = entry_data.get('created_at')
            entry_data['updated_raw'] = entry_data.get('updated_at')
            
            # Add formatted timestamps for display if requested
            if formatted:
                entry_data['created_formatted'] = self.format_datetime(entry_data.get('created_at'))
                entry_data['updated_formatted'] = self.format_datetime(entry_data.get('updated_at'))
            
            return entry_data
            
        except Exception as e:
            print(f"[-] Error retrieving entry {entry_id}: {e}")
            return None
    
    def list_entries(self, master_key: bytes, limit: int = 1000) -> List[dict]:
        """
        List all vault entries with basic information.
        
        Args:
            master_key (bytes): Master encryption key
            limit (int): Maximum number of entries to return
        
        Returns:
            List[dict]: List of entry summaries (title, username, category, creation date).
        
        Note:
            This method decrypts each entry to extract summary information.
            For large vaults, consider implementing a metadata-only approach.
        """
        entries = []
        
        try:
            self.connect()
            
            if not self.eyr_file.load():
                return entries
            
            # Get list of all entry IDs
            entry_ids = self.eyr_file.list_entries()
            
            # Process entries up to limit
            for entry_id in entry_ids[:limit]:
                entry_summary = {'id': entry_id}
                
                # Get full entry to extract summary information
                entry_full = self.get_entry(master_key, entry_id, formatted=False)
                if entry_full:
                    entry_summary['title'] = entry_full.get('title', 'Unknown')
                    entry_summary['username'] = entry_full.get('username', '')
                    entry_summary['category'] = entry_full.get('category', 'General')
                    
                    # Format creation date for display
                    created_at = entry_full.get('created_raw')
                    if created_at:
                        entry_summary['created_at'] = self.format_timestamp(created_at)
                    else:
                        entry_summary['created_at'] = ''
                
                entries.append(entry_summary)
        
        except Exception as e:
            print(f"[-] Error listing entries: {e}")
        
        return entries
    
    def search_entries(self, master_key: bytes, search_term: str) -> List[dict]:
        """
        Search entries by content across multiple fields including category.
        
        Args:
            master_key (bytes): Master encryption key
            search_term (str): Search query (case-insensitive)
        
        Returns:
            List[dict]: List of matching entries with full details.
        
        Search Fields:
            - Title
            - Username
            - URL
            - Notes
            - Category (with flexible matching)
        """
        results = []
        search_lower = search_term.lower()
        
        try:
            self.connect()
            
            if not self.eyr_file.load():
                return results
            
            entry_ids = self.eyr_file.list_entries()
            
            # Normalize search term for category matching
            normalized_search = self._normalize_category_name(search_term)
            
            # Search through all entries
            for entry_id in entry_ids:
                entry_full = self.get_entry(master_key, entry_id, formatted=True)
                if not entry_full:
                    continue
                
                # Check each searchable field for match
                matches = False
                if search_lower in entry_full.get('title', '').lower():
                    matches = True
                elif search_lower in entry_full.get('username', '').lower():
                    matches = True
                elif search_lower in entry_full.get('url', '').lower():
                    matches = True
                elif search_lower in entry_full.get('notes', '').lower():
                    matches = True
                else:
                    # Check category with flexible matching
                    entry_category = entry_full.get('category', '')
                    if entry_category:
                        normalized_category = self._normalize_category_name(entry_category)
                        if normalized_search and normalized_search in normalized_category:
                            matches = True
                
                # If match found, prepare result for display
                if matches:
                    # Create safe copy without password
                    if 'password' in entry_full:
                        entry_copy = entry_full.copy()
                        del entry_copy['password']
                    else:
                        entry_copy = entry_full
                    
                    # Ensure formatted timestamps
                    if 'created_formatted' in entry_copy:
                        entry_copy['created_at'] = entry_copy['created_formatted']
                    else:
                        entry_copy['created_at'] = self.format_datetime(entry_copy.get('created_raw'))
                    
                    if 'updated_formatted' in entry_copy:
                        entry_copy['updated_at'] = entry_copy['updated_formatted']
                    else:
                        entry_copy['updated_at'] = self.format_datetime(entry_copy.get('updated_raw'))
                    
                    results.append(entry_copy)
        
        except Exception as e:
            print(f"[-] Error searching entries: {e}")
        
        return results
    
    def get_entries_by_category(self, master_key: bytes, category: str) -> List[dict]:
        """
        Filter entries by category with flexible matching.
        
        Args:
            master_key (bytes): Master encryption key
            category (str): Category name to filter by (case-insensitive, flexible formatting)
        
        Returns:
            List[dict]: List of entries in the specified category.
        
        Note:
            Category matching is flexible:
            - Case-insensitive
            - Ignores extra spaces and hyphens
            - Normalizes variations (e.g., "socialmedia" matches "Social Media")
        """
        entries = []
        
        try:
            self.connect()
            
            if not self.eyr_file.load():
                return entries
            
            entry_ids = self.eyr_file.list_entries()
            
            # Normalize the search category for flexible matching
            normalized_search = self._normalize_category_name(category)
            
            # Filter entries by category with flexible matching
            for entry_id in entry_ids:
                entry = self.get_entry(master_key, entry_id, formatted=True)
                if entry:
                    entry_category = entry.get('category', 'General')
                    normalized_entry = self._normalize_category_name(entry_category)
                    
                    # Check if normalized categories match
                    if normalized_entry == normalized_search:
                        # Ensure formatted timestamps
                        if 'created_formatted' in entry:
                            entry['created_at'] = entry['created_formatted']
                        else:
                            entry['created_at'] = self.format_datetime(entry.get('created_raw'))
                        
                        if 'updated_formatted' in entry:
                            entry['updated_at'] = entry['updated_formatted']
                        else:
                            entry['updated_at'] = self.format_datetime(entry.get('updated_raw'))
                        
                        entries.append(entry)
        
        except Exception as e:
            print(f"[-] Error filtering by category: {e}")
        
        return entries
    
    def update_entry(self, master_key: bytes, entry_id: int, new_data: dict) -> bool:
        """
        Update an existing entry with new data.
        
        Args:
            master_key (bytes): Master encryption key
            entry_id (int): Entry identifier
            new_data (dict): Updated entry data
        
        Returns:
            bool: True if update succeeded.
        
        Features:
            - Maintains password history when password changes
            - Updates modification timestamp
            - Checks for password reuse in history
            - Limits history size to prevent excessive storage
        """
        try:
            self.connect()
            
            if not self.eyr_file.load():
                return False
            
            # Get current entry data
            current = self.get_entry(master_key, entry_id, formatted=False)
            if not current:
                return False
            
            # Merge current data with updates
            updated_data = current.copy()
            updated_data.update(new_data)
            
            # Update modification timestamp
            current_time = time.time()
            updated_data['updated_at'] = current_time
            
            # Check if password was changed
            old_password = current.get('password', '')
            new_password = new_data.get('password', '')
            
            if new_password and new_password != old_password:
                # Initialize password history if not present
                if 'password_history' not in updated_data:
                    updated_data['password_history'] = []
                
                # Check if new password was previously used
                if self._is_password_in_history(new_password, updated_data.get('password_history', [])):
                    print("[!] Warning: This password has been used before for this entry")
                
                # Add old password to history if it exists
                if old_password:
                    history_entry = {
                        'password': old_password,
                        'masked_password': self.mask_password_partial(old_password),
                        'length': len(old_password),
                        'changed_at': current_time,
                        'version': len(updated_data['password_history']) + 1
                    }
                    updated_data['password_history'].insert(0, history_entry)  # Add to beginning
                
                # Limit history size (keep last 10 passwords)
                max_history = 10
                if len(updated_data['password_history']) > max_history:
                    updated_data['password_history'] = updated_data['password_history'][:max_history]
            
            # Remove internal metadata fields before encryption
            for field in ['id', 'category', 'created_raw', 'updated_raw']:
                updated_data.pop(field, None)
            
            # Encrypt updated entry
            encrypted = encrypt_entry(master_key, updated_data, entry_id)
            
            # Update storage structure
            entry_storage = {
                'encrypted_data': encrypted,
                'category': new_data.get('category', current.get('category', 'General')),
                'created_at': current.get('created_raw', current_time),
                'updated_at': current_time
            }
            
            # Serialize and store
            entry_json = json.dumps(entry_storage, ensure_ascii=False)
            entry_bytes = entry_json.encode('utf-8')
            
            return self.eyr_file.update_entry(entry_id, entry_bytes)
            
        except Exception as e:
            print(f"[-] Error updating entry: {e}")
            return False
    
    def delete_entry(self, entry_id: int) -> bool:
        """
        Permanently remove an entry from the vault.
        
        Args:
            entry_id (int): Entry identifier
        
        Returns:
            bool: True if deletion succeeded.
        
        Security Note:
            The entry is removed from the vault file. Consider implementing
            secure deletion that overwrites the entry data.
        """
        try:
            self.connect()
            
            if not self.eyr_file.load():
                return False
            
            return self.eyr_file.delete_entry(entry_id)
            
        except Exception as e:
            print(f"[-] Error deleting entry: {e}")
            return False
    
    # ==========================================================================
    # VAULT MANAGEMENT OPERATIONS
    # ==========================================================================
    
    def change_master_key(self, old_key: bytes, new_key: bytes) -> bool:
        """
        Re-encrypt all entries with a new master key.
        
        Args:
            old_key (bytes): Current master key
            new_key (bytes): New master key
        
        Returns:
            bool: True if all entries were successfully re-encrypted.
        
        Process:
            1. Decrypt each entry with old key
            2. Re-encrypt with new key
            3. Update verification token in metadata
            4. Persist changes
        
        Security Note:
            This operation requires access to both old and new keys simultaneously.
            Consider implementing a progressive re-encryption for large vaults.
        """
        try:
            self.connect()
            
            if not self.eyr_file.load():
                return False
            
            # Get list of all entry IDs
            entry_ids = self.eyr_file.list_entries()
            
            # Re-encrypt each entry
            for entry_id in entry_ids:
                entry_data = self.get_entry(old_key, entry_id, formatted=False)
                if not entry_data:
                    return False  # Failed to decrypt an entry
                
                # Remove internal fields before re-encryption
                for field in ['id', 'category', 'created_raw', 'updated_raw']:
                    entry_data.pop(field, None)
                
                # Re-encrypt with new key
                encrypted = encrypt_entry(new_key, entry_data, entry_id)
                
                # Update entry in vault
                entry_bytes = self.eyr_file.get_entry(entry_id)
                if entry_bytes:
                    entry_storage = json.loads(entry_bytes.decode('utf-8'))
                    entry_storage['encrypted_data'] = encrypted
                    updated_bytes = json.dumps(entry_storage, ensure_ascii=False).encode('utf-8')
                    
                    if not self.eyr_file.update_entry(entry_id, updated_bytes):
                        return False  # Failed to update entry
                        # Update verification token in metadata with new key
            verification_token = os.urandom(32)
            encryption_key = new_key[:KEY_SIZE]
            nonce, ciphertext, tag = encrypt_data(encryption_key, verification_token)
            
            self.eyr_file.metadata['verification_token'] = base64.b64encode(ciphertext).decode('ascii')
            self.eyr_file.metadata['verification_nonce'] = base64.b64encode(nonce).decode('ascii')
            self.eyr_file.metadata['verification_tag'] = base64.b64encode(tag).decode('ascii')
            self.eyr_file.update_metadata()
            
            print("[+] All entries re-encrypted with new key")
            return True
            
        except Exception as e:
            print(f"[-] Error changing master key: {e}")
            return False
    
    def get_vault_info(self, master_key: bytes) -> Optional[dict]:
        """
        Generate vault statistics and metadata.
        
        Args:
            master_key (bytes): Master encryption key (to access entries)
        
        Returns:
            Optional[dict]: Vault information including:
                - categories: Count of entries per category
                - total_entries: Total number of entries
                - version: Vault format version
                - created_at: Vault creation timestamp (formatted)
        """
        try:
            self.connect()
            
            if not self.eyr_file.load():
                return None
            
            info = {}
            
            # Count entries by category
            categories = {}
            entry_ids = self.eyr_file.list_entries()
            
            for entry_id in entry_ids:
                entry = self.get_entry(master_key, entry_id, formatted=False)
                if entry:
                    category = entry.get('category', 'General')
                    categories[category] = categories.get(category, 0) + 1
            
            info['categories'] = categories
            info['total_entries'] = len(entry_ids)
            
            # Add vault metadata
            if self.eyr_file.metadata:
                info['version'] = self.eyr_file.metadata.get('version')
                info['created_at'] = self.format_datetime(self.eyr_file.metadata.get('created_at'))
            
            return info
            
        except Exception:
            return None
    
    # ==========================================================================
    # PASSWORD HISTORY MANAGEMENT
    # ==========================================================================
    
    def get_password_history(self, master_key: bytes, entry_id: int) -> Optional[List[Dict]]:
        """
        Retrieve password history for an entry with masked passwords.
        
        Args:
            master_key (bytes): Master encryption key
            entry_id (int): Entry identifier
        
        Returns:
            Optional[List[Dict]]: List of historical password entries with:
                - masked_password: Partially masked password
                - length: Password length
                - changed_at_formatted: Formatted timestamp
                - index: Display index
        
        Security Note:
            Actual passwords are removed from the returned data for security.
        """
        try:
            entry = self.get_entry(master_key, entry_id, formatted=False)
            if not entry:
                return None
            
            history = entry.get('password_history', [])
            
            # Format history entries for display
            formatted_history = []
            for i, item in enumerate(history, 1):
                formatted_item = item.copy()
                
                # Ensure masked password exists
                if 'masked_password' not in formatted_item and 'password' in formatted_item:
                    formatted_item['masked_password'] = self.mask_password_partial(formatted_item['password'])
                
                # Ensure length exists
                if 'length' not in formatted_item and 'password' in formatted_item:
                    formatted_item['length'] = len(formatted_item['password'])
                
                # Format timestamp
                changed_at = item.get('changed_at')
                if changed_at:
                    try:
                        formatted_item['changed_at_formatted'] = datetime.fromtimestamp(changed_at).strftime("%Y-%m-%d %H:%M:%S")
                    except:
                        formatted_item['changed_at_formatted'] = str(changed_at)
                
                formatted_item['index'] = i  # Display index
                
                # Remove actual password for security
                if 'password' in formatted_item:
                    del formatted_item['password']
                
                formatted_history.append(formatted_item)
            
            return formatted_history
            
        except Exception as e:
            print(f"[-] Error retrieving password history: {e}")
            return None
    
    def get_password_history_with_passwords(self, master_key: bytes, entry_id: int) -> Optional[List[Dict]]:
        """
        Retrieve password history for an entry WITH plaintext passwords.
        
        Args:
            master_key (bytes): Master encryption key
            entry_id (int): Entry identifier
        
        Returns:
            Optional[List[Dict]]: List of password entries including:
                - password: Plaintext password
                - masked_password: Partially masked password
                - length: Password length
                - changed_at_formatted: Formatted timestamp
                - version: Password version number
                - is_current: Boolean indicating if this is the current password
        
        Security Warning:
            This method returns actual passwords. Use only when explicitly needed
            and ensure proper authentication and authorization.
        """
        try:
            entry = self.get_entry(master_key, entry_id, formatted=False)
            if not entry:
                return None
            
            history = entry.get('password_history', [])
            current_password = entry.get('password', '')
            
            # Format history with plaintext passwords
            formatted_history = []
            
            # Handle edge case: fresh entry with no history but current password
            if current_password and len(history) == 0:
                current_item = {
                    'password': current_password,
                    'masked_password': self.mask_password_partial(current_password),
                    'length': len(current_password),
                    'changed_at': entry.get('created_at', time.time()),  # Use creation time
                    'version': 1,
                    'is_current': True
                }
                
                # Format timestamp
                changed_at = current_item.get('changed_at')
                if changed_at:
                    try:
                        current_item['changed_at_formatted'] = datetime.fromtimestamp(changed_at).strftime("%Y-%m-%d %H:%M:%S")
                    except:
                        current_item['changed_at_formatted'] = str(changed_at)
                
                formatted_history.append(current_item)
            
            # Add actual history items (old passwords)
            for i, item in enumerate(history, 1):
                formatted_item = item.copy()
                
                # Get plaintext password
                password = item.get('password', '')
                if password:
                    formatted_item['password'] = password
                    formatted_item['masked_password'] = self.mask_password_partial(password)
                else:
                    formatted_item['password'] = ''  # Handle missing password
                
                # Ensure length exists
                if 'length' not in formatted_item and 'password' in formatted_item:
                    formatted_item['length'] = len(formatted_item['password'])
                
                # Format timestamp
                changed_at = item.get('changed_at')
                if changed_at:
                    try:
                        formatted_item['changed_at_formatted'] = datetime.fromtimestamp(changed_at).strftime("%Y-%m-%d %H:%M:%S")
                    except:
                        formatted_item['changed_at_formatted'] = str(changed_at)
                
                formatted_item['version'] = i + 1  # History items start from version 2
                formatted_item['is_current'] = False  # History items are never current
                
                formatted_history.append(formatted_item)
            
            # Handle case with history: add current password as version 1
            if current_password and len(history) > 0 and not any(item.get('is_current', False) for item in formatted_history):
                current_item = {
                    'password': current_password,
                    'masked_password': self.mask_password_partial(current_password),
                    'length': len(current_password),
                    'changed_at': entry.get('updated_at', time.time()),  # Use update time
                    'version': 1,
                    'is_current': True
                }
                
                # Format timestamp
                changed_at = current_item.get('changed_at')
                if changed_at:
                    try:
                        current_item['changed_at_formatted'] = datetime.fromtimestamp(changed_at).strftime("%Y-%m-%d %H:%M:%S")
                    except:
                        current_item['changed_at_formatted'] = str(changed_at)
                
                formatted_history.insert(0, current_item)  # Add current password at beginning
            
            return formatted_history
            
        except Exception as e:
            print(f"[-] Error retrieving password history with passwords: {e}")
            return None
    
    def clear_password_history(self, master_key: bytes, entry_id: int) -> bool:
        """
        Clear all password history for an entry.
        
        Args:
            master_key (bytes): Master encryption key
            entry_id (int): Entry identifier
        
        Returns:
            bool: True if history was successfully cleared.
        
        Security Note:
            This operation is irreversible. Consider implementing an archive
            or backup before clearing history.
        """
        try:
            self.connect()
            
            if not self.eyr_file.load():
                return False
            
            current = self.get_entry(master_key, entry_id, formatted=False)
            if not current:
                return False
            
            # Clear password history
            if 'password_history' in current:
                current['password_history'] = []
            
            # Update modification timestamp
            current_time = time.time()
            current['updated_at'] = current_time
            
            # Remove internal fields
            for field in ['id', 'category', 'created_raw', 'updated_raw']:
                current.pop(field, None)
            
            # Re-encrypt entry without history
            encrypted = encrypt_entry(master_key, current, entry_id)
            
            # Update storage
            entry_storage = {
                'encrypted_data': encrypted,
                'category': current.get('category', 'General'),
                'created_at': current.get('created_raw', current_time),
                'updated_at': current_time
            }
            
            entry_json = json.dumps(entry_storage, ensure_ascii=False)
            entry_bytes = entry_json.encode('utf-8')
            
            return self.eyr_file.update_entry(entry_id, entry_bytes)
            
        except Exception as e:
            print(f"[-] Error clearing password history: {e}")
            return False
    
    def _is_password_in_history(self, password: str, history: List[Dict]) -> bool:
        """
        Check if a password exists in the history.
        
        Args:
            password (str): Password to check
            history (List[Dict]): Password history list
        
        Returns:
            bool: True if password is found in history.
        
        Note:
            This is a helper method used during password updates to warn
            users about password reuse.
        """
        for item in history:
            if item.get('password') == password:
                return True
        return False
    
    # ==========================================================================
    # HELPER METHODS
    # ==========================================================================
    
    def _encrypt_field(self, key: bytes, data: bytes) -> dict:
        """
        Encrypt a single field with AES-GCM.
        
        Args:
            key (bytes): Encryption key
            data (bytes): Data to encrypt
        
        Returns:
            dict: Dictionary containing base64-encoded:
                - ciphertext: Encrypted data
                - nonce: Encryption nonce
                - tag: Authentication tag
        
        Note:
            This is a helper method for field-level encryption operations.
        """
        from .crypto import encrypt_data
        nonce, ciphertext, tag = encrypt_data(key, data)
        return {
            'ciphertext': base64.b64encode(ciphertext).decode('ascii'),
            'nonce': base64.b64encode(nonce).decode('ascii'),
            'tag': base64.b64encode(tag).decode('ascii')
        }