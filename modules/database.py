"""
Eyrie Database Operations - EYR Vault Format

This module provides the database interface for the Eyrie password manager,
handling all CRUD operations on the encrypted EYR vault format. It manages
entry encryption/decryption, metadata operations.
"""

import json
import base64
import os
import time
import shutil
import re
import random
import string
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
    - CRUD operations on secure notes
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
    # ID GENERATION AND MANAGEMENT
    # ==========================================================================
    
    @staticmethod
    def generate_entry_id() -> str:
        """
        Generate a unique entry ID in the format: EYR-XXXXXX
        
        Returns:
            str: Unique entry ID (e.g., EYR-A9F3Q2)
        
        Format:
            - Prefix: "EYR-"
            - 6 characters: Uppercase letters (A-Z) and digits (0-9)
            - Total length: 10 characters (including prefix and hyphen)
        
        Example IDs:
            EYR-A9F3Q2, EYR-Z8Y4B1, EYR-7C2D9F, EYR-K5L8M3
        """
        # Generate 6 random characters from uppercase letters and digits
        chars = string.ascii_uppercase + string.digits
        random_chars = ''.join(random.choices(chars, k=6))
        return f"EYR-{random_chars}"
    
    def generate_unique_entry_id(self, existing_ids: set) -> str:
        """
        Generate a unique entry ID that doesn't exist in the provided set.
        
        Args:
            existing_ids (set): Set of existing entry IDs to avoid collisions
            
        Returns:
            str: Unique entry ID not present in existing_ids
        """
        max_attempts = 100  # Prevent infinite loop
        for _ in range(max_attempts):
            new_id = self.generate_entry_id()
            if new_id not in existing_ids:
                return new_id
        
        # If we can't find a unique ID after max_attempts, use a timestamp-based ID
        timestamp = int(time.time() % 1000000)
        return f"EYR-T{timestamp:06d}"
    
    def get_all_entry_ids(self) -> set:
        """
        Get all existing entry IDs from the vault.
        
        Returns:
            set: Set of all entry IDs currently in the vault
        """
        existing_ids = set()
        try:
            self.connect()
            if self.eyr_file.load():
                # Get all entries and extract their IDs
                entry_ids = self.eyr_file.list_entries()
                for entry_id in entry_ids:
                    entry_bytes = self.eyr_file.get_entry(entry_id)
                    if entry_bytes:
                        try:
                            entry_storage = json.loads(entry_bytes.decode('utf-8'))
                            # Check if it has a custom ID field
                            if 'entry_id' in entry_storage:
                                existing_ids.add(entry_storage['entry_id'])
                        except:
                            continue
        except Exception:
            pass
        return existing_ids
    
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
                entry_bytes = self.eyr_file.get_entry(entry_id)
                if not entry_bytes:
                    continue
                    
                try:
                    entry_storage = json.loads(entry_bytes.decode('utf-8'))
                    
                    # Skip notes if we only want password entry categories
                    if entry_storage.get('entry_type') == 'note':
                        continue
                        
                    # Get entry data for category
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
                except:
                    continue
        
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
            
            # Entry counter for generating unique entry IDs (still used for internal indexing)
            'entry_counter': 1,
        }
        
        # Create the vault file with metadata
        if self.eyr_file.create(metadata):
            print(f"[+] EYR vault created: {self.db_path}")
            self.next_entry_id = 1
            return True
        
        print("[-] Failed to create EYR vault")
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
    # PASSWORD ENTRY MANAGEMENT - CRUD OPERATIONS
    # ==========================================================================
    
    def add_entry(self, master_key: bytes, entry_data: dict) -> Optional[str]:
        """
        Add a new password entry to the vault.
        
        Args:
            master_key (bytes): Master encryption key
            entry_data (dict): Entry data including title, username, password, etc.
        
        Returns:
            Optional[str]: Assigned entry ID (e.g., "EYR-A9F3Q2") if successful, None otherwise.
        
        Security Notes:
            - Entry data is encrypted with entry-specific additional authenticated data
            - Password history is initialized as empty (only populated on changes)
            - Timestamps are added for creation and modification tracking
        """
        try:
            self.connect()
            
            if not self.eyr_file.load():
                return None
            
            # Get next available internal entry ID from metadata
            internal_entry_id = self.eyr_file.metadata.get('entry_counter', 1)
            
            # Generate unique display ID in format EYR-XXXXXX
            existing_ids = self.get_all_entry_ids()
            display_entry_id = self.generate_unique_entry_id(existing_ids)
            
            # Add timestamps and IDs to entry data
            current_time = time.time()
            entry_data_with_timestamps = entry_data.copy()
            entry_data_with_timestamps['created_at'] = current_time
            entry_data_with_timestamps['updated_at'] = current_time
            entry_data_with_timestamps['entry_type'] = 'password'  # Mark as password type
            entry_data_with_timestamps['display_id'] = display_entry_id  # Add display ID
            
            # Initialize empty password history
            # Current password is NOT added to history here - only old passwords go in history
            entry_data_with_timestamps['password_history'] = []
            
            # Encrypt the complete entry data
            encrypted = encrypt_entry(master_key, entry_data_with_timestamps, internal_entry_id)
            
            # Build storage structure with additional metadata
            entry_storage = {
                'encrypted_data': encrypted,  # The encrypted entry
                'category': entry_data.get('category', 'General'),
                'entry_type': 'password',  # Mark as password type
                'entry_id': display_entry_id,  # Store the display ID
                'internal_id': internal_entry_id,  # Store internal ID for backward compatibility
                'created_at': current_time,
                'updated_at': current_time
            }
            
            # Serialize to JSON and encode to bytes
            entry_json = json.dumps(entry_storage, ensure_ascii=False)
            entry_bytes = entry_json.encode('utf-8')
            
            # Store entry in vault using internal ID for indexing
            if self.eyr_file.add_entry(internal_entry_id, entry_bytes):
                # Increment entry counter in metadata
                self.eyr_file.metadata['entry_counter'] = internal_entry_id + 1
                self.eyr_file.update_metadata()
                
                print(f"[+] Entry added (ID: {display_entry_id})")
                return display_entry_id
            
            return None  # Entry addition failed
            
        except Exception as e:
            print(f"[-] Error adding entry: {e}")
            return None
    
    def _get_entry_by_display_id(self, master_key: bytes, display_id: str, formatted: bool = True) -> Optional[dict]:
        """
        Internal method to find and retrieve an entry by its display ID.
        
        Args:
            master_key (bytes): Master encryption key
            display_id (str): Display ID (e.g., "EYR-A9F3Q2")
            formatted (bool): If True, include formatted timestamps
        
        Returns:
            Optional[dict]: Decrypted entry data with metadata, or None if not found.
        """
        try:
            self.connect()
            
            if not self.eyr_file.load():
                return None
            
            # Search through all entries to find the one with matching display ID
            entry_ids = self.eyr_file.list_entries()
            
            for internal_entry_id in entry_ids:
                entry_bytes = self.eyr_file.get_entry(internal_entry_id)
                if not entry_bytes:
                    continue
                
                try:
                    entry_storage = json.loads(entry_bytes.decode('utf-8'))
                    
                    # Check if this is a password entry with matching display ID
                    if (entry_storage.get('entry_type') == 'password' and 
                        entry_storage.get('entry_id') == display_id):
                        
                        encrypted_data = entry_storage.get('encrypted_data', {})
                        
                        # Decrypt entry data
                        entry_data = decrypt_entry(master_key, encrypted_data)
                        if not entry_data:
                            return None
                        
                        # Add metadata fields
                        entry_data['id'] = display_id  # Use display ID as the ID
                        entry_data['internal_id'] = internal_entry_id  # Store internal ID for reference
                        entry_data['category'] = entry_storage.get('category', 'General')
                        entry_data['entry_type'] = 'password'
                        
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
                        
                except:
                    continue  # Skip invalid entries
            
            return None  # No entry found with the given display ID
            
        except Exception as e:
            print(f"[-] Error retrieving entry by display ID {display_id}: {e}")
            return None
    
    def get_entry(self, master_key: bytes, entry_id: str, formatted: bool = True) -> Optional[dict]:
        """
        Retrieve and decrypt a password entry by ID.
        
        Args:
            master_key (bytes): Master encryption key
            entry_id (str): Entry identifier (can be display ID like "EYR-A9F3Q2" or internal ID as string)
            formatted (bool): If True, include formatted timestamps
        
        Returns:
            Optional[dict]: Decrypted entry data with metadata, or None if not found.
        
        Note:
            The entry includes both raw timestamps (for internal use) and
            optionally formatted timestamps (for display).
        """
        # Check if entry_id is a display ID (starts with "EYR-")
        if isinstance(entry_id, str) and entry_id.startswith("EYR-"):
            return self._get_entry_by_display_id(master_key, entry_id, formatted)
        
        # Otherwise, assume it's an internal ID (for backward compatibility)
        try:
            internal_id = int(entry_id)
            return self._get_entry_by_internal_id(master_key, internal_id, formatted)
        except (ValueError, TypeError):
            return None
    
    def _get_entry_by_internal_id(self, master_key: bytes, internal_entry_id: int, formatted: bool = True) -> Optional[dict]:
        """
        Internal method to retrieve an entry by its internal ID (for backward compatibility).
        
        Args:
            master_key (bytes): Master encryption key
            internal_entry_id (int): Internal entry identifier
            formatted (bool): If True, include formatted timestamps
        
        Returns:
            Optional[dict]: Decrypted entry data with metadata, or None if not found.
        """
        try:
            self.connect()
            
            if not self.eyr_file.load():
                return None
            
            # Retrieve raw entry bytes from vault
            entry_bytes = self.eyr_file.get_entry(internal_entry_id)
            if not entry_bytes:
                return None
            
            # Parse storage structure
            entry_storage = json.loads(entry_bytes.decode('utf-8'))
            
            # Check if this is actually a password entry
            if entry_storage.get('entry_type') != 'password':
                return None  # This is not a password entry
            
            encrypted_data = entry_storage.get('encrypted_data', {})
            
            # Decrypt entry data
            entry_data = decrypt_entry(master_key, encrypted_data)
            if not entry_data:
                return None
            
            # Add metadata fields
            # Use display ID if available, otherwise use internal ID as string
            display_id = entry_storage.get('entry_id')
            if display_id:
                entry_data['id'] = display_id
            else:
                entry_data['id'] = str(internal_entry_id)  # Fallback to internal ID
            
            entry_data['internal_id'] = internal_entry_id  # Store internal ID for reference
            entry_data['category'] = entry_storage.get('category', 'General')
            entry_data['entry_type'] = 'password'
            
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
            print(f"[-] Error retrieving entry by internal ID {internal_entry_id}: {e}")
            return None
    
    def list_entries(self, master_key: bytes, limit: int = 1000) -> List[dict]:
        """
        List all password entries in the vault (excluding notes).
        
        Args:
            master_key (bytes): Master encryption key
            limit (int): Maximum number of entries to return
        
        Returns:
            List[dict]: List of password entry summaries (ID, title, username, category, creation date).
        """
        entries = []
        
        try:
            self.connect()
            
            if not self.eyr_file.load():
                return entries
            
            # Get list of all entry IDs
            internal_entry_ids = self.eyr_file.list_entries()
            
            # Process entries up to limit
            for internal_entry_id in internal_entry_ids[:limit]:
                # Check entry type first without full decryption
                entry_bytes = self.eyr_file.get_entry(internal_entry_id)
                if not entry_bytes:
                    continue
                    
                try:
                    entry_storage = json.loads(entry_bytes.decode('utf-8'))
                    # Skip notes
                    if entry_storage.get('entry_type') == 'note':
                        continue
                except:
                    continue  # Skip invalid entries
                
                entry_summary = {'internal_id': internal_entry_id}
                
                # Get the display ID from storage
                display_id = entry_storage.get('entry_id')
                if display_id:
                    entry_summary['id'] = display_id
                else:
                    entry_summary['id'] = str(internal_entry_id)  # Fallback
                
                # Get full entry to extract summary information
                entry_full = self.get_entry(master_key, entry_summary['id'], formatted=False)
                if entry_full:
                    entry_summary['title'] = entry_full.get('title', 'Unknown')
                    entry_summary['username'] = entry_full.get('username', '')
                    entry_summary['category'] = entry_full.get('category', 'General')
                    entry_summary['entry_type'] = 'password'
                    
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
        Search password entries by content across multiple fields including category.
        
        Args:
            master_key (bytes): Master encryption key
            search_term (str): Search query (case-insensitive)
        
        Returns:
            List[dict]: List of matching password entries with full details.
        
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
            
            internal_entry_ids = self.eyr_file.list_entries()
            
            # Normalize search term for category matching
            normalized_search = self._normalize_category_name(search_term)
            
            # Search through all entries
            for internal_entry_id in internal_entry_ids:
                # Check entry type first
                entry_bytes = self.eyr_file.get_entry(internal_entry_id)
                if entry_bytes:
                    try:
                        entry_storage = json.loads(entry_bytes.decode('utf-8'))
                        # Skip notes in password search
                        if entry_storage.get('entry_type') == 'note':
                            continue
                    except:
                        continue  # Skip invalid entries
                
                # Get display ID
                display_id = entry_storage.get('entry_id', str(internal_entry_id))
                entry_full = self.get_entry(master_key, display_id, formatted=True)
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
        Filter password entries by category with flexible matching.
        
        Args:
            master_key (bytes): Master encryption key
            category (str): Category name to filter by (case-insensitive, flexible formatting)
        
        Returns:
            List[dict]: List of password entries in the specified category.
        
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
            
            internal_entry_ids = self.eyr_file.list_entries()
            
            # Normalize the search category for flexible matching
            normalized_search = self._normalize_category_name(category)
            
            # Filter entries by category with flexible matching
            for internal_entry_id in internal_entry_ids:
                # Check entry type first
                entry_bytes = self.eyr_file.get_entry(internal_entry_id)
                if entry_bytes:
                    try:
                        entry_storage = json.loads(entry_bytes.decode('utf-8'))
                        # Skip notes
                        if entry_storage.get('entry_type') == 'note':
                            continue
                    except:
                        continue  # Skip invalid entries
                
                # Get display ID
                display_id = entry_storage.get('entry_id', str(internal_entry_id))
                entry = self.get_entry(master_key, display_id, formatted=True)
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
    
    def update_entry(self, master_key: bytes, entry_id: str, new_data: dict) -> bool:
        """
        Update an existing password entry with new data.
        
        Args:
            master_key (bytes): Master encryption key
            entry_id (str): Entry identifier (display ID like "EYR-A9F3Q2")
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
            
            # Get internal ID from current entry
            internal_entry_id = current.get('internal_id')
            if not internal_entry_id:
                return False
            
            # Merge current data with updates
            updated_data = current.copy()
            updated_data.update(new_data)
            
            # Update modification timestamp
            current_time = time.time()
            updated_data['updated_at'] = current_time
            updated_data['entry_type'] = 'password'  # Ensure type is preserved
            
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
            for field in ['id', 'internal_id', 'category', 'created_raw', 'updated_raw']:
                updated_data.pop(field, None)
            
            # Encrypt updated entry
            encrypted = encrypt_entry(master_key, updated_data, internal_entry_id)
            
            # Get current storage to preserve other fields
            entry_bytes = self.eyr_file.get_entry(internal_entry_id)
            if not entry_bytes:
                return False
            
            entry_storage = json.loads(entry_bytes.decode('utf-8'))
            
            # Update storage structure
            entry_storage['encrypted_data'] = encrypted
            entry_storage['category'] = new_data.get('category', current.get('category', 'General'))
            entry_storage['entry_type'] = 'password'
            entry_storage['updated_at'] = current_time
            
            # Serialize and store
            entry_json = json.dumps(entry_storage, ensure_ascii=False)
            entry_bytes = entry_json.encode('utf-8')
            
            return self.eyr_file.update_entry(internal_entry_id, entry_bytes)
            
        except Exception as e:
            print(f"[-] Error updating entry: {e}")
            return False
    
    def delete_entry(self, entry_id: str) -> bool:
        """
        Permanently remove an entry (password or note) from the vault.
        
        Args:
            entry_id (str): Entry identifier (display ID like "EYR-A9F3Q2")
        
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
            
            # Find the internal ID for the given display ID
            internal_entry_ids = self.eyr_file.list_entries()
            target_internal_id = None
            
            for internal_entry_id in internal_entry_ids:
                entry_bytes = self.eyr_file.get_entry(internal_entry_id)
                if entry_bytes:
                    try:
                        entry_storage = json.loads(entry_bytes.decode('utf-8'))
                        if entry_storage.get('entry_id') == entry_id:
                            target_internal_id = internal_entry_id
                            break
                    except:
                        continue
            
            # If not found by display ID, try as internal ID
            if target_internal_id is None:
                try:
                    # Check if entry_id is an internal ID
                    target_internal_id = int(entry_id)
                    # Verify it exists
                    entry_bytes = self.eyr_file.get_entry(target_internal_id)
                    if not entry_bytes:
                        return False
                except (ValueError, TypeError):
                    return False  # Not a valid ID format
            
            return self.eyr_file.delete_entry(target_internal_id)
            
        except Exception as e:
            print(f"[-] Error deleting entry: {e}")
            return False

    # ==============================================================================
    # NOTES MANAGEMENT
    # ==============================================================================

    def add_note(self, master_key: bytes, note_data: dict) -> Optional[str]:
        """
        Add a new secure note to the vault.
    
        Args:
            master_key (bytes): Master encryption key
            note_data (dict): Note data including title, content, category, etc.
    
        Returns:
            Optional[str]: Assigned entry ID (e.g., "EYR-A9F3Q2") if successful, None otherwise.
    
        Note:
            Notes are stored similarly to password entries but with different structure and content handling.
        """
        try:
            self.connect()
        
            if not self.eyr_file.load():
                return None
        
            # Get next available internal entry ID from metadata
            internal_entry_id = self.eyr_file.metadata.get('entry_counter', 1)
            
            # Generate unique display ID in format EYR-XXXXXX
            existing_ids = self.get_all_entry_ids()
            display_entry_id = self.generate_unique_entry_id(existing_ids)
        
            # Add timestamps and IDs to note data
            current_time = time.time()
            note_data_with_timestamps = note_data.copy()
            note_data_with_timestamps['created_at'] = current_time
            note_data_with_timestamps['updated_at'] = current_time
            note_data_with_timestamps['entry_type'] = 'note'  # Mark as note type
            note_data_with_timestamps['display_id'] = display_entry_id  # Add display ID

            # Encrypt the complete note data
            encrypted = encrypt_entry(master_key, note_data_with_timestamps, internal_entry_id)
        
            # Build storage structure with additional metadata
            entry_storage = {
                'encrypted_data': encrypted,  # The encrypted note
                'category': note_data.get('category', 'Notes'),
                'entry_type': 'note',  # Mark as note type
                'entry_id': display_entry_id,  # Store the display ID
                'internal_id': internal_entry_id,  # Store internal ID for backward compatibility
                'created_at': current_time,
                'updated_at': current_time
            }
        
            # Serialize to JSON and encode to bytes
            entry_json = json.dumps(entry_storage, ensure_ascii=False)
            entry_bytes = entry_json.encode('utf-8')
        
            # Store note in vault using internal ID for indexing
            if self.eyr_file.add_entry(internal_entry_id, entry_bytes):
                # Increment entry counter in metadata
                self.eyr_file.metadata['entry_counter'] = internal_entry_id + 1
                self.eyr_file.update_metadata()
            
                print(f"[+] Note added (ID: {display_entry_id})")
                return display_entry_id
        
            return None  # Note addition failed
        
        except Exception as e:
            print(f"[-] Error adding note: {e}")
            return None

    def get_note(self, master_key: bytes, entry_id: str, formatted: bool = True) -> Optional[dict]:
        """
        Retrieve and decrypt a note by ID.
    
        Args:
            master_key (bytes): Master encryption key
            entry_id (str): Entry identifier (display ID like "EYR-A9F3Q2")
            formatted (bool): If True, include formatted timestamps
    
        Returns:
            Optional[dict]: Decrypted note data with metadata, or None if not found.
        """
        # Check if entry_id is a display ID (starts with "EYR-")
        if isinstance(entry_id, str) and entry_id.startswith("EYR-"):
            return self._get_note_by_display_id(master_key, entry_id, formatted)
        
        # Otherwise, assume it's an internal ID (for backward compatibility)
        try:
            internal_id = int(entry_id)
            return self._get_note_by_internal_id(master_key, internal_id, formatted)
        except (ValueError, TypeError):
            return None
    
    def _get_note_by_display_id(self, master_key: bytes, display_id: str, formatted: bool = True) -> Optional[dict]:
        """
        Internal method to find and retrieve a note by its display ID.
        
        Args:
            master_key (bytes): Master encryption key
            display_id (str): Display ID (e.g., "EYR-A9F3Q2")
            formatted (bool): If True, include formatted timestamps
        
        Returns:
            Optional[dict]: Decrypted note data with metadata, or None if not found.
        """
        try:
            self.connect()
            
            if not self.eyr_file.load():
                return None
            
            # Search through all entries to find the one with matching display ID
            entry_ids = self.eyr_file.list_entries()
            
            for internal_entry_id in entry_ids:
                entry_bytes = self.eyr_file.get_entry(internal_entry_id)
                if not entry_bytes:
                    continue
                
                try:
                    entry_storage = json.loads(entry_bytes.decode('utf-8'))
                    
                    # Check if this is a note with matching display ID
                    if (entry_storage.get('entry_type') == 'note' and 
                        entry_storage.get('entry_id') == display_id):
                        
                        encrypted_data = entry_storage.get('encrypted_data', {})
                        
                        # Decrypt note data
                        note_data = decrypt_entry(master_key, encrypted_data)
                        if not note_data:
                            return None
                        
                        # Add metadata fields
                        note_data['id'] = display_id  # Use display ID as the ID
                        note_data['internal_id'] = internal_entry_id  # Store internal ID for reference
                        note_data['category'] = entry_storage.get('category', 'Notes')
                        note_data['entry_type'] = 'note'
                        
                        # Handle timestamps with storage data taking precedence
                        storage_created = entry_storage.get('created_at')
                        decrypted_created = note_data.get('created_at')
                        note_data['created_at'] = storage_created if storage_created is not None else decrypted_created
                        note_data['updated_at'] = entry_storage.get('updated_at', note_data.get('updated_at'))
                        
                        # Store raw timestamps for internal use
                        note_data['created_raw'] = note_data.get('created_at')
                        note_data['updated_raw'] = note_data.get('updated_at')
                        
                        # Add formatted timestamps for display if requested
                        if formatted:
                            note_data['created_formatted'] = self.format_datetime(note_data.get('created_at'))
                            note_data['updated_formatted'] = self.format_datetime(note_data.get('updated_at'))
                        
                        return note_data
                        
                except:
                    continue  # Skip invalid entries
            
            return None  # No note found with the given display ID
            
        except Exception as e:
            print(f"[-] Error retrieving note by display ID {display_id}: {e}")
            return None
    
    def _get_note_by_internal_id(self, master_key: bytes, internal_entry_id: int, formatted: bool = True) -> Optional[dict]:
        """
        Internal method to retrieve a note by its internal ID (for backward compatibility).
        
        Args:
            master_key (bytes): Master encryption key
            internal_entry_id (int): Internal entry identifier
            formatted (bool): If True, include formatted timestamps
        
        Returns:
            Optional[dict]: Decrypted note data with metadata, or None if not found.
        """
        try:
            self.connect()
            
            if not self.eyr_file.load():
                return None
            
            # Retrieve raw entry bytes from vault
            entry_bytes = self.eyr_file.get_entry(internal_entry_id)
            if not entry_bytes:
                return None
            
            # Parse storage structure
            entry_storage = json.loads(entry_bytes.decode('utf-8'))
            
            # Check if this is actually a note
            if entry_storage.get('entry_type') != 'note':
                return None  # This is not a note
            
            encrypted_data = entry_storage.get('encrypted_data', {})
            
            # Decrypt note data
            note_data = decrypt_entry(master_key, encrypted_data)
            if not note_data:
                return None
            
            # Add metadata fields
            # Use display ID if available, otherwise use internal ID as string
            display_id = entry_storage.get('entry_id')
            if display_id:
                note_data['id'] = display_id
            else:
                note_data['id'] = str(internal_entry_id)  # Fallback to internal ID
            
            note_data['internal_id'] = internal_entry_id  # Store internal ID for reference
            note_data['category'] = entry_storage.get('category', 'Notes')
            note_data['entry_type'] = 'note'
            
            # Handle timestamps with storage data taking precedence
            storage_created = entry_storage.get('created_at')
            decrypted_created = note_data.get('created_at')
            note_data['created_at'] = storage_created if storage_created is not None else decrypted_created
            note_data['updated_at'] = entry_storage.get('updated_at', note_data.get('updated_at'))
            
            # Store raw timestamps for internal use
            note_data['created_raw'] = note_data.get('created_at')
            note_data['updated_raw'] = note_data.get('updated_at')
            
            # Add formatted timestamps for display if requested
            if formatted:
                note_data['created_formatted'] = self.format_datetime(note_data.get('created_at'))
                note_data['updated_formatted'] = self.format_datetime(note_data.get('updated_at'))
            
            return note_data
            
        except Exception as e:
            print(f"[-] Error retrieving note by internal ID {internal_entry_id}: {e}")
            return None

    def list_notes(self, master_key: bytes, limit: int = 1000) -> List[dict]:
        """
        List all vault notes with basic information.
    
        Args:
            master_key (bytes): Master encryption key
            limit (int): Maximum number of notes to return
    
        Returns:
            List[dict]: List of note summaries (ID, title, category, content preview, creation date).
        """
        notes = []
    
        try:
            self.connect()

            if not self.eyr_file.load():
                return notes
        
            # Get list of all entry IDs
            internal_entry_ids = self.eyr_file.list_entries()
        
            # Process entries up to limit
            for internal_entry_id in internal_entry_ids[:limit]:
                # Get entry type first without full decryption
                entry_bytes = self.eyr_file.get_entry(internal_entry_id)
                if entry_bytes:
                    try:
                        entry_storage = json.loads(entry_bytes.decode('utf-8'))
                        if entry_storage.get('entry_type') == 'note':
                            note_summary = {'internal_id': internal_entry_id}
                            
                            # Get the display ID from storage
                            display_id = entry_storage.get('entry_id')
                            if display_id:
                                note_summary['id'] = display_id
                            else:
                                note_summary['id'] = str(internal_entry_id)  # Fallback
                        
                            # Get full note to extract summary information
                            note_full = self.get_note(master_key, note_summary['id'], formatted=False)
                            if note_full:
                                note_summary['title'] = note_full.get('title', 'Untitled')
                                note_summary['category'] = note_full.get('category', 'Notes')
                                note_summary['entry_type'] = 'note'
                            
                                # Create content preview
                                content = note_full.get('content', '')
                                note_summary['content_preview'] = content[:50] + '...' if len(content) > 50 else content
                            
                                # Format creation date for display
                                created_at = note_full.get('created_raw')
                                if created_at:
                                    note_summary['created_at'] = self.format_timestamp(created_at)
                                else:
                                    note_summary['created_at'] = ''
                            
                                notes.append(note_summary)
                    except:
                        continue  # Skip invalid entries
        
        except Exception as e:
            print(f"[-] Error listing notes: {e}")
    
        return notes

    def search_notes(self, master_key: bytes, search_term: str) -> List[dict]:
        """
        Search notes by content across title, content, and category.
    
        Args:
            master_key (bytes): Master encryption key
            search_term (str): Search query (case-insensitive)
    
        Returns:
            List[dict]: List of matching notes with full details.
        """
        results = []
        search_lower = search_term.lower()
    
        try:
            self.connect()
        
            if not self.eyr_file.load():
                return results
        
            internal_entry_ids = self.eyr_file.list_entries()
        
            # Normalize search term for category matching
            normalized_search = self._normalize_category_name(search_term)
        
            # Search through all entries
            for internal_entry_id in internal_entry_ids:
                # Check entry type first
                entry_bytes = self.eyr_file.get_entry(internal_entry_id)
                if entry_bytes:
                    try:
                        entry_storage = json.loads(entry_bytes.decode('utf-8'))
                        if entry_storage.get('entry_type') != 'note':
                            continue  # Skip non-note entries
                    except:
                        continue  # Skip invalid entries
                
                # Get display ID
                display_id = entry_storage.get('entry_id', str(internal_entry_id))
                note_full = self.get_note(master_key, display_id, formatted=True)
                if not note_full:
                    continue
            
                # Check each searchable field for match
                matches = False
                if search_lower in note_full.get('title', '').lower():
                    matches = True
                elif search_lower in note_full.get('content', '').lower():
                    matches = True
                else:
                    # Check category with flexible matching
                    entry_category = note_full.get('category', '')
                    if entry_category:
                        normalized_category = self._normalize_category_name(entry_category)
                        if normalized_search and normalized_search in normalized_category:
                            matches = True
            
                # If match found, prepare result for display
                if matches:
                    # Ensure formatted timestamps
                    if 'created_formatted' in note_full:
                        note_full['created_at'] = note_full['created_formatted']
                    else:
                        note_full['created_at'] = self.format_datetime(note_full.get('created_raw'))

                    if 'updated_formatted' in note_full:
                        note_full['updated_at'] = note_full['updated_formatted']
                    else:
                        note_full['updated_at'] = self.format_datetime(note_full.get('updated_raw'))
                
                    # Add content preview
                    content = note_full.get('content', '')
                    note_full['content_preview'] = content[:50] + '...' if len(content) > 50 else content
                
                    results.append(note_full)
    
        except Exception as e:
            print(f"[-] Error searching notes: {e}")
    
        return results

    def get_notes_by_category(self, master_key: bytes, category: str) -> List[dict]:
        """
        Filter notes by category with flexible matching.
    
        Args:
            master_key (bytes): Master encryption key
            category (str): Category name to filter by
    
        Returns:
            List[dict]: List of notes in the specified category.
        """
        notes = []
    
        try:
            self.connect()

            if not self.eyr_file.load():
                return notes
        
            internal_entry_ids = self.eyr_file.list_entries()
        
            # Normalize the search category for flexible matching
            normalized_search = self._normalize_category_name(category)

            # Filter notes by category with flexible matching
            for internal_entry_id in internal_entry_ids:
                # Check entry type first
                entry_bytes = self.eyr_file.get_entry(internal_entry_id)
                if entry_bytes:
                    try:
                        entry_storage = json.loads(entry_bytes.decode('utf-8'))
                        if entry_storage.get('entry_type') != 'note':
                            continue  # Skip non-note entries
                    except:
                        continue  # Skip invalid entries
                
                # Get display ID
                display_id = entry_storage.get('entry_id', str(internal_entry_id))
                note = self.get_note(master_key, display_id, formatted=True)
                if note:
                    note_category = note.get('category', 'Notes')
                    normalized_entry = self._normalize_category_name(note_category)

                    # Check if normalized categories match
                    if normalized_entry == normalized_search:
                        # Ensure formatted timestamps
                        if 'created_formatted' in note:
                            note['created_at'] = note['created_formatted']
                        else:
                            note['created_at'] = self.format_datetime(note.get('created_raw'))
                    
                        if 'updated_formatted' in note:
                            note['updated_at'] = note['updated_formatted']
                        else:
                            note['updated_at'] = self.format_datetime(note.get('updated_raw'))
                    
                        # Add content preview
                        content = note.get('content', '')
                        note['content_preview'] = content[:50] + '...' if len(content) > 50 else content
                    
                        notes.append(note)
    
        except Exception as e:
            print(f"[-] Error filtering notes by category: {e}")
    
        return notes

    def update_note(self, master_key: bytes, entry_id: str, new_data: dict) -> bool:
        """
        Update an existing note with new data.
    
        Args:
            master_key (bytes): Master encryption key
            entry_id (str): Entry identifier (display ID like "EYR-A9F3Q2")
            new_data (dict): Updated note data
    
        Returns:
            bool: True if update succeeded.
        """
        try:
            self.connect()
        
            if not self.eyr_file.load():
                return False
        
            # Get current note data
            current = self.get_note(master_key, entry_id, formatted=False)
            if not current:
                return False
            
            # Get internal ID from current note
            internal_entry_id = current.get('internal_id')
            if not internal_entry_id:
                return False
        
            # Merge current data with updates
            updated_data = current.copy()
            updated_data.update(new_data)
        
            # Update modification timestamp
            current_time = time.time()
            updated_data['updated_at'] = current_time
            updated_data['entry_type'] = 'note'  # Ensure type is preserved
        
            # Remove internal metadata fields before encryption
            for field in ['id', 'internal_id', 'category', 'created_raw', 'updated_raw']:
                updated_data.pop(field, None)
        
            # Encrypt updated note
            encrypted = encrypt_entry(master_key, updated_data, internal_entry_id)
        
            # Get current storage to preserve other fields
            entry_bytes = self.eyr_file.get_entry(internal_entry_id)
            if not entry_bytes:
                return False
            
            entry_storage = json.loads(entry_bytes.decode('utf-8'))
        
            # Update storage structure
            entry_storage['encrypted_data'] = encrypted
            entry_storage['category'] = new_data.get('category', current.get('category', 'Notes'))
            entry_storage['entry_type'] = 'note'
            entry_storage['updated_at'] = current_time
        
            # Serialize and store
            entry_json = json.dumps(entry_storage, ensure_ascii=False)
            entry_bytes = entry_json.encode('utf-8')
        
            return self.eyr_file.update_entry(internal_entry_id, entry_bytes)
        
        except Exception as e:
            print(f"[-] Error updating note: {e}")
            return False

    def delete_note(self, entry_id: str) -> bool:
        """
        Permanently remove a note from the vault.
    
        Args:
            entry_id (str): Entry identifier (display ID like "EYR-A9F3Q2")
    
        Returns:
            bool: True if deletion succeeded.
        """
        # Use the same delete_entry method since notes are stored as entries
        return self.delete_entry(entry_id)

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
            internal_entry_ids = self.eyr_file.list_entries()
            
            # Re-encrypt each entry
            for internal_entry_id in internal_entry_ids:
                # Get entry type first
                entry_bytes = self.eyr_file.get_entry(internal_entry_id)
                if not entry_bytes:
                    continue
                    
                try:
                    entry_storage = json.loads(entry_bytes.decode('utf-8'))
                    entry_type = entry_storage.get('entry_type', 'password')
                except:
                    continue  # Skip invalid entries
                
                # Decrypt based on entry type
                if entry_type == 'note':
                    display_id = entry_storage.get('entry_id', str(internal_entry_id))
                    entry_data = self.get_note(old_key, display_id, formatted=False)
                else:
                    display_id = entry_storage.get('entry_id', str(internal_entry_id))
                    entry_data = self.get_entry(old_key, display_id, formatted=False)
                    
                if not entry_data:
                    return False  # Failed to decrypt an entry
                
                # Remove internal fields before re-encryption
                for field in ['id', 'internal_id', 'category', 'created_raw', 'updated_raw']:
                    entry_data.pop(field, None)
                
                # Ensure entry type is preserved
                entry_data['entry_type'] = entry_type
                
                # Re-encrypt with new key
                encrypted = encrypt_entry(new_key, entry_data, internal_entry_id)
                
                # Update entry in vault
                entry_storage['encrypted_data'] = encrypted
                updated_bytes = json.dumps(entry_storage, ensure_ascii=False).encode('utf-8')
                
                if not self.eyr_file.update_entry(internal_entry_id, updated_bytes):
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
                - password_entries: Number of password entries
                - notes: Number of secure notes
                - version: Vault format version
                - created_at: Vault creation timestamp (formatted)
        """
        try:
            self.connect()
            
            if not self.eyr_file.load():
                return None
            
            info = {}
            
            # Count entries by category and type
            password_categories = {}
            note_categories = {}
            password_count = 0
            note_count = 0
            internal_entry_ids = self.eyr_file.list_entries()
            
            for internal_entry_id in internal_entry_ids:
                entry_bytes = self.eyr_file.get_entry(internal_entry_id)
                if not entry_bytes:
                    continue
                    
                try:
                    entry_storage = json.loads(entry_bytes.decode('utf-8'))
                    entry_type = entry_storage.get('entry_type', 'password')
                    
                    if entry_type == 'note':
                        note_count += 1
                        display_id = entry_storage.get('entry_id', str(internal_entry_id))
                        note = self.get_note(master_key, display_id, formatted=False)
                        if note:
                            category = note.get('category', 'Notes')
                            note_categories[category] = note_categories.get(category, 0) + 1
                    else:
                        password_count += 1
                        display_id = entry_storage.get('entry_id', str(internal_entry_id))
                        entry = self.get_entry(master_key, display_id, formatted=False)
                        if entry:
                            category = entry.get('category', 'General')
                            password_categories[category] = password_categories.get(category, 0) + 1
                except:
                    continue
            
            info['password_categories'] = password_categories
            info['note_categories'] = note_categories
            info['total_entries'] = len(internal_entry_ids)
            info['password_entries'] = password_count
            info['notes'] = note_count
            
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
    
    def get_password_history(self, master_key: bytes, entry_id: str) -> Optional[List[Dict]]:
        """
        Retrieve password history for an entry with masked passwords.
        
        Args:
            master_key (bytes): Master encryption key
            entry_id (str): Entry identifier (display ID like "EYR-A9F3Q2")
        
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
    
    def get_password_history_with_passwords(self, master_key: bytes, entry_id: str) -> Optional[List[Dict]]:
        """
        Retrieve password history for an entry WITH plaintext passwords.
        
        Args:
            master_key (bytes): Master encryption key
            entry_id (str): Entry identifier (display ID like "EYR-A9F3Q2")
        
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
    
    def clear_password_history(self, master_key: bytes, entry_id: str) -> bool:
        """
        Clear all password history for an entry.
        
        Args:
            master_key (bytes): Master encryption key
            entry_id (str): Entry identifier (display ID like "EYR-A9F3Q2")
        
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
            
            # Get internal ID from current entry
            internal_entry_id = current.get('internal_id')
            if not internal_entry_id:
                return False
            
            # Clear password history
            if 'password_history' in current:
                current['password_history'] = []
            
            # Update modification timestamp
            current_time = time.time()
            current['updated_at'] = current_time
            current['entry_type'] = 'password'  # Ensure type is preserved
            
            # Remove internal fields
            for field in ['id', 'internal_id', 'category', 'created_raw', 'updated_raw']:
                current.pop(field, None)
            
            # Re-encrypt entry without history
            encrypted = encrypt_entry(master_key, current, internal_entry_id)
            
            # Get current storage
            entry_bytes = self.eyr_file.get_entry(internal_entry_id)
            if not entry_bytes:
                return False
            
            entry_storage = json.loads(entry_bytes.decode('utf-8'))
            
            # Update storage
            entry_storage['encrypted_data'] = encrypted
            entry_storage['category'] = current.get('category', 'General')
            entry_storage['entry_type'] = 'password'
            entry_storage['updated_at'] = current_time
            
            entry_json = json.dumps(entry_storage, ensure_ascii=False)
            entry_bytes = entry_json.encode('utf-8')
            
            return self.eyr_file.update_entry(internal_entry_id, entry_bytes)
            
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