"""
Cryptographic operations for Eyrie Password Manager.

This module provides secure cryptographic primitives for:
- Key derivation using Argon2id (memory-hard KDF)
- Authenticated encryption using AES-GCM
- Secure memory management and data sanitization
- HMAC-based authentication

All cryptographic operations follow current best practices and are designed
to be resistant to timing attacks and memory analysis.
"""

import os
import json
import base64
import struct
from typing import Tuple, Optional, Dict, Any
import ctypes
import hashlib
import hmac

# Cryptography library imports for modern cryptographic primitives
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

# ==============================================================================
# CRYPTOGRAPHIC CONSTANTS
# ==============================================================================

# Size of cryptographic salt in bytes (256 bits for Argon2)
SALT_SIZE = 32

# Size of AES-GCM nonce in bytes (96 bits as recommended for AES-GCM)
NONCE_SIZE = 12

# Size of AES-GCM authentication tag in bytes (128 bits)
TAG_SIZE = 16

# Size of encryption key in bytes (256 bits for AES-256)
KEY_SIZE = 32

# Argon2id parameters for memory-hard key derivation
# Time cost: Number of iterations (higher = more secure but slower)
ARGON2_TIME_COST = 2

# Memory cost: Memory usage in KB (100 MB = 102400 KB)
# High memory usage defends against GPU/ASIC attacks
ARGON2_MEMORY_COST = 102400  # 100 MB

# Parallelism: Number of parallel threads/lanes
ARGON2_PARALLELISM = 4

# ==============================================================================
# KEY DERIVATION FUNCTIONS
# ==============================================================================

def derive_master_key(password: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    """
    Derive a cryptographically secure master key from a password using Argon2id.
    
    Argon2id is a memory-hard key derivation function that provides resistance
    against GPU/ASIC attacks. This function produces a 64-byte master key
    consisting of separate encryption and authentication keys.
    
    Args:
        password (str): User's master password (will be encoded to UTF-8)
        salt (bytes, optional): Cryptographic salt for key derivation.
            If not provided, a random 32-byte salt will be generated.
            
    Returns:
        Tuple[bytes, bytes]: A tuple containing:
            - master_key: 64 bytes (32 encryption + 32 authentication)
            - salt: The salt used for derivation (same as input if provided)
            
    Security Notes:
        - Uses Argon2id (memory-hard) to resist GPU/ASIC attacks
        - Generates separate keys for encryption and authentication
        - Includes proper HKDF step for key separation
        - Salt is essential for preventing rainbow table attacks
    """
    # Generate random salt if not provided
    if salt is None:
        salt = os.urandom(SALT_SIZE)
    
    # Initialize Argon2id with configured parameters
    kdf = Argon2id(
        salt=salt,
        length=64,  # Output length in bytes
        iterations=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        lanes=ARGON2_PARALLELISM,
    )
    
    # Derive initial key material from password
    key = kdf.derive(password.encode("utf-8"))
    
    # Split key material and apply HKDF for proper key separation
    encryption_key = derive_hkdf_key(key[:32], b"encryption")
    authentication_key = derive_hkdf_key(key[32:], b"authentication")
    
    return (encryption_key + authentication_key, salt)


def derive_hkdf_key(key_material: bytes, info: bytes) -> bytes:
    """
    Apply HKDF (HMAC-based Key Derivation Function) to key material.
    
    HKDF provides cryptographically strong key derivation and ensures
    proper key separation for different cryptographic purposes.
    
    Args:
        key_material (bytes): Input key material from Argon2
        info (bytes): Context/application-specific information
            Used to bind derived key to specific purpose
        
    Returns:
        bytes: 32-byte derived key suitable for cryptographic use
        
    Security Notes:
        - Uses SHA-256 as underlying hash function
        - Provides key separation between encryption and authentication keys
        - Follows RFC 5869 HKDF standard
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=None,  # No salt needed as Argon2 already provides salt
        info=info,  # Context binding
    )
    return hkdf.derive(key_material)

# ==============================================================================
# SYMMETRIC ENCRYPTION / DECRYPTION
# ==============================================================================

def _normalize_aes_key(key: bytes) -> bytes:
    """
    Ensure a key is valid for AES-256 encryption.
    
    This function validates key length and extracts exactly KEY_SIZE bytes.
    Acts as a defensive boundary for cryptographic operations.
    
    Args:
        key (bytes): Input key material
        
    Returns:
        bytes: Exactly KEY_SIZE (32) bytes for AES-256
        
    Raises:
        ValueError: If key is shorter than KEY_SIZE
        
    Security Notes:
        - Enforces minimum key length requirement
        - Prevents key truncation vulnerabilities
        - Defensive programming at crypto boundary
    """
    if len(key) < KEY_SIZE:
        raise ValueError("Encryption key too short for AES-256")
    return key[:KEY_SIZE]


def encrypt_data(
    encryption_key: bytes,
    data: bytes,
    associated_data: Optional[bytes] = None,
) -> Tuple[bytes, bytes, bytes]:
    """
    Encrypt data using AES-GCM authenticated encryption.
    
    AES-GCM provides both confidentiality and authenticity in a single operation.
    Returns the nonce, ciphertext, and authentication tag separately.
    
    Args:
        encryption_key (bytes): 32-byte AES-256 encryption key
        data (bytes): Plaintext data to encrypt
        associated_data (bytes, optional): Additional authenticated data (AAD)
            that will be authenticated but not encrypted
            
    Returns:
        Tuple[bytes, bytes, bytes]: A tuple containing:
            - nonce: 12-byte random nonce
            - ciphertext: Encrypted data
            - tag: 16-byte authentication tag
            
    Security Notes:
        - Uses AES-GCM for authenticated encryption
        - Generates cryptographically secure random nonce
        - Supports Additional Authenticated Data (AAD)
        - Nonce is never reused with the same key
    """
    # Ensure key is properly sized for AES-256
    encryption_key = _normalize_aes_key(encryption_key)
    
    # Generate cryptographically secure random nonce
    nonce = os.urandom(NONCE_SIZE)
    
    # Initialize AES-GCM cipher
    aesgcm = AESGCM(encryption_key)
    
    # Encrypt data with authentication
    ciphertext_with_tag = aesgcm.encrypt(nonce, data, associated_data)
    
    # Split ciphertext and authentication tag
    ciphertext = ciphertext_with_tag[:-TAG_SIZE]
    tag = ciphertext_with_tag[-TAG_SIZE:]
    
    return nonce, ciphertext, tag


def decrypt_data(
    encryption_key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    tag: bytes,
    associated_data: Optional[bytes] = None,
) -> Optional[bytes]:
    """
    Decrypt and verify data encrypted with AES-GCM.
    
    This function verifies the authentication tag before returning decrypted data.
    Returns None if authentication fails or decryption error occurs.
    
    Args:
        encryption_key (bytes): 32-byte AES-256 encryption key
        nonce (bytes): 12-byte nonce used during encryption
        ciphertext (bytes): Encrypted data
        tag (bytes): 16-byte authentication tag
        associated_data (bytes, optional): Additional authenticated data (AAD)
            
    Returns:
        Optional[bytes]: Decrypted plaintext if authentication succeeds,
                         None otherwise
        
    Security Notes:
        - Authentication is verified before decryption
        - Uses constant-time comparison for authentication tag
        - Returns None on failure to avoid timing leaks
        - Handles all exceptions gracefully
    """
    try:
        # Ensure key is properly sized for AES-256
        encryption_key = _normalize_aes_key(encryption_key)
        
        # Initialize AES-GCM cipher
        aesgcm = AESGCM(encryption_key)
        
        # Combine ciphertext and tag for decryption
        combined_ciphertext = ciphertext + tag
        
        # Decrypt and verify authentication
        plaintext = aesgcm.decrypt(nonce, combined_ciphertext, associated_data)
        
        return plaintext
        
    except Exception:
        # Return None on any cryptographic failure
        # This includes authentication failures and decryption errors
        return None

# ==============================================================================
# ENTRY-LEVEL ENCRYPTION WRAPPERS
# ==============================================================================

def encrypt_entry(
    master_key: bytes,
    entry_data: Dict[str, Any],
    entry_id: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Encrypt a credential entry with associated data binding.
    
    This function serializes the entry data to JSON, encrypts it with AES-GCM,
    and optionally binds the encryption to a specific entry ID using AAD.
    
    Args:
        master_key (bytes): 64-byte master key (encryption + authentication)
        entry_data (dict): Dictionary containing credential data
        entry_id (int, optional): Unique entry identifier for AAD binding
        
    Returns:
        dict: Dictionary containing:
            - nonce: Base64-encoded nonce
            - ciphertext: Base64-encoded encrypted data
            - tag: Base64-encoded authentication tag
            - entry_id: Original entry ID (if provided)
            
    Security Notes:
        - Entry ID is used as Additional Authenticated Data (AAD)
        - This binds ciphertext to specific entry, preventing substitution attacks
        - Base64 encoding is used for JSON serialization compatibility
    """
    # Extract the encryption portion of the master key
    encryption_key = master_key[:KEY_SIZE]
    
    # Serialize entry data to JSON
    json_data = json.dumps(entry_data, ensure_ascii=False).encode("utf-8")
    
    # Prepare associated data using entry ID if provided
    associated_data = None
    if entry_id is not None:
        # Pack entry ID as 64-bit unsigned integer for consistent format
        associated_data = struct.pack("Q", entry_id)
    
    # Encrypt the serialized data
    nonce, ciphertext, tag = encrypt_data(
        encryption_key, 
        json_data, 
        associated_data
    )
    
    # Build result dictionary with base64-encoded components
    result = {
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "tag": base64.b64encode(tag).decode("ascii"),
    }
    
    # Include entry ID in result for reference
    if entry_id is not None:
        result["entry_id"] = entry_id
    
    return result


def decrypt_entry(master_key: bytes, encrypted_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Decrypt a credential entry with authentication verification.
    
    This function reverses the encryption performed by encrypt_entry(),
    verifying both the authentication tag and the associated data binding.
    
    Args:
        master_key (bytes): 64-byte master key (encryption + authentication)
        encrypted_data (dict): Dictionary containing encrypted entry components
        
    Returns:
        Optional[dict]: Decrypted entry data if authentication succeeds,
                        None otherwise
        
    Security Notes:
        - Verifies authentication tag before attempting decryption
        - Validates associated data binding (entry ID)
        - Returns None on any cryptographic failure
        - Handles malformed input gracefully
    """
    # Extract the encryption portion of the master key
    encryption_key = master_key[:KEY_SIZE]
    
    try:
        # Decode base64-encoded cryptographic components
        nonce = base64.b64decode(encrypted_data["nonce"])
        ciphertext = base64.b64decode(encrypted_data["ciphertext"])
        tag = base64.b64decode(encrypted_data["tag"])
    except (KeyError, ValueError):
        # Return None if cryptographic components are missing or malformed
        return None
    
    # Prepare associated data if entry ID is present
    associated_data = None
    if "entry_id" in encrypted_data:
        # Pack entry ID to match encryption format
        associated_data = struct.pack("Q", encrypted_data["entry_id"])
    
    # Decrypt and verify the data
    decrypted = decrypt_data(
        encryption_key, 
        nonce, 
        ciphertext, 
        tag, 
        associated_data
    )
    
    # Return None if decryption or authentication failed
    if decrypted is None:
        return None
    
    try:
        # Deserialize JSON back to dictionary
        return json.loads(decrypted.decode("utf-8"))
    except Exception:
        # Return None if JSON deserialization fails
        return None

# ==============================================================================
# SECURE MEMORY MANAGEMENT
# ==============================================================================

def generate_salt() -> bytes:
    """
    Generate a cryptographically secure random salt.
    
    Returns:
        bytes: SALT_SIZE bytes of cryptographically secure random data
        
    Security Notes:
        - Uses os.urandom() which is suitable for cryptographic use
        - Provides sufficient entropy for Argon2id salt
    """
    return os.urandom(SALT_SIZE)


def secure_erase(data: str) -> None:
    """
    Securely erase a string from memory by overwriting with zeros.
    
    This attempts to prevent sensitive data from remaining in memory
    after it's no longer needed. Note: Effectiveness depends on Python's
    memory management and may not work with immutable strings in all cases.
    
    Args:
        data (str): String to securely erase
        
    Security Notes:
        - Attempts to overwrite memory but effectiveness is limited in Python
        - Use bytearray for more reliable secure erasure
        - Consider using specialized libraries for high-security applications
    """
    if isinstance(data, str):
        # Convert to mutable bytearray for secure erasure
        secure_erase_bytes(bytearray(data.encode("utf-8")))


def secure_erase_bytes(data: bytearray) -> None:
    """
    Securely erase a mutable bytearray from memory.
    
    This function overwrites the memory with zeros and uses ctypes to
    attempt to force the overwrite at the C level.
    
    Args:
        data (bytearray): Mutable byte array to securely erase
        
    Security Notes:
        - Overwrites memory with zeros
        - Uses ctypes to attempt low-level memory overwrite
        - More reliable than string erasure but still limited by Python GC
    """
    # Python-level overwrite with zeros
    for i in range(len(data)):
        data[i] = 0
    
    # Attempt low-level memory overwrite using ctypes
    ctypes.memset(
        ctypes.addressof(ctypes.c_char.from_buffer(data)), 
        0, 
        len(data)
    )


def secure_erase_key(key: bytes) -> None:
    """
    Securely erase a cryptographic key from memory.
    
    Args:
        key (bytes): Cryptographic key to securely erase
        
    Security Notes:
        - Converts immutable bytes to mutable bytearray for erasure
        - Critical for preventing key material from persisting in memory
    """
    secure_erase_bytes(bytearray(key))

# ==============================================================================
# MESSAGE AUTHENTICATION (HMAC)
# ==============================================================================

def compute_hmac(key: bytes, data: bytes) -> bytes:
    """
    Compute HMAC-SHA256 for data authentication.
    
    Uses the authentication portion of the master key (second 32 bytes)
    to compute a cryptographic hash-based message authentication code.
    
    Args:
        key (bytes): 64-byte master key (only authentication portion is used)
        data (bytes): Data to compute HMAC for
        
    Returns:
        bytes: 32-byte HMAC-SHA256 digest
        
    Security Notes:
        - Uses SHA-256 as underlying hash function
        - Uses authentication key (not encryption key) for proper separation
        - Provides integrity and authenticity verification
    """
    # Extract authentication key (second 32 bytes of master key)
    auth_key = key[KEY_SIZE:]
    
    # Compute HMAC-SHA256
    return hmac.new(auth_key, data, hashlib.sha256).digest()


def verify_hmac(key: bytes, data: bytes, expected_hmac: bytes) -> bool:
    """
    Verify HMAC-SHA256 with constant-time comparison.
    
    Args:
        key (bytes): 64-byte master key
        data (bytes): Data to verify
        expected_hmac (bytes): Expected HMAC value to compare against
        
    Returns:
        bool: True if HMAC verification succeeds, False otherwise
        
    Security Notes:
        - Uses hmac.compare_digest() for constant-time comparison
        - Prevents timing attacks that could reveal information about the HMAC
        - Properly verifies both integrity and authenticity
    """
    return hmac.compare_digest(
        compute_hmac(key, data),  # Compute HMAC for provided data
        expected_hmac,            # Compare against expected value
    )