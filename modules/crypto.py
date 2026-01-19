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
from typing import Tuple, Optional, Dict, Any, List
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
    
    Args:
        key_material (bytes): Input key material from Argon2
        info (bytes): Context/application-specific information
        
    Returns:
        bytes: 32-byte derived key suitable for cryptographic use
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=None,
        info=info,
    )
    return hkdf.derive(key_material)

# ==============================================================================
# SYMMETRIC ENCRYPTION / DECRYPTION
# ==============================================================================

def _normalize_aes_key(key: bytes) -> bytes:
    """
    Ensure a key is valid for AES-256 encryption.
    
    Args:
        key (bytes): Input key material
        
    Returns:
        bytes: Exactly KEY_SIZE (32) bytes for AES-256
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
    
    Args:
        encryption_key (bytes): 32-byte AES-256 encryption key
        data (bytes): Plaintext data to encrypt
        associated_data (bytes, optional): Additional authenticated data
        
    Returns:
        Tuple[bytes, bytes, bytes]: A tuple containing:
            - nonce: 12-byte random nonce
            - ciphertext: Encrypted data
            - tag: 16-byte authentication tag
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
    
    Args:
        encryption_key (bytes): 32-byte AES-256 encryption key
        nonce (bytes): 12-byte nonce used during encryption
        ciphertext (bytes): Encrypted data
        tag (bytes): 16-byte authentication tag
        associated_data (bytes, optional): Additional authenticated data
            
    Returns:
        Optional[bytes]: Decrypted plaintext if authentication succeeds,
                         None otherwise
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
    
    Args:
        master_key (bytes): 64-byte master key
        entry_data (dict): Dictionary containing credential data
        entry_id (int, optional): Unique entry identifier for AAD binding
        
    Returns:
        dict: Dictionary containing encrypted entry
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
    
    Args:
        master_key (bytes): 64-byte master key
        encrypted_data (dict): Dictionary containing encrypted entry components
        
    Returns:
        Optional[dict]: Decrypted entry data if authentication succeeds
    """
    # Extract the encryption portion of the master key
    encryption_key = master_key[:KEY_SIZE]
    
    try:
        # Decode base64-encoded cryptographic components
        nonce = base64.b64decode(encrypted_data["nonce"])
        ciphertext = base64.b64decode(encrypted_data["ciphertext"])
        tag = base64.b64decode(encrypted_data["tag"])
    except (KeyError, ValueError):
        return None
    
    # Prepare associated data if entry ID is present
    associated_data = None
    if "entry_id" in encrypted_data:
        associated_data = struct.pack("Q", encrypted_data["entry_id"])
    
    # Decrypt and verify the data
    decrypted = decrypt_data(
        encryption_key, 
        nonce, 
        ciphertext, 
        tag, 
        associated_data
    )
    
    if decrypted is None:
        return None
    
    try:
        # Deserialize JSON back to dictionary
        return json.loads(decrypted.decode("utf-8"))
    except Exception:
        return None

# ==============================================================================
# SECURE MEMORY MANAGEMENT
# ==============================================================================

def generate_salt() -> bytes:
    """
    Generate a cryptographically secure random salt.
    
    Returns:
        bytes: SALT_SIZE bytes of cryptographically secure random data
    """
    return os.urandom(SALT_SIZE)


def secure_erase(data: str) -> None:
    """
    Securely erase a string from memory by overwriting with zeros.
    
    Args:
        data (str): String to securely erase
    """
    if isinstance(data, str):
        # Convert to mutable bytearray for secure erasure
        secure_erase_bytes(bytearray(data.encode("utf-8")))


def secure_erase_bytes(data: bytearray) -> None:
    """
    Securely erase a mutable bytearray from memory.
    
    Args:
        data (bytearray): Mutable byte array to securely erase
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
    """
    secure_erase_bytes(bytearray(key))

# ==============================================================================
# MESSAGE AUTHENTICATION (HMAC)
# ==============================================================================

def compute_hmac(key: bytes, data: bytes) -> bytes:
    """
    Compute HMAC-SHA256 for data authentication.
    
    Args:
        key (bytes): 64-byte master key
        data (bytes): Data to compute HMAC for
        
    Returns:
        bytes: 32-byte HMAC-SHA256 digest
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
        bool: True if HMAC verification succeeds
    """
    return hmac.compare_digest(
        compute_hmac(key, data),
        expected_hmac,
    )