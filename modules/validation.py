"""
Eyrie Validation and Security Module
Input validation and security enforcement
"""

import re
import time
import os
import json
import math
import hashlib
from typing import Dict, Optional, Tuple
from datetime import datetime, timedelta
import email_validator

# Security configuration
MAX_ATTEMPTS = 5
LOCKOUT_TIME = 300  # 5 minutes
ATTEMPT_WINDOW = 900  # 15 minutes
MIN_PASSWORD_LENGTH = 12

def validate_password_strength(password: str) -> Tuple[bool, str]:
    """
    Enforce strong password requirements
    
    Returns:
        (is_valid, validation_message)
    """
    if len(password) < MIN_PASSWORD_LENGTH:
        return False, f"Minimum {MIN_PASSWORD_LENGTH} characters required"
    
    # Character class requirements
    has_upper = bool(re.search(r'[A-Z]', password))
    has_lower = bool(re.search(r'[a-z]', password))
    has_digit = bool(re.search(r'[0-9]', password))
    has_special = bool(re.search(r'[^A-Za-z0-9]', password))
    
    char_types = sum([has_upper, has_lower, has_digit, has_special])
    if char_types < 3:
        return False, "Use at least 3 character classes"
    
    # Block common passwords
    common_passwords = {
        'password', '123456', '12345678', '123456789', '12345',
        'qwerty', 'abc123', 'password1', 'admin', 'welcome',
        'letmein', 'monkey', 'dragon', 'baseball', 'football',
        'master', 'superman', 'sunshine', 'iloveyou', 'trustno1'
    }
    
    if password.lower() in common_passwords:
        return False, "Password is too common"
    
    # Sequential pattern detection
    if re.search(r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)', password.lower()):
        return False, "Avoid sequential letters"
    
    if re.search(r'(012|123|234|345|456|567|678|789|890)', password):
        return False, "Avoid sequential numbers"
    
    # Repeated characters
    if re.search(r'(.)\1{2,}', password):
        return False, "Avoid repeated characters"
    
    # Keyboard patterns
    keyboard_patterns = [
        'qwerty', 'asdfgh', 'zxcvbn', 'qazwsx', 'edcrfv'
    ]
    if any(pattern in password.lower() for pattern in keyboard_patterns):
        return False, "Avoid keyboard patterns"
    
    return True, "Password meets requirements"

def validate_url(url: str) -> bool:
    """
    Validate URL format and safety
    
    Returns:
        True if URL is valid and safe
    """
    if not url:
        return True
    
    url_pattern = re.compile(
        r'^(https?://)?'  # Optional protocol
        r'([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+'  # Domain
        r'[a-zA-Z]{2,}'  # TLD
        r'(:\d+)?'  # Optional port
        r'(/[-a-zA-Z0-9@:%_\+.~#?&//=]*)?$'  # Path
    )
    
    if not bool(url_pattern.match(url)):
        return False
    
    return True

def validate_email(email: str) -> bool:
    """
    Validate email using python-email-validator
    
    Returns:
        True if email is valid
    """
    if not email:
        return True
    
    try:
        email_validator.validate_email(email, check_deliverability=False)
        return True
    except email_validator.EmailNotValidError:
        return False

def record_failed_attempt(vault_path: str) -> None:
    """Log failed authentication attempt"""
    attempt_file = f"{vault_path}.attempts"
    
    try:
        attempts = []
        
        if os.path.exists(attempt_file):
            with open(attempt_file, 'r') as f:
                attempts = json.load(f)
        
        attempts.append({'timestamp': time.time()})
        
        window_start = time.time() - ATTEMPT_WINDOW
        attempts = [a for a in attempts if a['timestamp'] > window_start]
        
        with open(attempt_file, 'w') as f:
            json.dump(attempts, f)
            
    except Exception:
        pass

def check_rate_limit(vault_path: str) -> bool:
    """Verify authentication attempts are within limits"""
    attempt_file = f"{vault_path}.attempts"
    
    if not os.path.exists(attempt_file):
        return True
    
    try:
        with open(attempt_file, 'r') as f:
            attempts = json.load(f)
        
        if len(attempts) >= MAX_ATTEMPTS:
            last_attempt = max(a['timestamp'] for a in attempts)
            if time.time() - last_attempt < LOCKOUT_TIME:
                return False
        
        return True
        
    except Exception:
        return True

def clear_failed_attempts(vault_path: str) -> None:
    """Reset authentication attempt tracking"""
    attempt_file = f"{vault_path}.attempts"
    
    try:
        if os.path.exists(attempt_file):
            os.remove(attempt_file)
    except Exception:
        pass

def validate_entry_data(entry_data: Dict) -> Tuple[bool, str]:
    """
    Validate password entry data integrity
    
    Returns:
        (is_valid, validation_message)
    """
    required_fields = ['title', 'username', 'password']
    for field in required_fields:
        if not entry_data.get(field, '').strip():
            return False, f"{field.capitalize()} required"
    
    title = entry_data.get('title', '')
    if len(title.strip()) < 2:
        return False, "Title too short"
    
    if len(title) > 200:
        return False, "Title exceeds maximum length"
    
    # URL validation
    url = entry_data.get('url', '')
    if url and not validate_url(url):
        return False, "Invalid URL format"
    
    # Email validation for username if applicable
    username = entry_data.get('username', '')
    if '@' in username and '.' in username:
        if not validate_email(username):
            return False, "Invalid email format"
    
    return True, "Entry validation passed"

def validate_master_password(password: str) -> Tuple[bool, str]:
    """
    Enhanced master password validation
    
    Returns:
        (is_valid, validation_message)
    """
    # Length requirement
    if len(password) < MIN_PASSWORD_LENGTH:
        return False, f"Minimum {MIN_PASSWORD_LENGTH} characters"
    
    # Character variety
    if len(set(password)) < 10:
        return False, "Insufficient character variety"
    
    # Entropy check
    entropy = calculate_password_entropy(password)
    if entropy < 3.0:  # Very low entropy
        return False, "Password too predictable"
    
    # Check against worst passwords
    if is_password_pwned(password):
        return False, "Password appears in known breaches"
    
    return True, "Master password accepted"

def calculate_password_entropy(password: str) -> float:
    """
    Calculate Shannon entropy for password strength analysis
    
    Returns:
        Entropy in bits (higher = more secure)
    """
    if not password:
        return 0.0
    
    # Character pool size estimation
    char_pool = 0
    if re.search(r'[a-z]', password):
        char_pool += 26
    if re.search(r'[A-Z]', password):
        char_pool += 26
    if re.search(r'[0-9]', password):
        char_pool += 10
    if re.search(r'[^A-Za-z0-9]', password):
        char_pool += 33  # Common special characters
    
    # Calculate entropy per character
    if char_pool == 0:
        return 0.0
    
    bits_per_char = math.log2(char_pool)
    total_entropy = bits_per_char * len(password)
    
    return total_entropy

def is_password_pwned(password: str) -> bool:
    """
    Check password against known breaches using k-anonymity
    
    Note: This simulates the check. For production, implement
    Have I Been Pwned API integration.
    
    Returns:
        True if password appears in known breaches
    """
    # Top 100 most breached passwords (source: various breach compilations)
    breached_passwords = {
        '123456', '123456789', 'qwerty', 'password', '12345678',
        '111111', '1234567890', '1234567', 'password1', '12345',
        '123123', 'admin', 'welcome', 'monkey', 'dragon',
        'sunshine', 'master', 'letmein', 'superman', 'trustno1',
        'iloveyou', 'princess', 'football', 'mustang', 'michael',
        'shadow', 'bailey', 'charles', 'jordan', 'harley',
        'andrew', 'matthew', 'charlie', 'daniel', 'robert',
        'thomas', 'hunter', 'joshua', 'ashley', 'samantha',
        'george', 'jessica', 'sophie', 'oliver', 'jackson'
    }
    
    return password.lower() in breached_passwords

def validate_category_name(category: str) -> bool:
    """
    Validate category name format
    
    Returns:
        True if category name is valid
    """
    if not category or not category.strip():
        return False
    
    category = category.strip()
    
    # Length limits
    if len(category) < 1 or len(category) > 50:
        return False
    
    # Allow only alphanumeric, space, hyphen, underscore
    if not re.match(r'^[a-zA-Z0-9 _-]+$', category):
        return False
    
    return True

def validate_input_length(field: str, value: str, max_length: int = 500) -> bool:
    """
    Validate field length constraints
    
    Returns:
        True if length is within limits
    """
    if value is None:
        return True
    
    return len(str(value)) <= max_length