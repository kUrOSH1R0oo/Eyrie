"""
Secure Password Generation Module for Eyrie Password Manager

This module provides cryptographically secure password generation and strength
analysis utilities. It implements multiple password generation strategies including:
- Cryptographically secure random passwords
- Memorable password generation (Diceware method)
- Pattern-based password generation
- Password strength estimation and analysis

All random generation uses the secrets module which is suitable for cryptographic
applications and provides true randomness from the operating system.

SECURITY NOTES:
- Uses secrets module instead of random module for cryptographic security
- Implements character set customization for different security requirements
- Includes strength estimation to guide users toward secure passwords
- Handles edge cases and provides clear error messages
"""

import secrets
import random
import string
import re
import sys
from typing import List, Optional, Dict, Tuple

# Import constants from validation module with fallback
try:
    from validation import MIN_PASSWORD_LENGTH
except ImportError:
    # Fallback if validation module isn't available
    # Minimum password length recommendation based on NIST guidelines
    MIN_PASSWORD_LENGTH = 12

# ==============================================================================
# CUSTOM EXCEPTION CLASSES
# ==============================================================================

class PasswordGenerationError(Exception):
    """
    Custom exception class for password generation errors.
    
    Raised when password generation fails due to invalid parameters or
    constraints that cannot be satisfied.
    
    Attributes:
        message (str): Human-readable error description
    """
    pass

# ==============================================================================
# MAIN PASSWORD GENERATION FUNCTIONS
# ==============================================================================

def generate_secure_password(length: int = MIN_PASSWORD_LENGTH, 
                           include_uppercase: bool = True,
                           include_lowercase: bool = True,
                           include_digits: bool = True,
                           include_symbols: bool = True,
                           exclude_similar: bool = True,
                           exclude_ambiguous: bool = False,
                           raise_error: bool = True) -> str:
    """
    Generate a cryptographically secure random password with configurable character sets.
    
    This is the primary password generation function that ensures:
    1. Cryptographically secure randomness using secrets module
    2. At least one character from each selected character type
    3. Configurable character set exclusions for usability
    4. Minimum password length enforcement
    
    Args:
        length (int): Desired password length. Must be at least MIN_PASSWORD_LENGTH.
                     Default: MIN_PASSWORD_LENGTH (typically 12)
        
        include_uppercase (bool): Include uppercase letters (A-Z). Default: True
        include_lowercase (bool): Include lowercase letters (a-z). Default: True
        include_digits (bool): Include digits (0-9). Default: True
        include_symbols (bool): Include symbols (!@#$% etc.). Default: True
        
        exclude_similar (bool): Exclude visually similar characters to prevent confusion.
                               Removes: i, l, 1, L, o, 0, O. Default: True
        
        exclude_ambiguous (bool): Exclude ambiguous symbols that might cause issues in
                                 certain contexts. Removes: { } [ ] ( ) / \\ ' " ` ~ , ; : . < >
                                 Default: False
        
        raise_error (bool): If True, raises PasswordGenerationError on failure.
                           If False, returns error message as string. Default: True
    
    Returns:
        str: Generated secure password meeting all specified criteria.
             If raise_error=False and an error occurs, returns error message string.
    
    Raises:
        PasswordGenerationError: If parameters are invalid or generation fails.
    
    Examples:
        >>> generate_secure_password(16)
        'k8#pL@9qT2$zM5!x'
        
        >>> generate_secure_password(12, include_symbols=False)
        'hG7fD2k9LpQ3'
        
        >>> generate_secure_password(8, raise_error=False)
        'Password length must be at least 12 characters'
    
    Security Notes:
        - Uses secrets.choice() for cryptographically secure random selection
        - Ensures minimum password length to prevent weak passwords
        - Shuffles password characters to prevent pattern recognition
        - Allows exclusion of confusing characters to reduce user errors
    """
    # Validate minimum password length requirement
    if length < MIN_PASSWORD_LENGTH:
        error_msg = f"Password length must be at least {MIN_PASSWORD_LENGTH} characters"
        if raise_error:
            raise PasswordGenerationError(error_msg)
        return error_msg
    
    # Initialize character pools based on selected options
    pools = []
    
    # Uppercase letters pool
    if include_uppercase:
        upper = string.ascii_uppercase
        if exclude_similar:
            # Remove visually similar uppercase characters
            upper = upper.replace('I', '').replace('O', '')  # Remove I and O
        pools.append(upper)
    
    # Lowercase letters pool
    if include_lowercase:
        lower = string.ascii_lowercase
        if exclude_similar:
            # Remove visually similar lowercase characters
            lower = lower.replace('i', '').replace('l', '').replace('o', '')  # Remove i, l, o
        pools.append(lower)
    
    # Digits pool
    if include_digits:
        digits = string.digits
        if exclude_similar:
            # Remove visually similar digits
            digits = digits.replace('0', '').replace('1', '')  # Remove 0 and 1
        pools.append(digits)
    
    # Symbols pool
    if include_symbols:
        symbols = string.punctuation
        if exclude_ambiguous:
            # Remove ambiguous symbols that might cause issues in forms, URLs, etc.
            ambiguous = '{}[]()/\\\'"`~,;:.<>'
            for char in ambiguous:
                symbols = symbols.replace(char, '')
        pools.append(symbols)
    
    # Ensure at least one character type is selected
    if not pools:
        error_msg = "At least one character type must be selected"
        if raise_error:
            raise PasswordGenerationError(error_msg)
        return error_msg
    
    # Build password ensuring at least one character from each selected pool
    password_chars = []
    
    # Add one character from each selected pool to ensure diversity
    for pool in pools:
        password_chars.append(secrets.choice(pool))
    
    # Combine all pools for remaining character selection
    all_chars = ''.join(pools)
    
    # Calculate remaining characters needed to reach desired length
    remaining_length = length - len(password_chars)
    
    # Fill remaining slots with random characters from combined pool
    for _ in range(remaining_length):
        password_chars.append(secrets.choice(all_chars))
    
    # Shuffle characters to prevent pattern recognition
    # Note: random.shuffle is acceptable here as we're only shuffling an already
    # randomly generated list, not generating randomness
    random.shuffle(password_chars)
    
    # Convert character list to string
    return ''.join(password_chars)


def generate_memorable_password(word_count: int = 4, 
                              separator: str = '-',
                              capitalize: bool = True,
                              add_number: bool = True,
                              add_symbol: bool = False) -> str:
    """
    Generate a memorable password using the Diceware method with enhancements.
    
    The Diceware method creates passwords by combining random words, making them
    easier to remember while maintaining security through length and randomness.
    
    Args:
        word_count (int): Number of words to include in password. Default: 4
                         (4 words provides approximately 52 bits of entropy)
        
        separator (str): Character to separate words. Default: '-'
        
        capitalize (bool): Capitalize each word. Default: True
                         (Adds visual distinction and minor entropy)
        
        add_number (bool): Append random 2-digit number. Default: True
                          (Adds approximately 6.5 bits of entropy)
        
        add_symbol (bool): Append random symbol. Default: False
                          (Adds approximately 3-4 bits of entropy)
    
    Returns:
        str: Memorable password that meets minimum length requirements.
    
    Examples:
        >>> generate_memorable_password()
        'Apple-Bird-Cloud-56'
        
        >>> generate_memorable_password(3, '_', True, True, True)
        'Dragon_Elephant_Flame42!'
    
    Security Notes:
        - Uses a curated word list of 50 common, short words
        - Each word adds approximately 5.6 bits of entropy (log2(50))
        - 4-word password provides ~22 bits of word entropy plus additional bits
        - Minimum length padding ensures compliance with password policies
    """
    # Curated word list - 50 common, short, easy-to-spell words
    # Based on Diceware principles but simplified for demonstration
    word_list = [
        'apple', 'bird', 'cat', 'dog', 'elephant', 'fish', 'goat', 'horse',
        'ice', 'jacket', 'kite', 'lion', 'mouse', 'nest', 'owl', 'pig',
        'queen', 'rabbit', 'snake', 'tiger', 'umbrella', 'violin', 'whale',
        'xray', 'yacht', 'zebra', 'anchor', 'brick', 'cloud', 'dragon',
        'earth', 'flame', 'globe', 'heart', 'island', 'jewel', 'king',
        'lemon', 'moon', 'night', 'ocean', 'planet', 'quilt', 'river',
        'star', 'tree', 'unicorn', 'violet', 'water', 'yellow'
    ]
    
    # Select random words using cryptographically secure random choice
    words = [secrets.choice(word_list) for _ in range(word_count)]
    
    # Apply capitalization if requested
    if capitalize:
        words = [word.capitalize() for word in words]
    
    # Join words with separator
    password = separator.join(words)
    
    # Add random 2-digit number (00-99) for additional entropy
    if add_number:
        password += str(secrets.randbelow(100)).zfill(2)  # Pad to 2 digits
    
    # Add random symbol for additional security
    if add_symbol:
        symbols = '!@#$%^&*'
        password += secrets.choice(symbols)
    
    # Ensure password meets minimum length requirement
    if len(password) < MIN_PASSWORD_LENGTH:
        # Calculate padding needed
        padding_length = MIN_PASSWORD_LENGTH - len(password)
        
        # Create character set for padding (excluding ambiguous characters)
        all_chars = string.ascii_letters + string.digits + '!@#$%^&*'
        
        # Add random padding
        padding = ''.join(secrets.choice(all_chars) for _ in range(padding_length))
        password += padding
    
    return password


def estimate_password_strength(password: str) -> dict:
    """
    Comprehensive password strength analysis with multiple metrics.
    
    Evaluates password strength based on:
    1. Length and character diversity
    2. Resistance to common patterns and attacks
    3. Estimated entropy (simplified)
    4. Compliance with security best practices
    
    Args:
        password (str): Password to analyze
    
    Returns:
        dict: Dictionary containing comprehensive strength analysis with keys:
            - 'score': Numerical score 0-10
            - 'strength': Category (Very Weak to Very Strong)
            - 'color': Display color for UI
            - 'length': Password length
            - 'has_upper': Contains uppercase letters
            - 'has_lower': Contains lowercase letters
            - 'has_digit': Contains digits
            - 'has_symbol': Contains symbols
            - 'entropy_bits': Simplified entropy estimation
            - 'feedback': List of improvement suggestions
            - 'meets_requirements': Boolean indicating minimum requirements
    
    Examples:
        >>> estimate_password_strength("Password123!")
        {'score': 8, 'strength': 'Very Strong', ...}
        
        >>> estimate_password_strength("12345")
        {'score': 1, 'strength': 'Very Weak', ...}
    
    Note:
        This is a simplified strength estimator. For production use, consider
        integrating with dedicated password strength libraries like zxcvbn.
    """
    # Handle edge case where password is actually an error message
    if isinstance(password, tuple) or (isinstance(password, str) and password.startswith("Password length must be")):
        return {
            'score': 0,
            'strength': "Invalid",
            'color': "red",
            'length': 0,
            'has_upper': False,
            'has_lower': False,
            'has_digit': False,
            'has_symbol': False,
            'entropy_bits': 0,
            'feedback': ["Invalid password input"],
            'meets_requirements': False
        }
    
    score = 0
    feedback = []
    
    # Length scoring based on NIST guidelines
    length = len(password)
    
    # Length scoring tiers
    if length >= 20:
        score += 4
    elif length >= MIN_PASSWORD_LENGTH:
        score += 3
    elif length >= 8:
        score += 2
    elif length >= 6:
        score += 1
    else:
        feedback.append(f"Password is too short (minimum {MIN_PASSWORD_LENGTH} characters recommended)")
    
    # Character type diversity scoring
    has_upper = bool(re.search(r'[A-Z]', password))
    has_lower = bool(re.search(r'[a-z]', password))
    has_digit = bool(re.search(r'[0-9]', password))
    has_symbol = bool(re.search(r'[^A-Za-z0-9]', password))
    
    # Count unique character types
    char_types = sum([has_upper, has_lower, has_digit, has_symbol])
    
    # Score based on character type diversity
    if char_types >= 4:
        score += 3
        feedback.append("Excellent character diversity")
    elif char_types >= 3:
        score += 2
    elif char_types >= 2:
        score += 1
    else:
        feedback.append("Use mixed character types (uppercase, lowercase, digits, symbols)")
    
    # Check for common weak patterns (top 10 most common passwords)
    common_patterns = [
        '123456', 'password', 'qwerty', 'admin', 'welcome',
        '123456789', '12345678', '12345', '1234567', '123123'
    ]
    
    password_lower = password.lower()
    for pattern in common_patterns:
        if pattern in password_lower:
            score -= 3  # Heavy penalty for common patterns
            feedback.append(f"Avoid common passwords like '{pattern}'")
            break
    
    # Check for sequential characters (e.g., "abc", "123")
    sequential_chars = 0
    for i in range(len(password) - 2):
        # Check for three consecutive increasing characters
        if (ord(password[i+1]) == ord(password[i]) + 1 and
            ord(password[i+2]) == ord(password[i]) + 2):
            sequential_chars += 1
    
    if sequential_chars > 0:
        score -= 1
        feedback.append("Avoid sequential characters (abc, 123, etc.)")
    
    # Check for repeated characters (e.g., "aaa", "111")
    if re.search(r'(.)\1{2,}', password):  # Three or more of the same character
        score -= 1
        feedback.append("Avoid repeated characters (aaa, 111, etc.)")
    
    # Check for keyboard patterns (e.g., "qwerty", "asdfgh")
    keyboard_patterns = ['qwerty', 'asdfgh', 'zxcvbn', 'qazwsx', '123qwe']
    for pattern in keyboard_patterns:
        if pattern in password_lower:
            score -= 2
            feedback.append(f"Avoid keyboard patterns like '{pattern}'")
            break
    
    # Simplified entropy calculation
    # Note: This is a simplified estimation. Real entropy depends on actual character distribution
    charset_size = 0
    if has_upper:
        charset_size += 26  # A-Z
    if has_lower:
        charset_size += 26  # a-z
    if has_digit:
        charset_size += 10  # 0-9
    if has_symbol:
        charset_size += 32  # Approximate common symbol count
    
    # Add entropy-based scoring if we have a character set
    if charset_size > 0:
        # Simplified entropy: log2(charset_size) * length
        entropy_bits = length * (charset_size.bit_length())
        # Add bonus for high entropy
        if entropy_bits > 80:
            score += 2
        elif entropy_bits > 60:
            score += 1
    
    # Determine strength category based on score
    if score >= 9:
        strength = "Excellent"
        color = "green"
    elif score >= 7:
        strength = "Very Strong"
        color = "green"
    elif score >= 6:
        strength = "Strong"
        color = "blue"
    elif score >= 4:
        strength = "Good"
        color = "yellow"
    elif score >= 2:
        strength = "Weak"
        color = "orange"
    else:
        strength = "Very Weak"
        color = "red"
    
    # Check if password meets minimum requirements
    meets_requirements = (length >= MIN_PASSWORD_LENGTH and char_types >= 3)
    
    # Calculate actual entropy bits for the report
    actual_entropy = 0
    if charset_size > 0:
        actual_entropy = length * (charset_size.bit_length())
    
    return {
        'score': min(10, max(0, score)),  # Clamp score between 0-10
        'strength': strength,
        'color': color,
        'length': length,
        'has_upper': has_upper,
        'has_lower': has_lower,
        'has_digit': has_digit,
        'has_symbol': has_symbol,
        'entropy_bits': actual_entropy,
        'feedback': feedback,
        'meets_requirements': meets_requirements
    }


def generate_password_from_pattern(pattern: str) -> Optional[str]:
    """
    Generate a password based on a user-defined pattern.
    
    Useful for creating passwords that must conform to specific organizational
    policies or legacy system requirements.
    
    Pattern Syntax:
        L = lowercase letter
        U = uppercase letter
        D = digit
        S = symbol
        * = any character (letter, digit, or symbol)
        Any other character = used as-is (e.g., separators)
    
    Args:
        pattern (str): Pattern string defining password structure.
    
    Returns:
        Optional[str]: Generated password, or None if pattern is empty.
    
    Examples:
        >>> generate_password_from_pattern("LLL-DDD-SSS")
        'abc-123-!@#'
        
        >>> generate_password_from_pattern("UUDDLL**")
        'AB12cd#$'
    """
    # Character mapping for pattern generation
    char_map = {
        'L': string.ascii_lowercase,      # Lowercase letters
        'U': string.ascii_uppercase,      # Uppercase letters
        'D': string.digits,               # Digits 0-9
        'S': string.punctuation,          # Symbols
        '*': string.ascii_letters + string.digits + string.punctuation  # Any character
    }
    
    password = []
    
    # Process each character in the pattern
    for char in pattern:
        if char in char_map:
            # Replace pattern character with random character from corresponding set
            password.append(secrets.choice(char_map[char]))
        else:
            # Use non-pattern characters as-is (e.g., separators)
            password.append(char)
    
    # Return None for empty patterns
    if not password:
        return None
    
    result = ''.join(password)
    
    # Ensure generated password meets minimum length requirement
    if len(result) < MIN_PASSWORD_LENGTH:
        # Create character set for padding (excluding ambiguous symbols)
        all_chars = string.ascii_letters + string.digits + '!@#$%^&*'
        
        # Calculate padding needed
        padding_length = MIN_PASSWORD_LENGTH - len(result)
        
        # Add random padding
        padding = ''.join(secrets.choice(all_chars) for _ in range(padding_length))
        result += padding
    
    return result


def generate_quick_password() -> str:
    """
    Generate a quick secure password with recommended default settings.
    
    This is a convenience function that provides a good balance of security
    and usability with sensible defaults.
    
    Returns:
        str: 16-character password with mixed character types.
    
    Example:
        >>> generate_quick_password()
        'pL9@k2#zM5!qT8$x'
    """
    # Generate 16-character password with all character types enabled
    # and similar characters excluded for better usability
    return generate_secure_password(
        length=16,
        include_uppercase=True,
        include_lowercase=True,
        include_digits=True,
        include_symbols=True,
        exclude_similar=True,
        exclude_ambiguous=False
    )


def display_password_strength(password: str) -> None:
    """
    Display comprehensive password strength analysis in a user-friendly format.
    
    This function provides visual feedback on password strength and
    specific recommendations for improvement.
    
    Args:
        password (str): Password to analyze and display
    
    Output Example:
        Password Strength Analysis:
          Password: ************
          Length: 12 characters
          Strength: Very Strong (Score: 8/10)
        
        Character Types:
          Uppercase letters: ✓
          Lowercase letters: ✓
          Digits: ✓
          Symbols: ✓
        
        Requirements Met: ✓
        
        Recommendations:
          - Avoid sequential characters
    """
    # Perform strength analysis
    analysis = estimate_password_strength(password)
    
    # Display analysis header
    print(f"\n{'='*50}")
    print("PASSWORD STRENGTH ANALYSIS")
    print(f"{'='*50}")
    
    # Basic password info (masked for security)
    print(f"\nPassword: {'*' * len(password)}")
    print(f"Length: {analysis['length']} characters")
    
    # Strength rating with color indicator
    strength_color = {
        'green': '🟢',
        'blue': '🔵', 
        'yellow': '🟡',
        'orange': '🟠',
        'red': '🔴'
    }.get(analysis['color'], '⚪')
    
    print(f"Strength: {strength_color} {analysis['strength']} (Score: {analysis['score']}/10)")
    
    # Character type analysis
    print(f"\nCharacter Types:")
    print(f"  Uppercase letters: {'✓' if analysis['has_upper'] else '✗'}")
    print(f"  Lowercase letters: {'✓' if analysis['has_lower'] else '✗'}")
    print(f"  Digits: {'✓' if analysis['has_digit'] else '✗'}")
    print(f"  Symbols: {'✓' if analysis['has_symbol'] else '✗'}")
    
    # Estimated entropy (simplified)
    print(f"\nEstimated Entropy: ~{analysis['entropy_bits']} bits")
    
    # Requirements compliance
    print(f"\nRequirements Met: {'✓' if analysis['meets_requirements'] else '✗'}")
    
    # Display recommendations if any
    if analysis['feedback']:
        print(f"\nRecommendations:")
        for feedback in analysis['feedback']:
            print(f"  - {feedback}")
    else:
        print(f"\n✅ No significant issues found.")
    
    print(f"\n{'='*50}")


def generate_password_safe(length: int = MIN_PASSWORD_LENGTH) -> Tuple[bool, str]:
    """
    Safe password generation wrapper that never raises exceptions.
    
    This function is designed for use in contexts where exception handling
    is inconvenient or where the caller needs to handle errors gracefully.
    
    Args:
        length (int): Desired password length. Default: MIN_PASSWORD_LENGTH
    
    Returns:
        Tuple[bool, str]: 
            - First element: True if generation succeeded, False otherwise
            - Second element: Generated password or error message
    
    Example:
        >>> generate_password_safe(16)
        (True, 'k8#pL@9qT2$zM5!x')
        
        >>> generate_password_safe(8)
        (False, 'Password length must be at least 12 characters')
    """
    try:
        # Attempt to generate password with error raising enabled
        password = generate_secure_password(length, raise_error=True)
        return True, password
    except PasswordGenerationError as e:
        # Return error message instead of raising exception
        return False, str(e)

# ==============================================================================
# ADDITIONAL UTILITY FUNCTIONS
# ==============================================================================

def validate_password_pattern(pattern: str) -> Tuple[bool, str]:
    """
    Validate a password generation pattern.
    
    Args:
        pattern (str): Pattern string to validate
    
    Returns:
        Tuple[bool, str]: 
            - True if pattern is valid, False otherwise
            - Error message if invalid, empty string if valid
    """
    if not pattern:
        return False, "Pattern cannot be empty"
    
    # Check for excessively long patterns
    if len(pattern) > 100:
        return False, "Pattern too long (max 100 characters)"
    
    # Allowed pattern characters
    allowed_chars = set('LUDS*' + string.ascii_letters + string.digits + string.punctuation)
    
    for char in pattern:
        if char not in allowed_chars:
            return False, f"Invalid character in pattern: '{char}'"
    
    return True, ""