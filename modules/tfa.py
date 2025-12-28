"""
Eyrie Two-Factor Authentication Module
TOTP (Time-based One-Time Password) implementation
"""
import base64
import hashlib
import hmac
import json
import os
import struct
import time
import qrcode
from typing import Dict, List, Optional, Tuple
import secrets
from datetime import datetime


class TFA:
    """Two-Factor Authentication Manager"""
    
    def __init__(self):
        self.recovery_codes_count = 10
        self.totp_step = 30          # 30 seconds per code
        self.totp_digits = 6         # 6-digit codes
        self.window = 1              # Allow ±1 time step for clock drift
        self.trusted_device_days = 30

    def generate_secret(self) -> str:
        """Generate a new TOTP secret (Base32, 16 characters without padding)"""
        random_bytes = secrets.token_bytes(20)
        return base64.b32encode(random_bytes).decode('utf-8').rstrip('=')

    def generate_totp_code(self, secret: str, timestamp: Optional[int] = None) -> str:
        """Generate current TOTP code from secret"""
        if timestamp is None:
            timestamp = int(time.time())

        # Normalize secret padding
        secret = secret.upper() + '=' * ((8 - len(secret) % 8) % 8)
        try:
            key = base64.b32decode(secret, casefold=True)
        except Exception:
            key = base64.b32decode(secret + '====', casefold=True)

        time_steps = timestamp // self.totp_step
        msg = struct.pack('>Q', time_steps)
        hmac_digest = hmac.new(key, msg, hashlib.sha1).digest()

        offset = hmac_digest[-1] & 0x0F
        truncated_hash = hmac_digest[offset:offset + 4]
        code = struct.unpack('>I', truncated_hash)[0] & 0x7FFFFFFF
        code = code % (10 ** self.totp_digits)
        return f"{code:06d}"

    def verify_totp_code(self, secret: str, code: str) -> bool:
        """Verify TOTP code with ±window tolerance"""
        current_time = int(time.time())
        for i in range(-self.window, self.window + 1):
            ts = current_time + (i * self.totp_step)
            expected = self.generate_totp_code(secret, ts)
            if hmac.compare_digest(code, expected):
                return True
        return False

    def generate_recovery_codes(self) -> List[str]:
        """Generate 10 emergency recovery codes (8 hex chars each)"""
        return [secrets.token_hex(4).upper() for _ in range(self.recovery_codes_count)]

    def save_recovery_codes_to_file(self, recovery_codes: List[str], username: str, 
                                   filepath: Optional[str] = None) -> str:
        """
        Save recovery codes to a text file
        
        Args:
            recovery_codes: List of recovery codes to save
            username: Username associated with the codes
            filepath: Optional custom filepath, defaults to "recovery_codes_username_timestamp.txt"
        
        Returns:
            str: Path to the saved file
        
        Raises:
            Exception: If file cannot be saved
        """
        # Generate default filename if not provided
        if filepath is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            # Create safe filename from username
            safe_username = "".join(c for c in username if c.isalnum() or c in ('_', '-')).rstrip()
            if not safe_username:
                safe_username = "user"
            filename = f"recovery_codes_{safe_username}_{timestamp}.txt"
            filepath = os.path.join(os.getcwd(), filename)
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
        
        # Prepare file content
        content = [
            "=" * 50,
            f"Eyrie Password Manager - Recovery Codes",
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Vault: {username}",
            "",
            "IMPORTANT: Save these codes in a secure place!",
            "These are one-time use codes for account recovery.",
            "Each code can only be used once.",
            "",
            "Recovery Codes:",
            "=" * 50,
            ""
        ]
        
        # Add recovery codes with numbering
        for i, code in enumerate(recovery_codes, 1):
            content.append(f"{i:2d}. {code}")
        
        content.extend([
            "",
            "=" * 50,
            "Instructions:",
            "1. Store this file in a secure location",
            "2. Do not share these codes with anyone",
            "3. Use one code when you can't access your authenticator app",
            "4. Generate new codes after using all of these",
            "5. Each code can be used only once",
            "=" * 50
        ])
        
        # Write to file
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write('\n'.join(content))
            return filepath
        except Exception as e:
            raise Exception(f"Failed to save recovery codes: {e}")

    def verify_recovery_code(self, code: str, used_codes: List[Dict]) -> Tuple[bool, List[Dict]]:
        """Verify recovery code and mark as used if valid"""
        current_time = time.time()
        valid_codes = []

        # Clean up expired/invalid entries
        for c in used_codes:
            if isinstance(c, dict):
                if c.get('expires', 0) > current_time:
                    valid_codes.append(c)
            else:
                # Legacy support
                valid_codes.append({
                    'code': c,
                    'used': False,
                    'used_at': None,
                    'expires': current_time + (86400 * 365)
                })

        for i, stored in enumerate(valid_codes):
            if hmac.compare_digest(code, stored['code']):
                if stored.get('used', False):
                    return False, valid_codes
                if stored.get('expires', 0) <= current_time:
                    return False, valid_codes
                valid_codes[i]['used'] = True
                valid_codes[i]['used_at'] = current_time
                return True, valid_codes

        return False, valid_codes

    def generate_otpauth_uri(self, secret: str, account_name: str, issuer: str = "Eyrie Password Manager") -> str:
        """Generate standard otpauth:// URI for authenticator apps"""
        label = f"{issuer}:{account_name}"
        params = {
            'secret': secret,
            'issuer': issuer,
            'digits': self.totp_digits,
            'period': self.totp_step,
            'algorithm': 'SHA1'
        }
        param_str = '&'.join(f"{k}={v}" for k, v in params.items())
        return f"otpauth://totp/{label}?{param_str}"

    def generate_qr_code(self, otpauth_uri: str) -> Optional[str]:
        """
        Generate **compact** terminal QR code using half-blocks (▀▄█ )
        ≈ half the height of classic full-block version
        """
        try:
            qr = qrcode.QRCode(
                version=1,                              # let it auto-grow
                error_correction=qrcode.constants.ERROR_CORRECT_L,  # smallest size
                box_size=1,
                border=0,                               # no quiet zone → minimal size
            )
            qr.add_data(otpauth_uri)
            qr.make(fit=True)

            matrix = qr.get_matrix()
            if not matrix:
                return None

            height = len(matrix)
            width = len(matrix[0]) if height > 0 else 0

            # Pad with empty row if odd height (rare)
            if height % 2 == 1:
                matrix.append([False] * width)
                height += 1

            lines = []
            for y in range(0, height, 2):
                line = ""
                for x in range(width):
                    upper = matrix[y][x]
                    lower = matrix[y + 1][x] if y + 1 < height else False

                    if upper and lower:
                        line += "█"
                    elif upper:
                        line += "▀"
                    elif lower:
                        line += "▄"
                    else:
                        line += " "
                lines.append(line)

            return "\n".join(lines)

        except Exception as e:
            print(f"[-] QR code generation failed: {e}")
            return None

    def generate_qr_code_with_frame(self, otpauth_uri: str) -> Optional[str]:
        """
        Generate QR code with a border frame for better visibility
        """
        qr_content = self.generate_qr_code(otpauth_uri)
        if not qr_content:
            return None
        
        lines = qr_content.split('\n')
        width = len(lines[0]) if lines else 0
        
        # Add frame
        framed_lines = []
        framed_lines.append("┌" + "─" * width + "┐")
        for line in lines:
            framed_lines.append("│" + line + "│")
        framed_lines.append("└" + "─" * width + "┘")
        
        return "\n".join(framed_lines)

    # ────────────────────────────────────────────────
    #  Legacy / alternative methods (you can remove them)
    # ────────────────────────────────────────────────

    def generate_small_qr_code(self, otpauth_uri: str) -> Optional[str]:
        """DEPRECATED - use generate_qr_code() instead (now compact by default)"""
        return self.generate_qr_code(otpauth_uri)

    # ────────────────────────────────────────────────
    #  Trusted device methods (unchanged)
    # ────────────────────────────────────────────────

    def is_trusted_device(self, device_id: str, trusted_devices: List[Dict]) -> bool:
        current_time = time.time()
        for dev in trusted_devices:
            if dev.get('device_id') == device_id:
                return dev.get('expires', 0) > current_time
        return False

    def add_trusted_device(self, device_id: str, trusted_devices: List[Dict]) -> List[Dict]:
        current_time = time.time()
        expires = current_time + (86400 * self.trusted_device_days)

        # Remove expired
        trusted_devices = [d for d in trusted_devices if d.get('expires', 0) > current_time]

        # Update if exists
        for dev in trusted_devices:
            if dev.get('device_id') == device_id:
                dev['expires'] = expires
                dev['last_used'] = current_time
                return trusted_devices

        # Add new
        trusted_devices.append({
            'device_id': device_id,
            'added': current_time,
            'expires': expires,
            'last_used': current_time
        })

        # Keep max 10 most recently used
        if len(trusted_devices) > 10:
            trusted_devices.sort(key=lambda x: x.get('last_used', 0))
            trusted_devices = trusted_devices[-10:]

        return trusted_devices

    def remove_trusted_device(self, device_id: str, trusted_devices: List[Dict]) -> List[Dict]:
        return [d for d in trusted_devices if d.get('device_id') != device_id]

    def get_device_id(self) -> str:
        import platform
        import uuid
        info = (platform.node() + platform.system()).encode()
        mac = str(uuid.getnode()).encode()
        return hashlib.sha256(info + mac).hexdigest()[:16]

    # ────────────────────────────────────────────────
    #  Utility methods for 2FA setup and management
    # ────────────────────────────────────────────────

    def setup_two_factor_auth(self, username: str, custom_filepath: Optional[str] = None) -> Tuple[str, List[str], str, str]:
        """
        Complete 2FA setup process for a user
        
        Args:
            username: The username for the account
            custom_filepath: Optional custom path to save recovery codes
        
        Returns:
            Tuple containing: (secret, recovery_codes, qr_code, saved_file_path)
        
        Raises:
            Exception: If any part of the setup fails
        """
        try:
            # Generate secret
            secret = self.generate_secret()
            
            # Generate recovery codes
            recovery_codes = self.generate_recovery_codes()
            
            # Save recovery codes to file
            saved_file = self.save_recovery_codes_to_file(recovery_codes, username, custom_filepath)
            
            # Generate QR code
            uri = self.generate_otpauth_uri(secret, username)
            qr_code = self.generate_qr_code_with_frame(uri) or self.generate_qr_code(uri)
            
            return secret, recovery_codes, qr_code, saved_file
            
        except Exception as e:
            raise Exception(f"2FA setup failed: {e}")

    def verify_initial_totp(self, secret: str, user_provided_code: str) -> bool:
        """
        Verify initial TOTP code during 2FA setup
        
        This is used to ensure the user has successfully scanned the QR code
        and their authenticator app is working correctly.
        """
        return self.verify_totp_code(secret, user_provided_code)

    def get_recovery_codes_display(self, recovery_codes: List[str]) -> str:
        """
        Format recovery codes for display to user
        
        Returns:
            Formatted string showing all recovery codes
        """
        lines = ["Recovery Codes:"]
        lines.append("-" * 30)
        for i, code in enumerate(recovery_codes, 1):
            lines.append(f"{i:2d}. {code}")
        lines.append("-" * 30)
        lines.append("Save these codes in a secure location!")
        return "\n".join(lines)


# Singleton instance
tfa_manager = TFA()