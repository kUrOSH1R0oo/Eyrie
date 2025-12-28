"""
Eyrie Vault Export/Import Module
Secure backup and restore operations
"""

import os
import json
import base64
import struct
import zipfile
import tempfile
import shutil
from typing import Optional
from datetime import datetime

from .crypto import (
    derive_master_key, encrypt_data, decrypt_data,
    secure_erase_key, KEY_SIZE
)
from .database import VaultDatabase

def export_vault(db: VaultDatabase, backup_password: str, backup_path: str) -> bool:
    """
    Create encrypted vault backup
    
    Args:
        db: Vault database instance
        backup_password: Backup encryption password
        backup_path: Destination backup file path
    
    Returns:
        True if export succeeded
    """
    try:
        # Fixed salt for reproducible backup keys
        BACKUP_SALT = b'EYRIE_BACKUP_v1.0.1'
        export_key, _ = derive_master_key(backup_password, BACKUP_SALT)
        
        if len(export_key) < KEY_SIZE:
            print("[-] Key derivation failed")
            return False
        
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = db.db_path
            
            metadata = {
                'export_date': datetime.now().isoformat(),
                'format_version': '1.0.1',
                'entry_count': 0
            }
            
            db.connect()
            if not db.eyr_file or not db.eyr_file.load():
                db.close()
                return False
            
            entry_ids = db.eyr_file.list_entries()
            metadata['entry_count'] = len(entry_ids)
            
            if db.eyr_file.metadata:
                vault_meta = db.eyr_file.metadata
                metadata['vault_created'] = vault_meta.get('created_at')
                metadata['vault_version'] = vault_meta.get('version')
            
            db.close()
            
            # Create metadata file
            meta_file = os.path.join(temp_dir, 'metadata.json')
            with open(meta_file, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            # Package vault and metadata
            zip_path = os.path.join(temp_dir, 'vault_export.zip')
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                zipf.write(db_path, 'vault.eyr')
                zipf.write(meta_file, 'metadata.json')
            
            # Encrypt backup
            with open(zip_path, 'rb') as f:
                zip_data = f.read()
            
            nonce, ciphertext, tag = encrypt_data(export_key, zip_data)
            
            # Write backup file with header
            magic = b'EYRIE_BACKUP_v1.0.1'
            magic_padded = magic.ljust(32, b'\x00')
            
            header = struct.pack('!32s12s16s', magic_padded, nonce, tag)
            
            with open(backup_path, 'wb') as f:
                f.write(header)
                f.write(ciphertext)
            
            print(f"[+] Vault exported: {backup_path}")
            return True
            
    except Exception as e:
        print(f"[-] Export failed: {e}")
        return False

def import_vault(db: VaultDatabase, backup_password: str, backup_path: str) -> bool:
    """
    Restore vault from encrypted backup
    
    Args:
        db: Target database instance
        backup_password: Backup password
        backup_path: Backup file path
    
    Returns:
        True if import succeeded
    """
    try:
        BACKUP_SALT = b'EYRIE_BACKUP_v1.0.1'
        import_key, _ = derive_master_key(backup_password, BACKUP_SALT)
        
        if len(import_key) < KEY_SIZE:
            print("[-] Key derivation failed")
            return False
        
        with open(backup_path, 'rb') as f:
            header = f.read(60)
            if len(header) < 60:
                print("[-] Invalid backup file")
                return False
            
            magic, nonce, tag = struct.unpack('!32s12s16s', header)
            magic = magic.rstrip(b'\x00')
            
            if magic != b'EYRIE_BACKUP_v1.0.1':
                print("[-] Invalid backup format")
                return False
            
            ciphertext = f.read()
        
        decrypted = decrypt_data(import_key, nonce, ciphertext, tag)
        
        if decrypted is None:
            print("[-] Decryption failed - incorrect password")
            return False
        
        with tempfile.TemporaryDirectory() as temp_dir:
            zip_path = os.path.join(temp_dir, 'import.zip')
            with open(zip_path, 'wb') as f:
                f.write(decrypted)
            
            try:
                with zipfile.ZipFile(zip_path, 'r') as zipf:
                    if 'vault.eyr' not in zipf.namelist():
                        print("[-] Invalid backup contents")
                        return False
                    
                    zipf.extractall(temp_dir)
            except zipfile.BadZipFile:
                print("[-] Corrupted backup file")
                return False
            
            import_db_path = os.path.join(temp_dir, 'vault.eyr')
            
            if os.path.exists(db.db_path):
                os.remove(db.db_path)
            
            shutil.copy2(import_db_path, db.db_path)
            
            print("[+] Vault imported successfully")
            return True
            
    except Exception as e:
        print(f"[-] Import failed: {e}")
        return False

def export_to_csv(db: VaultDatabase, master_key: bytes, csv_path: str, 
                  include_passwords: bool = False) -> bool:
    """
    Export vault entries to CSV format
    
    Args:
        db: Vault database instance
        master_key: Master encryption key
        csv_path: CSV output file path
        include_passwords: Export password column
    
    Returns:
        True if export succeeded
    """
    try:
        import csv
        
        entries = db.list_entries(master_key)
        
        with open(csv_path, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['ID', 'Title', 'Username', 'URL', 'Category', 'Created']
            
            if include_passwords:
                fieldnames.append('Password')
            
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for entry_summary in entries:
                entry_full = db.get_entry(master_key, entry_summary['id'])
                if not entry_full:
                    continue
                
                row = {
                    'ID': entry_full.get('id', ''),
                    'Title': entry_full.get('title', ''),
                    'Username': entry_full.get('username', ''),
                    'URL': entry_full.get('url', ''),
                    'Category': entry_full.get('category', ''),
                    'Created': entry_full.get('created_at', '')
                }
                
                if include_passwords:
                    row['Password'] = entry_full.get('password', '')
                
                writer.writerow(row)
        
        print(f"[+] CSV exported: {csv_path}")
        return True
        
    except Exception as e:
        print(f"[-] CSV export failed: {e}")
        return False

def import_from_csv(db: VaultDatabase, master_key: bytes, csv_path: str) -> bool:
    """
    Import entries from CSV file
    
    Args:
        db: Vault database instance
        master_key: Master encryption key
        csv_path: CSV source file path
    
    Returns:
        True if import succeeded
    """
    try:
        import csv
        
        with open(csv_path, 'r', newline='', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            
            imported = 0
            failed = 0
            
            for row in reader:
                try:
                    entry_data = {
                        'title': row.get('Title', '').strip(),
                        'username': row.get('Username', '').strip(),
                        'url': row.get('URL', '').strip(),
                        'category': row.get('Category', 'General').strip(),
                        'password': row.get('Password', '').strip()
                    }
                    
                    if not entry_data['title'] or not entry_data['username']:
                        failed += 1
                        continue
                    
                    if db.add_entry(master_key, entry_data):
                        imported += 1
                    else:
                        failed += 1
                        
                except Exception:
                    failed += 1
            
            print(f"[+] CSV import: {imported} successful, {failed} failed")
            return imported > 0
            
    except Exception as e:
        print(f"[-] CSV import failed: {e}")
        return False

def create_backup_schedule(vault_path: str, backup_dir: str, 
                          frequency_days: int = 7, max_backups: int = 10) -> bool:
    """
    Configure automated backup schedule
    
    Args:
        vault_path: Source vault file path
        backup_dir: Backup storage directory
        frequency_days: Backup frequency in days
        max_backups: Maximum backup retention count
    
    Returns:
        True if schedule configured
    """
    try:
        os.makedirs(backup_dir, exist_ok=True)
        
        schedule_file = os.path.join(backup_dir, 'backup_schedule.json')
        
        schedule = {
            'vault_path': os.path.abspath(vault_path),
            'backup_dir': os.path.abspath(backup_dir),
            'frequency_days': frequency_days,
            'max_backups': max_backups,
            'last_backup': None,
            'next_backup': None
        }
        
        with open(schedule_file, 'w') as f:
            json.dump(schedule, f, indent=2)
        
        print(f"[+] Backup schedule configured: {schedule_file}")
        return True
        
    except Exception as e:
        print(f"[-] Schedule configuration failed: {e}")
        return False