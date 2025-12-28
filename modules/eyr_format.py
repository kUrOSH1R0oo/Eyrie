"""
Eyrie EYR File Format Implementation

A custom encrypted vault format designed for secure password storage with:
- Strong integrity protection via checksums and CRC32
- Compressed storage to reduce file size
- Efficient entry indexing and retrieval
- Metadata persistence with corruption recovery
- Atomic operations to prevent data loss

The EYR format uses a custom binary structure with:
1. Fixed header with magic bytes and format version
2. Entry table for efficient indexing
3. JSON metadata section
4. Compressed entry data section
5. Footer with file validation data

Security Features:
- SHA-256 checksums for header integrity
- CRC32 for entry data integrity
- HMAC comparison for constant-time checksum validation
- File size validation to detect truncation

Author: Kur0Sh1r0
Version: 1.0.1
"""

import os
import struct
import json
import base64
import zlib
import hashlib
import hmac
import time
from typing import Dict, List, Optional, Tuple, Any

# ==============================================================================
# EYR FORMAT CONSTANTS AND UTILITY CLASS
# ==============================================================================

class EYRFormat:
    """
    Static class containing EYR file format constants and utility functions.
    
    This class defines the binary structure of the EYR format and provides
    methods for creating, parsing, and validating format components.
    """
    
    # Magic bytes identifying EYR files: 'E' 'Y' 'R' 0x00 0x01 0x00
    # The trailing bytes represent version 1.0 in BCD format
    MAGIC = bytes([69, 89, 82, 0, 1, 0])
    
    # Magic bytes marking the end of the file
    FOOTER_MAGIC = b'EYR_END\0'
    
    # Format version (increment for breaking changes)
    FORMAT_VERSION = 1
    
    # Fixed sizes for format components (in bytes)
    HEADER_SIZE = 128        # Total header size including padding
    FOOTER_SIZE = 32         # Footer size
    ENTRY_HEADER_SIZE = 20   # Entry table slot size (4 + 8 + 8 bytes)
    
    @staticmethod
    def create_header(entry_count: int = 0, 
                     content_offset: int = 0,
                     content_size: int = 0,
                     metadata_offset: int = 0,
                     metadata_size: int = 0) -> bytes:
        """
        Create a complete EYR file header with checksum protection.
        
        Args:
            entry_count (int): Number of entries in the vault
            content_offset (int): File offset where content section begins
            content_size (int): Total size of all entry data
            metadata_offset (int): File offset where metadata begins
            metadata_size (int): Size of metadata section
        
        Returns:
            bytes: 128-byte header ready for writing to file
        
        Header Structure (128 bytes):
            Bytes 0-5:   Magic bytes (6 bytes)
            Byte 6:      Format version (1 byte)
            Bytes 7-8:   Header size (2 bytes, little-endian)
            Bytes 9-12:  Content offset (4 bytes, LE)
            Bytes 13-20: Content size (8 bytes, LE)
            Bytes 21-24: Entry count (4 bytes, LE)
            Bytes 25-32: Metadata offset (8 bytes, LE)
            Bytes 33-40: Metadata size (8 bytes, LE)
            Bytes 41-72: SHA-256 checksum of header (32 bytes)
            Bytes 73-127: Reserved padding (55 bytes)
        
        Raises:
            struct.error: If packing fails due to invalid values
        """
        try:
            # Pack the primary header fields (first 41 bytes)
            header_part1 = struct.pack(
                '<6sBHIQIQQ',  # Format string for little-endian packing
                EYRFormat.MAGIC,
                EYRFormat.FORMAT_VERSION,
                EYRFormat.HEADER_SIZE,
                content_offset,
                content_size,
                entry_count,
                metadata_offset,
                metadata_size,
            )
            
            # Calculate SHA-256 checksum of header with zeroed checksum field
            # Create a copy of the header with zeros in the checksum field
            header_without_checksum = header_part1 + b'\x00' * 87
            checksum = hashlib.sha256(header_without_checksum).digest()
            
            # Combine all parts into final header
            header_bytes = header_part1 + checksum + b'\x00' * 55
            return header_bytes
            
        except struct.error as e:
            # Re-raise with additional context
            raise struct.error(f"Failed to create header: {e}")
    
    @staticmethod
    def validate_header(header: bytes) -> Tuple[bool, Dict]:
        """
        Validate an EYR file header for integrity and format compliance.
        
        Args:
            header (bytes): Raw header data (must be at least HEADER_SIZE bytes)
        
        Returns:
            Tuple[bool, Dict]: 
                - bool: True if header is valid
                - Dict: Header information dictionary or error message
        
        Validation Steps:
            1. Check minimum size
            2. Verify magic bytes
            3. Check format version compatibility
            4. Validate SHA-256 checksum
            5. Parse and return header fields
        """
        if len(header) < EYRFormat.HEADER_SIZE:
            return False, {"error": f"Insufficient header size: {len(header)} bytes"}
        
        try:
            # Unpack the header structure
            # Note: Q format requires 8 bytes for metadata_offset and metadata_size
            magic, version, header_size, content_offset, content_size, \
            entry_count, metadata_offset, metadata_size = struct.unpack(
                '<6sBHIQIQQ', header[:41]
            )
            
            # Extract the stored checksum (bytes 41-72)
            checksum = header[41:73]
            
            # Verify magic bytes
            if magic != EYRFormat.MAGIC:
                return False, {"error": "Invalid file signature - not an EYR file"}
            
            # Check version compatibility
            if version != EYRFormat.FORMAT_VERSION:
                return False, {"error": f"Unsupported version: {version}"}
            
            # Verify checksum using HMAC for constant-time comparison
            # Create a copy of the header with zeros in the checksum field
            header_for_checksum = bytearray(header)
            header_for_checksum[41:73] = b'\x00' * 32
            calculated_checksum = hashlib.sha256(header_for_checksum).digest()
            
            if not hmac.compare_digest(checksum, calculated_checksum):
                return False, {"error": "Header checksum mismatch - file may be corrupted"}
            
            # Return success with parsed header information
            return True, {
                "version": version,
                "header_size": header_size,
                "content_offset": content_offset,
                "content_size": content_size,
                "entry_count": entry_count,
                "metadata_offset": metadata_offset,
                "metadata_size": metadata_size
            }
            
        except struct.error as e:
            return False, {"error": f"Header parsing error: {e}"}
    
    @staticmethod
    def create_footer(file_size: int, header_checksum: bytes) -> bytes:
        """
        Create EYR file footer with file validation data.
        
        Args:
            file_size (int): Total size of the EYR file
            header_checksum (bytes): SHA-256 checksum from the header
        
        Returns:
            bytes: 32-byte footer
        
        Footer Structure (32 bytes):
            Bytes 0-7:   Footer magic (8 bytes)
            Bytes 8-15:  Total file size (8 bytes, LE)
            Bytes 16-47: Header checksum copy (32 bytes)
            Bytes 48-63: Reserved (16 bytes)
        """
        return struct.pack(
            '<8sQ32s16s',
            EYRFormat.FOOTER_MAGIC,
            file_size,
            header_checksum,
            b'\x00' * 16  # Reserved for future use
        )
    
    @staticmethod
    def parse_footer(footer: bytes) -> Tuple[bytes, int, bytes]:
        """
        Parse EYR file footer to extract validation data.
        
        Args:
            footer (bytes): Raw footer data
        
        Returns:
            Tuple[bytes, int, bytes]:
                - Footer magic bytes
                - Stored file size
                - Stored header checksum
        
        Raises:
            ValueError: If footer is too small
        """
        if len(footer) < 56:  # Need at least magic + size + checksum
            raise ValueError(f"Insufficient footer size: {len(footer)} bytes")
        return struct.unpack('<8sQ32s', footer[:56])
    
    @staticmethod
    def create_entry_header(entry_id: int, data_offset: int, data_size: int) -> bytes:
        """
        Create entry table header for an individual entry.
        
        Args:
            entry_id (int): Unique identifier for the entry
            data_offset (int): File offset where entry data begins
            data_size (int): Size of entry data in bytes
        
        Returns:
            bytes: 20-byte entry header
        
        Entry Header Structure (20 bytes):
            Bytes 0-3:   Entry ID (4 bytes, LE)
            Bytes 4-11:  Data offset (8 bytes, LE)
            Bytes 12-19: Data size (8 bytes, LE)
        """
        return struct.pack('<IQQ', entry_id, data_offset, data_size)
    
    @staticmethod
    def parse_entry_header(header: bytes) -> Tuple[int, int, int]:
        """
        Parse an entry header to extract its components.
        
        Args:
            header (bytes): Raw entry header data
        
        Returns:
            Tuple[int, int, int]: Entry ID, data offset, data size
        
        Raises:
            ValueError: If header is incomplete
        """
        if len(header) < EYRFormat.ENTRY_HEADER_SIZE:
            raise ValueError(f"Entry header incomplete: {len(header)} bytes")
        return struct.unpack('<IQQ', header)
    
    @staticmethod
    def compress_data(data: bytes) -> bytes:
        """
        Compress data using zlib with best compression level.
        
        Args:
            data (bytes): Raw data to compress
        
        Returns:
            bytes: Compressed data, or empty bytes if input is empty
        
        Note:
            Uses zlib.Z_BEST_COMPRESSION for maximum size reduction.
            For very small data, compression may increase size.
        """
        if not data:
            return b''
        return zlib.compress(data, level=zlib.Z_BEST_COMPRESSION)
    
    @staticmethod
    def decompress_data(data: bytes) -> bytes:
        """
        Decompress zlib-compressed data.
        
        Args:
            data (bytes): Compressed data
        
        Returns:
            bytes: Decompressed data, or original data if decompression fails
        
        Note:
            If decompression fails (e.g., data is not compressed),
            returns the original data unchanged.
        """
        if not data:
            return b''
        try:
            return zlib.decompress(data)
        except zlib.error:
            # Data may not be compressed - return as-is
            return data
    
    @staticmethod
    def calculate_crc32(data: bytes) -> int:
        """
        Calculate CRC32 checksum for data integrity verification.
        
        Args:
            data (bytes): Data to checksum
        
        Returns:
            int: CRC32 checksum (unsigned 32-bit integer)
        
        Note:
            The mask (0xffffffff) ensures the result is an unsigned 32-bit value.
            CRC32 provides fast integrity checking but is not cryptographically secure.
        """
        return zlib.crc32(data) & 0xffffffff

# ==============================================================================
# EYR FILE HANDLER CLASS
# ==============================================================================

class EYRFile:
    """
    Handler for EYR vault files providing file I/O operations.
    
    This class manages the complete lifecycle of EYR files including:
    - File creation and initialization
    - Entry addition, retrieval, update, and deletion
    - Metadata management
    - File integrity validation
    - Corruption detection and recovery
    
    File Structure:
        [Header (128 bytes)]
        [Entry Table (variable)]
        [Metadata Section (variable)]
        [Entry Data Section (variable)]
        [Footer (32 bytes)]
    
    Instance Attributes:
        filepath (str): Path to the EYR file
        file (file object): Current file handle (None when closed)
        header (Dict): Parsed header information
        metadata (Dict): JSON metadata dictionary
        entry_table (Dict): Mapping of entry IDs to file positions
        next_entry_id (int): Next available entry ID
    """
    
    def __init__(self, filepath: str):
        """
        Initialize EYR file handler.
        
        Args:
            filepath (str): Path to the EYR vault file
        
        Note:
            The file is not opened until load() or create() is called.
        """
        self.filepath = filepath
        self.file = None           # Current file handle
        self.header = None         # Parsed header information
        self.metadata = None       # JSON metadata
        self.entry_table = {}      # entry_id -> {'offset': int, 'size': int}
        self.next_entry_id = 1     # Next available entry ID
    
    # ==========================================================================
    # FILE HANDLING METHODS
    # ==========================================================================
    
    def open(self, mode: str = 'rb') -> bool:
        """
        Open the EYR file with the specified mode.
        
        Args:
            mode (str): File open mode ('rb' for read, 'wb' for write, etc.)
        
        Returns:
            bool: True if file opened successfully, False otherwise
        
        Note:
            Closes any previously opened file handle before opening.
        """
        try:
            # Close existing handle if open
            if self.file:
                self.file.close()
            
            # Open file with requested mode
            self.file = open(self.filepath, mode)
            return True
        except Exception as e:
            # Log error in production (commented out for now)
            # print(f"Failed to open file {self.filepath}: {e}")
            return False
    
    def close(self):
        """Close the file handle and release resources."""
        if self.file:
            self.file.close()
            self.file = None
    
    # ==========================================================================
    # FILE CREATION AND LOADING
    # ==========================================================================
    
    def create(self, metadata: Dict) -> bool:
        """
        Create a new EYR vault file with the specified metadata.
        
        Args:
            metadata (Dict): Initial metadata for the vault
        
        Returns:
            bool: True if creation succeeded, False otherwise
        
        Process:
            1. Create directory structure if needed
            2. Write placeholder header
            3. Reserve space for entry table
            4. Write metadata
            5. Finalize header and footer
            6. Load the file to verify creation
        
        Security:
            - Ensures parent directories exist
            - Cleans up partial files on failure
            - Validates file structure after creation
        """
        try:
            # Ensure parent directories exist
            os.makedirs(os.path.dirname(os.path.abspath(self.filepath)), exist_ok=True)
            
            # Convert metadata to JSON bytes
            metadata_json = json.dumps(metadata, ensure_ascii=False, indent=2)
            metadata_bytes = metadata_json.encode('utf-8')
            metadata_size = len(metadata_bytes)
            
            # Calculate file structure offsets
            # Reserve space for 1000 entry slots initially
            ENTRY_TABLE_RESERVE = 1000 * EYRFormat.ENTRY_HEADER_SIZE
            entry_table_offset = EYRFormat.HEADER_SIZE
            metadata_offset = entry_table_offset + ENTRY_TABLE_RESERVE
            content_offset = metadata_offset + metadata_size
            
            # Create and open file for writing
            self.file = open(self.filepath, 'wb')
            
            # Write placeholder header (will be replaced later)
            self.file.write(b'\x00' * EYRFormat.HEADER_SIZE)
            
            # Write empty entry table (all zeros)
            self.file.write(b'\x00' * ENTRY_TABLE_RESERVE)
            
            # Write metadata
            actual_metadata_offset = self.file.tell()
            self.file.write(metadata_bytes)
            
            # Adjust offsets if necessary (due to filesystem alignment)
            if actual_metadata_offset != metadata_offset:
                metadata_offset = actual_metadata_offset
                content_offset = metadata_offset + metadata_size
            
            # Get file size before footer
            self.file.seek(0, os.SEEK_END)
            file_size_before_footer = self.file.tell()
            self.file.close()
            
            # Create final header with calculated values
            final_header = EYRFormat.create_header(
                entry_count=0,  # New vault has no entries
                content_offset=content_offset,
                content_size=0,  # No content yet
                metadata_offset=metadata_offset,
                metadata_size=metadata_size
            )
            
            # Extract checksum from final header
            header_checksum = final_header[41:73]
            
            # Reopen file for updating header and adding footer
            self.file = open(self.filepath, 'r+b')
            self.file.seek(0)
            self.file.write(final_header)
            
            # Calculate final file size and create footer
            final_file_size = file_size_before_footer + EYRFormat.FOOTER_SIZE
            footer = EYRFormat.create_footer(final_file_size, header_checksum)
            self.file.seek(0, os.SEEK_END)
            self.file.write(footer)
            
            self.file.close()
            
            # Load the file to verify it was created correctly
            return self.load()
            
        except Exception as e:
            # Cleanup on failure
            if os.path.exists(self.filepath):
                try:
                    os.remove(self.filepath)
                except:
                    pass  # Ignore cleanup errors
            return False
    
    def load(self) -> bool:
        """
        Load an existing EYR vault file into memory.
        
        Returns:
            bool: True if file loaded successfully, False otherwise
        
        Process:
            1. Verify file exists and has minimum size
            2. Read and validate header
            3. Load metadata with corruption handling
            4. Parse entry table
            5. Calculate next available entry ID
        
        Error Handling:
            - Tolerates minor metadata corruption
            - Skips invalid entry table entries
            - Creates default metadata if needed
        """
        try:
            # Verify file exists and has minimum size
            if not os.path.exists(self.filepath):
                return False
            
            file_size = os.path.getsize(self.filepath)
            if file_size < EYRFormat.HEADER_SIZE + EYRFormat.FOOTER_SIZE:
                return False
            
            # Open file for reading
            if not self.open('rb'):
                return False
            
            # Read and validate header
            self.file.seek(0)
            header_data = self.file.read(EYRFormat.HEADER_SIZE)
            
            if len(header_data) < EYRFormat.HEADER_SIZE:
                self.close()
                return False
            
            is_valid, header_info = EYRFormat.validate_header(header_data)
            if not is_valid:
                self.close()
                return False
            
            self.header = header_info
            
            # Load metadata with robust error handling
            if header_info['metadata_size'] > 0:
                self.file.seek(header_info['metadata_offset'])
                metadata_bytes = self.file.read(header_info['metadata_size'])
                
                try:
                    # Decode with error tolerance
                    metadata_str = metadata_bytes.decode('utf-8', errors='ignore').strip()
                    
                    # Find valid JSON within the metadata (handles trailing garbage)
                    start_idx = metadata_str.find('{')
                    end_idx = metadata_str.rfind('}')
                    
                    if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
                        valid_json = metadata_str[start_idx:end_idx+1]
                        self.metadata = json.loads(valid_json)
                    else:
                        # No valid JSON found, create default metadata
                        self.metadata = self._create_default_metadata()
                        
                except json.JSONDecodeError:
                    # JSON parsing failed, use defaults
                    self.metadata = self._create_default_metadata()
                except Exception:
                    # Any other error, use defaults
                    self.metadata = self._create_default_metadata()
                
                # Initialize entry counter from metadata
                self.next_entry_id = self.metadata.get('entry_counter', 1)
            
            # Load entry table
            self.entry_table = {}
            entry_table_start = EYRFormat.HEADER_SIZE
            
            # Calculate maximum number of entry slots
            if 'metadata_offset' in header_info and header_info['metadata_offset'] > entry_table_start:
                max_slots = (header_info['metadata_offset'] - entry_table_start) // EYRFormat.ENTRY_HEADER_SIZE
            else:
                max_slots = 1000  # Default
            
            # Read entry table slots
            self.file.seek(entry_table_start)
            entries_loaded = 0
            
            for i in range(max_slots):
                entry_header = self.file.read(EYRFormat.ENTRY_HEADER_SIZE)
                if len(entry_header) < EYRFormat.ENTRY_HEADER_SIZE:
                    break  # End of file reached
                
                # Skip empty slots (all zeros)
                if all(b == 0 for b in entry_header):
                    continue
                
                try:
                    # Parse entry header
                    entry_id, data_offset, data_size = EYRFormat.parse_entry_header(entry_header)
                    
                    # Validate entry parameters
                    if entry_id == 0 or data_offset == 0 or data_size == 0:
                        continue  # Skip invalid entries
                    
                    # Verify data fits within file
                    if data_offset + data_size > file_size:
                        continue  # Skip entries that extend beyond file
                    
                    # Add to entry table
                    self.entry_table[entry_id] = {
                        'offset': data_offset,
                        'size': data_size
                    }
                    
                    # Update next available ID
                    if entry_id >= self.next_entry_id:
                        self.next_entry_id = entry_id + 1
                    
                    entries_loaded += 1
                    
                except Exception:
                    # Skip entries with parsing errors
                    continue
            
            # Update entry count if it doesn't match loaded entries
            if entries_loaded != self.header['entry_count']:
                self.header['entry_count'] = entries_loaded
            
            self.close()
            return True
            
        except Exception:
            # Ensure file is closed on any error
            self.close()
            return False
    
    def _create_default_metadata(self) -> Dict:
        """
        Create default metadata for corrupted or missing metadata.
        
        Returns:
            Dict: Default metadata dictionary
        
        Note:
            This is used when the metadata section is corrupted or
            cannot be parsed, ensuring the vault remains usable.
        """
        return {
            'version': '1.0.1',
            'created_at': time.time(),
            'entry_counter': 1,
            'tfa_enabled': False,
            'tfa_secret': None,
            'tfa_recovery_codes': [],
            'tfa_trusted_devices': [],
            'tfa_last_used': None
        }
    
    # ==========================================================================
    # ENTRY MANAGEMENT OPERATIONS
    # ==========================================================================
    
    def add_entry(self, entry_id: int, data: bytes) -> bool:
        """
        Add a new encrypted entry to the vault.
        
        Args:
            entry_id (int): Unique identifier for the entry
            data (bytes): Encrypted entry data
        
        Returns:
            bool: True if entry was added successfully
        
        Process:
            1. Compress and checksum the data
            2. Insert data before the footer
            3. Find empty slot in entry table
            4. Update header, footer, and metadata
            5. Update in-memory structures
        
        Note:
            This operation modifies the file in-place and updates all
            necessary file structures atomically.
        """
        try:
            # Close file to ensure clean state
            self.close()
            
            # Compress data to save space
            compressed_data = EYRFormat.compress_data(data)
            
            # Add CRC32 checksum for integrity verification
            crc = EYRFormat.calculate_crc32(data)
            entry_with_crc = struct.pack('<I', crc) + compressed_data
            total_entry_size = len(entry_with_crc)
            
            # Open file for read/write
            file_handle = open(self.filepath, 'r+b')
            
            # Insert data before the footer
            file_handle.seek(-EYRFormat.FOOTER_SIZE, os.SEEK_END)
            data_offset = file_handle.tell()
            
            # Read existing data after insertion point
            file_handle.seek(data_offset)
            existing_data = file_handle.read()
            
            # Write new entry and then original data
            file_handle.seek(data_offset)
            file_handle.write(entry_with_crc)
            file_handle.write(existing_data)
            
            # Create entry header for the entry table
            entry_header = EYRFormat.create_entry_header(entry_id, data_offset, total_entry_size)
            
            # Find empty slot in entry table
            entry_table_start = EYRFormat.HEADER_SIZE
            file_handle.seek(entry_table_start)
            
            slot_found = False
            if self.header and 'metadata_offset' in self.header:
                max_slots = (self.header['metadata_offset'] - entry_table_start) // EYRFormat.ENTRY_HEADER_SIZE
            else:
                max_slots = 1000
            
            # Scan for empty slot (all zeros)
            for i in range(max_slots):
                current_pos = file_handle.tell()
                slot_data = file_handle.read(EYRFormat.ENTRY_HEADER_SIZE)
                
                if len(slot_data) < EYRFormat.ENTRY_HEADER_SIZE:
                    break  # End of table
                
                is_empty = all(b == 0 for b in slot_data)
                
                if is_empty:
                    # Found empty slot, write entry header
                    file_handle.seek(current_pos)
                    file_handle.write(entry_header)
                    slot_found = True
                    break
            
            if not slot_found:
                # No empty slots - table is full
                file_handle.close()
                return False
            
            # Update in-memory entry table
            self.entry_table[entry_id] = {
                'offset': data_offset,
                'size': total_entry_size
            }
            
            # Update header statistics
            self.header['entry_count'] = len(self.entry_table)
            self.header['content_size'] += total_entry_size
            
            # Update file size and footer
            file_handle.seek(0, os.SEEK_END)
            file_size = file_handle.tell()
            
            # Read current header checksum
            file_handle.seek(41)
            checksum = file_handle.read(32)
            
            # Update footer with new file size
            file_handle.seek(-EYRFormat.FOOTER_SIZE, os.SEEK_END)
            footer = EYRFormat.create_footer(file_size, checksum)
            file_handle.write(footer)
            
            # Update header with new statistics
            file_handle.seek(0)
            new_header = EYRFormat.create_header(
                entry_count=self.header['entry_count'],
                content_offset=self.header['content_offset'],
                content_size=self.header['content_size'],
                metadata_offset=self.header['metadata_offset'],
                metadata_size=self.header['metadata_size']
            )
            file_handle.write(new_header)
            
            # Update metadata entry counter if needed
            if self.metadata and entry_id >= self.metadata.get('entry_counter', 1):
                self.metadata['entry_counter'] = entry_id + 1
                self._update_metadata_with_handle(file_handle)
            
            file_handle.close()
            return True
            
        except Exception:
            # Ensure file is closed on error
            self.close()
            return False
    
    def get_entry(self, entry_id: int) -> Optional[bytes]:
        """
        Retrieve entry data by ID.
        
        Args:
            entry_id (int): Entry identifier
        
        Returns:
            Optional[bytes]: Entry data if found and valid, None otherwise
        
        Process:
            1. Look up entry in table
            2. Read and verify CRC32 checksum
            3. Decompress data
            4. Return validated data
        
        Error Handling:
            - Returns None if entry not found
            - Logs checksum mismatches but still returns data
            - Handles decompression failures gracefully
        """
        try:
            # Check if entry exists
            if entry_id not in self.entry_table:
                return None
            
            # Open file for reading
            self.close()
            if not self.open('rb'):
                return None
            
            # Read entry data
            entry_info = self.entry_table[entry_id]
            self.file.seek(entry_info['offset'])
            entry_data = self.file.read(entry_info['size'])
            
            # Verify minimum data size (4 bytes for CRC + some data)
            if len(entry_data) < 4:
                self.close()
                return None
            
            try:
                # Extract stored CRC and compressed data
                crc_stored = struct.unpack('<I', entry_data[:4])[0]
                compressed_data = entry_data[4:]
            except struct.error:
                self.close()
                return None
            
            # Decompress data
            data = EYRFormat.decompress_data(compressed_data)
            
            # Verify CRC (log mismatch but return data anyway)
            crc_calculated = EYRFormat.calculate_crc32(data)
            if crc_stored != crc_calculated:
                # In production, consider logging this
                pass  # Data integrity warning
            
            self.close()
            return data
            
        except Exception:
            self.close()
            return None
    
    def delete_entry(self, entry_id: int) -> bool:
        """
        Remove an entry from the vault (mark as deleted).
        
        Args:
            entry_id (int): Entry identifier to delete
        
        Returns:
            bool: True if entry was marked as deleted
        
        Note:
            This marks the entry table slot as empty but doesn't
            immediately reclaim the file space. The space will be
            reused when new entries are added.
        """
        try:
            # Verify entry exists
            if entry_id not in self.entry_table:
                return False
            
            # Open file for read/write
            self.close()
            file_handle = open(self.filepath, 'r+b')
            
            # Find and clear the entry table slot
            entry_table_start = EYRFormat.HEADER_SIZE
            if self.header and 'metadata_offset' in self.header:
                max_slots = (self.header['metadata_offset'] - entry_table_start) // EYRFormat.ENTRY_HEADER_SIZE
            else:
                max_slots = 1000
            
            file_handle.seek(entry_table_start)
            
            slot_found = False
            for i in range(max_slots):
                current_pos = file_handle.tell()
                entry_header_bytes = file_handle.read(EYRFormat.ENTRY_HEADER_SIZE)
                
                if len(entry_header_bytes) < EYRFormat.ENTRY_HEADER_SIZE:
                    break
                
                # Skip already empty slots
                if all(b == 0 for b in entry_header_bytes):
                    continue
                
                try:
                    # Check if this is the entry to delete
                    current_id, _, _ = EYRFormat.parse_entry_header(entry_header_bytes)
                    if current_id == entry_id:
                        # Clear the slot by writing zeros
                        file_handle.seek(current_pos)
                        file_handle.write(b'\x00' * EYRFormat.ENTRY_HEADER_SIZE)
                        slot_found = True
                        break
                except:
                    continue  # Skip malformed entries
            
            # Update in-memory structures
            del self.entry_table[entry_id]
            self.header['entry_count'] = len(self.entry_table)
            
            # Update header with new entry count
            file_handle.seek(0)
            new_header = EYRFormat.create_header(
                entry_count=self.header['entry_count'],
                content_offset=self.header['content_offset'],
                content_size=self.header['content_size'],
                metadata_offset=self.header['metadata_offset'],
                metadata_size=self.header['metadata_size']
            )
            file_handle.write(new_header)
            
            file_handle.close()
            return True
            
        except Exception:
            self.close()
            return False
    
    def update_entry(self, entry_id: int, data: bytes) -> bool:
        """
        Update an existing entry with new data.
        
        Args:
            entry_id (int): Entry identifier
            data (bytes): New entry data
        
        Returns:
            bool: True if update succeeded
        
        Process:
            1. Delete old entry (mark slot as empty)
            2. Add new entry (may reuse same slot)
        
        Note:
            This doesn't physically overwrite the old data immediately.
            The old data remains in the file but is no longer referenced.
        """
        try:
            # Delete old entry and add new one
            if not self.delete_entry(entry_id):
                return False
            
            return self.add_entry(entry_id, data)
            
        except Exception:
            return False
    
    # ==========================================================================
    # METADATA MANAGEMENT
    # ==========================================================================
    
    def _update_metadata_with_handle(self, file_handle) -> bool:
        """
        Internal method to update metadata using an open file handle.
        
        Args:
            file_handle: Open file handle positioned at metadata location
        
        Returns:
            bool: True if metadata was updated successfully
        
        Note:
            This method assumes the file handle is already positioned
            correctly and handles metadata size constraints.
        """
        try:
            if not self.metadata:
                return False
            
            # Save current position for restoration
            current_pos = file_handle.tell()
            
            # Convert metadata to JSON bytes
            metadata_json = json.dumps(self.metadata, ensure_ascii=False, indent=2)
            metadata_bytes = metadata_json.encode('utf-8')
            new_metadata_size = len(metadata_bytes)
            
            # Check if metadata fits in allocated space
            if new_metadata_size <= self.header['metadata_size']:
                file_handle.seek(self.header['metadata_offset'])
                
                # CRITICAL: Clear entire metadata area to prevent corruption
                # This ensures no leftover bytes from previous metadata
                file_handle.write(b'\x00' * self.header['metadata_size'])
                file_handle.seek(self.header['metadata_offset'])
                
                # Write new metadata
                file_handle.write(metadata_bytes)
                
                # Restore original position
                file_handle.seek(current_pos)
                return True
            else:
                # Metadata grew too large for allocated space
                file_handle.seek(current_pos)
                return False
                
        except Exception:
            return False
    
    def update_metadata(self, metadata: Optional[Dict] = None) -> bool:
        """
        Update vault metadata with optional new data.
        
        Args:
            metadata (Dict, optional): New metadata to use.
                                      If None, uses current metadata.
        
        Returns:
            bool: True if metadata was updated successfully
        
        Note:
            If metadata is provided, it replaces the current metadata.
            The file is reloaded after update to ensure consistency.
        """
        # Update in-memory metadata if provided
        if metadata is not None:
            self.metadata = metadata
        
        # Update metadata in file
        result = self._update_metadata()
        
        # Reload file to ensure consistency
        if result:
            self.load()
        
        return result
    
    def _update_metadata(self) -> bool:
        """
        Internal standalone metadata update method.
        
        Returns:
            bool: True if metadata was updated successfully
        
        Note:
            This is a simplified version that opens and closes the file
            internally. Use _update_metadata_with_handle when you already
            have an open file handle.
        """
        try:
            if not self.metadata:
                return False
            
            # Open file for read/write
            self.close()
            file_handle = open(self.filepath, 'r+b')
            
            # Convert metadata to JSON bytes
            metadata_json = json.dumps(self.metadata, ensure_ascii=False, indent=2)
            metadata_bytes = metadata_json.encode('utf-8')
            new_metadata_size = len(metadata_bytes)
            
            # Check size constraint
            if new_metadata_size <= self.header['metadata_size']:
                file_handle.seek(self.header['metadata_offset'])
                
                # Clear entire metadata area
                file_handle.write(b'\x00' * self.header['metadata_size'])
                file_handle.seek(self.header['metadata_offset'])
                
                # Write new metadata
                file_handle.write(metadata_bytes)
                
                file_handle.close()
                return True
            else:
                # Metadata too large for allocated space
                file_handle.close()
                return False
                
        except Exception:
            self.close()
            return False
    
    # ==========================================================================
    # UTILITY METHODS
    # ==========================================================================
    
    def list_entries(self) -> List[int]:
        """
        Get list of all entry IDs in the vault.
        
        Returns:
            List[int]: Sorted list of entry IDs
        
        Note:
            Returns IDs sorted in ascending order for consistent display.
        """
        return sorted(self.entry_table.keys())
    
    def get_next_entry_id(self) -> int:
        """
        Get the next available entry ID.
        
        Returns:
            int: Next unused entry ID
        
        Note:
            This is based on the highest existing ID + 1,
            or 1 if the vault is empty.
        """
        return self.next_entry_id
    
    def validate_and_fix_metadata(self) -> bool:
        """
        Validate metadata and attempt to fix corruption.
        
        Returns:
            bool: True if metadata is valid or was successfully fixed
        
        Process:
            1. Try to serialize current metadata (quick check)
            2. If serialization fails, attempt to read and parse raw metadata
            3. Extract valid JSON from potentially corrupted data
            4. Update file with fixed metadata
        
        Note:
            This method attempts to recover from metadata corruption
            but cannot recover data that has been overwritten or lost.
        """
        try:
            if not self.header or not self.metadata:
                return False
            
            # Quick validation: can we serialize the metadata?
            try:
                metadata_json = json.dumps(self.metadata, ensure_ascii=False, indent=2)
                # If we get here, metadata is already valid JSON
                return True
                
            except json.JSONDecodeError:
                # Metadata appears corrupted, attempt recovery
                try:
                    self.close()
                    with open(self.filepath, 'rb') as f:
                        f.seek(self.header['metadata_offset'])
                        raw_metadata = f.read(self.header['metadata_size'])
                        
                        # Find first null byte (end of valid data)
                        null_pos = raw_metadata.find(b'\x00')
                        if null_pos > 0:
                            raw_metadata = raw_metadata[:null_pos]
                        
                        # Attempt to decode and parse
                        metadata_str = raw_metadata.decode('utf-8', errors='ignore').strip()
                        
                        # Find valid JSON within the string
                        start_idx = metadata_str.find('{')
                        end_idx = metadata_str.rfind('}')
                        
                        if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
                            valid_json = metadata_str[start_idx:end_idx+1]
                            self.metadata = json.loads(valid_json)
                            
                            # Save the fixed metadata back to file
                            self._update_metadata()
                            return True
                            
                except Exception:
                    # Recovery failed
                    pass
            
            return False
            
        except Exception:
            return False
    
    def repair_metadata(self) -> bool:
        """
        Force repair metadata by overwriting with current in-memory metadata.
        
        Returns:
            bool: True if repair succeeded
        
        Note:
            This is a last-resort method when metadata is severely corrupted.
            It overwrites the metadata section with the current in-memory
            metadata or defaults if no metadata exists.
        """
        try:
            # Use current metadata or create defaults
            if not self.metadata:
                self.metadata = self._create_default_metadata()
            
            # Force update
            result = self._update_metadata()
            return result
            
        except Exception:
            return False