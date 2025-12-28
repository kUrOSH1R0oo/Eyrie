"""
Eyrie User Interface Components

This module provides display and interaction utilities for the Eyrie password manager.
It includes functions for formatting and displaying data, clipboard management,
and user interaction helpers. The UI components are designed to be:
- Clear and readable for command-line interfaces
- Secure in handling sensitive data like passwords
- Platform-agnostic with clipboard support
- User-friendly with proper formatting and validation

Key Features:
- Tabular display of password entries with proper truncation
- Detailed entry viewing with timestamp formatting
- Secure clipboard operations with auto-clear functionality
- Progress indicators for long-running operations
- Input validation for user choices

Author: A1SBERG
Dependencies: pyperclip for cross-platform clipboard support
"""

import sys
import pyperclip
import threading
import time
from typing import List, Dict, Optional, Any
from datetime import datetime

# ==============================================================================
# ENTRY DISPLAY FUNCTIONS
# ==============================================================================

def display_entries_table(entries: List[Dict], show_password: bool = False) -> None:
    """
    Display password entries in a formatted ASCII table.
    
    This function creates a clean, readable table view of password entries
    with proper column alignment and data truncation for long values.
    
    Args:
        entries (List[Dict]): List of entry dictionaries. Each entry should contain:
            - id: Entry identifier (required for table)
            - title: Entry title/name
            - username: Username or email
            - category: Entry category
            - created_at: Creation timestamp (string, int, or float)
            - password: Password (only shown if show_password=True)
        
        show_password (bool): Whether to include password column in the table.
                              Default: False (passwords are hidden)
    
    Returns:
        None: Outputs directly to console
        
    Example Output:
        ID  | Title                   | Username/Email   | Category   | Created
        ----------------------------------------------------------------------
        1   | Google Account          | user@gmail.com   | Web        | 2023/01/15
        2   | GitHub                  | developer         | Development| 2023/02/20
    
    Security Note:
        - Passwords are hidden by default to prevent accidental exposure
        - When show_password=True, passwords are truncated to 20 characters
        - Consider user consent and environment before showing passwords
    """
    if not entries:
        print("[-] No entries found")
        return
    
    # Prepare table data with formatted strings
    table_data = []
    
    for entry in entries:
        # Format title with proper capitalization
        title = entry.get('title', 'Unknown')
        # Capitalize each word in title for consistency
        title_formatted = ' '.join(word.capitalize() for word in str(title).split())
        
        # Format category similarly
        category = entry.get('category', 'General')
        category_formatted = ' '.join(word.capitalize() for word in str(category).split())
        
        # Build row with formatted data
        row = [
            entry.get('id', 'N/A'),                      # Entry ID
            title_formatted[:30],                        # Title (truncated to 30 chars)
            entry.get('username', '')[:20],              # Username (truncated to 20 chars)
            category_formatted[:15]                      # Category (truncated to 15 chars)
        ]
        
        # Format creation date for display
        created = entry.get('created_at')
        if created:
            if isinstance(created, str):
                # If already a string, use first 10 characters (YYYY/MM/DD)
                row.append(created[:10])
            else:
                # Convert numeric timestamp to formatted date
                try:
                    row.append(datetime.fromtimestamp(float(created)).strftime("%Y/%m/%d"))
                except (ValueError, TypeError, OSError):
                    # Fallback if timestamp conversion fails
                    row.append('')
        else:
            row.append('')  # Empty cell if no creation date
        
        # Add password column if requested
        if show_password:
            row.append(entry.get('password', '')[:20])  # Password (truncated to 20 chars)
        
        table_data.append(row)
    
    # Define table headers
    headers = ['ID', 'Title', 'Username/Email', 'Category', 'Created']
    if show_password:
        headers.append('Password')
    
    # Calculate optimal column widths based on data
    col_widths = []
    for i, header in enumerate(headers):
        # Start with header width as minimum
        max_width = len(header)
        # Find maximum data width in this column
        for row in table_data:
            cell_length = len(str(row[i]))
            if cell_length > max_width:
                max_width = cell_length
        # Add padding for readability
        col_widths.append(max_width + 2)  # 2 spaces padding
    
    # Print table header
    header_row = []
    for i, header in enumerate(headers):
        header_row.append(header.ljust(col_widths[i]))
    print(' | '.join(header_row))
    
    # Print separator line (dashes)
    separator_length = sum(col_widths) + len(headers) * 3 - 1  # 3 chars for " | " separators
    print('-' * separator_length)
    
    # Print table rows
    for row in table_data:
        data_row = []
        for i, cell in enumerate(row):
            data_row.append(str(cell).ljust(col_widths[i]))
        print(' | '.join(data_row))


def display_entry(entry: Dict, show_password: bool = True, copy_password: bool = False) -> None:
    """
    Display detailed information for a single password entry.
    
    Shows all entry fields in a clean, readable format with proper
    timestamp formatting and optional password display/clipboard copy.
    
    Args:
        entry (Dict): Entry dictionary containing:
            - id: Entry identifier
            - title: Entry title
            - username: Username or email
            - url: Associated URL (optional)
            - category: Entry category
            - password: Password (if show_password=True)
            - created_at: Creation timestamp
            - updated_at: Last update timestamp
        
        show_password (bool): Whether to display the password field.
                              Default: True (show password)
        
        copy_password (bool): Whether to automatically copy password to clipboard.
                              Default: False (manual copy required)
    
    Returns:
        None: Outputs directly to console
    
    Example Output:
        ==================================================
        Entry #1
        ==================================================
        Title:       Google Account
        Username:    user@gmail.com
        URL:         https://accounts.google.com
        Category:    Web
        Password:    SuperSecretPassword123!
        Created:     2023/01/15 14:30:45
        Updated:     2023/06/20 09:15:30
        ==================================================
    """
    # Print entry header
    print("=" * 50)
    print(f"Entry #{entry.get('id', 'N/A')}")
    print("=" * 50)
    
    # Display basic entry information
    print(f"Title:       {entry.get('title', 'Unknown')}")
    print(f"Username:    {entry.get('username', '')}")
    print(f"URL:         {entry.get('url', '')}")
    print(f"Category:    {entry.get('category', 'General')}")
    
    # Handle password display
    password = entry.get('password', '')
    
    if show_password and password:
        print(f"Password:    {password}")
        if copy_password:
            # Auto-copy password to clipboard
            if copy_to_clipboard(password, timeout=30):
                print("[+] Password copied to clipboard (will clear in 30 seconds)")
            else:
                print("[-] Failed to copy password to clipboard")
    elif show_password:
        print(f"Password:    Not available")
    
    # Format and display creation timestamp
    created = entry.get('created_at')
    if created:
        if isinstance(created, (int, float)):
            # Convert numeric timestamp to formatted datetime
            try:
                created = datetime.fromtimestamp(created).strftime("%Y/%m/%d %H:%M:%S")
            except (ValueError, TypeError, OSError):
                created = str(created)
        elif isinstance(created, str) and created.replace('.', '').isdigit():
            # Handle string representation of numeric timestamp
            try:
                created = datetime.fromtimestamp(float(created)).strftime("%Y/%m/%d %H:%M:%S")
            except (ValueError, TypeError, OSError):
                pass  # Keep original string if conversion fails
    print(f"Created:     {created or ''}")
    
    # Format and display update timestamp
    updated = entry.get('updated_at')
    if updated:
        if isinstance(updated, (int, float)):
            try:
                updated = datetime.fromtimestamp(updated).strftime("%Y/%m/%d %H:%M:%S")
            except (ValueError, TypeError, OSError):
                updated = str(updated)
        elif isinstance(updated, str) and updated.replace('.', '').isdigit():
            try:
                updated = datetime.fromtimestamp(float(updated)).strftime("%Y/%m/%d %H:%M:%S")
            except (ValueError, TypeError, OSError):
                pass
    print(f"Updated:     {updated or ''}")
    
    print("=" * 50)


def copy_entry_password(entry: Dict) -> bool:
    """
    Copy an entry's password to the system clipboard.
    
    This is a convenience wrapper around copy_to_clipboard() specifically
    for password entries with automatic timeout clearing.
    
    Args:
        entry (Dict): Entry dictionary containing a 'password' key
    
    Returns:
        bool: True if password was successfully copied, False otherwise
    
    Security Note:
        - Automatically clears clipboard after 30 seconds
        - Validates that a password exists before attempting copy
        - Provides user feedback on success/failure
    """
    password = entry.get('password', '')
    if not password:
        print("[-] No password available for this entry")
        return False
    
    if copy_to_clipboard(password, timeout=30):
        print("[+] Password copied to clipboard (will clear in 30 seconds)")
        return True
    else:
        print("[-] Failed to copy password to clipboard")
        return False

# ==============================================================================
# VAULT INFORMATION DISPLAY
# ==============================================================================

def display_vault_info(info: Dict) -> None:
    """
    Display vault statistics and metadata in a formatted view.
    
    Shows information about the vault including entry counts, categories,
    creation date, and other metadata.
    
    Args:
        info (Dict): Vault information dictionary containing:
            - version: Vault format version
            - created_at: Vault creation timestamp
            - total_entries: Total number of entries
            - categories: Dictionary of category counts
            - oldest_entry: Date of oldest entry (optional)
            - newest_entry: Date of newest entry (optional)
    
    Returns:
        None: Outputs directly to console
    
    Example Output:
        ==================================================
        Vault Information
        ==================================================
        Version:      1.0
        Created:      2023-01-15 14:30:45
        Total entries: 42
        Entries by category:
        ------------------------------
          Web         : 15
          Development : 12
          Personal    : 8
          Work        : 7
        ==================================================
    """
    print("=" * 50)
    print("Vault Information")
    print("=" * 50)
    
    # Display basic vault metadata
    print(f"Version:      {info.get('version', 'Unknown')}")
    
    # Format and display creation timestamp
    created = info.get('created_at')
    if created:
        if isinstance(created, (int, float)):
            created = datetime.fromtimestamp(created).strftime('%Y-%m-%d %H:%M:%S')
        print(f"Created:      {created}")
    
    print(f"Total entries: {info.get('total_entries', 0)}")
    
    # Display category breakdown if available
    categories = info.get('categories', {})
    if categories:
        print("Entries by category:")
        print("-" * 30)
        
        # Find maximum category name length for alignment
        max_cat_length = max(len(str(cat)) for cat in categories.keys())
        
        # Display each category with aligned counts
        for category, count in sorted(categories.items()):
            # Format category name with proper spacing
            print(f"  {category:<{max_cat_length}} : {count}")
    
    # Display optional entry date range
    oldest = info.get('oldest_entry')
    newest = info.get('newest_entry')
    
    if oldest and newest:
        print(f"\nOldest entry:  {oldest}")
        print(f"Newest entry:  {newest}")
    
    print("=" * 50)

# ==============================================================================
# USER INTERACTION HELPERS
# ==============================================================================

def get_user_choice(prompt: str, valid_choices: List[str], default: Optional[str] = None) -> str:
    """
    Prompt user for input and validate against allowed choices.
    
    This function handles user input validation with clear error messages
    and optional default values. It loops until valid input is received.
    
    Args:
        prompt (str): The prompt to display to the user
        valid_choices (List[str]): List of acceptable response strings
        default (Optional[str]): Default value to return for empty input.
                                If None (default), empty input is not allowed.
    
    Returns:
        str: The validated user choice
    
    Example:
        >>> choice = get_user_choice("Continue? [y/N]: ", ["y", "n", ""], "n")
        Continue? [y/N]: 
        >>> print(choice)  # User pressed Enter
        "n"
    """
    while True:
        # Display prompt and get input
        choice = input(prompt).strip()
        
        # Handle empty input with default
        if not choice and default is not None:
            return default
        
        # Validate input against allowed choices
        if choice in valid_choices:
            return choice
        
        # Provide helpful error message
        print(f"[-] Invalid choice. Options: {', '.join(valid_choices)}")

# ==============================================================================
# CLIPBOARD MANAGEMENT
# ==============================================================================

def copy_to_clipboard(text: str, timeout: int = 30) -> bool:
    """
    Copy text to system clipboard with optional auto-clear timeout.
    
    This function provides secure clipboard handling by automatically
    clearing sensitive data after a specified timeout. It uses a daemon
    thread to manage the timeout without blocking the main application.
    
    Args:
        text (str): The text to copy to clipboard
        timeout (int): Number of seconds after which to clear clipboard.
                      Set to 0 to disable auto-clear. Default: 30 seconds
    
    Returns:
        bool: True if text was successfully copied, False otherwise
    
    Security Features:
        - Auto-clears clipboard after timeout to prevent accidental exposure
        - Only clears if clipboard still contains the original text
        - Uses daemon thread to avoid blocking application exit
        - Handles clipboard errors gracefully
    
    Dependencies:
        Requires pyperclip module for cross-platform clipboard support
        Install with: pip install pyperclip
    
    Example:
        >>> copy_to_clipboard("secret123", timeout=10)
        True  # Clipboard will be cleared after 10 seconds
    """
    try:
        # Copy text to system clipboard
        pyperclip.copy(text)
        
        # Set up auto-clear if timeout specified
        if timeout > 0:
            def clear_clipboard():
                """
                Internal function to clear clipboard after timeout.
                
                This function runs in a separate thread and only clears
                the clipboard if it still contains the original text,
                preventing accidental clearing of other clipboard data.
                """
                # Wait for specified timeout
                time.sleep(timeout)
                try:
                    # Get current clipboard contents
                    current = pyperclip.paste()
                    # Only clear if it's still our text (not overwritten by user)
                    if current == text:
                        pyperclip.copy("")  # Clear clipboard
                except Exception:
                    # Silently ignore errors during cleanup
                    # (clipboard may be unavailable or in use)
                    pass
            
            # Start clear timer as daemon thread
            # Daemon threads automatically exit when main program exits
            clear_thread = threading.Thread(target=clear_clipboard)
            clear_thread.daemon = True
            clear_thread.start()
        
        return True
        
    except Exception as e:
        # Log clipboard error (in production, use proper logging)
        print(f"[-] Clipboard error: {e}")
        return False


def clear_clipboard() -> bool:
    """
    Clear the system clipboard immediately.
    
    Returns:
        bool: True if clipboard was cleared successfully, False otherwise
    
    Note:
        This function clears the clipboard unconditionally.
        Use with caution as it may remove user data.
    """
    try:
        pyperclip.copy("")  # Set clipboard to empty string
        return True
    except Exception:
        return False


def get_clipboard() -> Optional[str]:
    """
    Get current clipboard contents.
    
    Returns:
        Optional[str]: Clipboard text if available, None if failed
    
    Security Note:
        This function reads whatever is in the clipboard, which may
        contain sensitive data. Use responsibly and clear when done.
    """
    try:
        return pyperclip.paste()
    except Exception:
        return None

# ==============================================================================
# PROGRESS INDICATORS
# ==============================================================================

def progress_bar(iteration: int, total: int, prefix: str = '', length: int = 50) -> None:
    """
    Display a progress bar in the console.
    
    This function provides visual feedback for long-running operations
    by showing a progress bar that updates in place.
    
    Args:
        iteration (int): Current progress (0 to total)
        total (int): Target value for 100% completion
        prefix (str): Optional text to display before progress bar
        length (int): Width of the progress bar in characters. Default: 50
    
    Returns:
        None: Outputs directly to console
    
    Example Output:
        Processing... |██████████████████████████████░░░░░| 75% (75/100)
    
    Usage:
        for i in range(total):
            # Do work...
            progress_bar(i + 1, total, "Processing...")
    """
    # Calculate percentage complete
    percent = int(100 * (iteration / float(total)))
    
    # Calculate filled length based on percentage
    filled_length = int(length * iteration // total)
    
    # Create visual bar with filled and empty sections
    bar = '█' * filled_length + '░' * (length - filled_length)
    
    # Write progress bar to console (overwrites previous line)
    sys.stdout.write(f'\r{prefix} |{bar}| {percent}% ({iteration}/{total})')
    sys.stdout.flush()
    
    # Print newline when complete
    if iteration == total:
        sys.stdout.write('\n')
        sys.stdout.flush()