"""
Eyrie Secure Notes Module

Secure note management functionality
"""

import time
from typing import List, Dict, Optional
from datetime import datetime


def display_note_entry(note: Dict, show_content: bool = True) -> None:
    """
    Display detailed information for a secure note.

    Args:
        note (Dict): Note entry dictionary containing:
            - id: Entry identifier
            - title: Note title
            - category: Note category
            - content: Note content
            - created_at: Creation timestamp
            - updated_at: Last update timestamp
        
        show_content (bool): Whether to display the full content.
                            Default: True (show content)
    
    Returns:
        None: Outputs directly to console
    """
    # Print note header
    print("="*60)
    print(f"NOTE {note.get('id', 'N/A')}")
    print("="*60)

    # Display basic note information
    print(f"Title:      {note.get('title', 'Untitled')}")
    print(f"Category:   {note.get('category', 'Notes')}")

    # Format and display creation timestamp
    created = note.get('created_at')
    if created:
        if isinstance(created, (int, float)):
            try:
                created = datetime.fromtimestamp(created).strftime("%Y-%m-%d %H:%M:%S")
            except (ValueError, TypeError, OSError):
                created = str(created)
        elif isinstance(created, str) and created.replace('.','').isdigit():
            try:
                 created = datetime.fromtimestamp(float(created)).strftime("%Y-%m-%d %H:%M:%S")
            except (ValueError, TypeError, OSError):
                pass
    
    print(f"Created:    {created or ''}")

    # Format and display update timestamp
    updated = note.get('updated_at')
    if updated:
        if isinstance(updated, (int, float)):
            try:
                updated = datetime.fromtimestamp(updated).strftime("%Y-%m-%d %H:%M:%S")
            except (ValueError, TypeError, OSError):
                updated = str(updated)
        elif isinstance(updated, str) and updated.replace('.', '').isdigit():
            try:
                updated = datetime.fromtimestamp(float(updated)).strftime("%Y-%m-%d %H:%M:%S")
            except (ValueError, TypeError, OSError):
                pass
    print(f"Updated:    {updated or ''}")

    # Display content metadata
    content = note.get('content', '')
    content_size = len(content.encode('utf-8'))
    print(f"Size:       {content_size} bytes")
    print(f"Lines:      {len(content.splitlines())}")

    print("-"*60)

    if show_content and content:
        print("Content:")
        print("-" * 60)
        print(content)
        print("-"*60)

        # Offer copy to clipboard for small notes
        if len(content) <= 1000:
            from .ui import copy_to_clipboard
            copy_choice = input("Copy content to clipboard? [y/N]: ").strip().lower()
            if copy_choice == 'y':
                if copy_to_clipboard(content, timeout=60):
                    print("[+] Note content copied to clipboard (will clear in 60 seconds)")
                else:
                    print("[-] Failed to copy content to clipboard")
    
    print("="*60)


def display_notes_table(notes: List[Dict]) -> None:
    """
    Display secure notes in a formatted ASCII table.
    
    Args:
        notes (List[Dict]): List of note dictionaries
    
    Returns:
        None: Outputs directly to console
    """
    if not notes:
        print("[-] No notes found")
        return

    # Prepare table data with formatted strings
    table_data = []

    for note in notes:
        # Format title with proper capitalization
        title = note.get('title', 'Untitled')
        title_formatted = ' '.join(word.capitalize() for word in str(title).split())

        # Format category
        category = note.get('category', 'Notes')
        category_formatted = ' '.join(word.capitalize() for word in str(category).split())

        # Format timestamps
        created = note.get('created_at', '')
        created_formatted = ''
        if created:
            if isinstance(created, str):
                created_formatted = created[:10]
            else:
                try:
                    created_formatted = datetime.fromtimestamp(float(created)).strftime("%Y-%m-%d")
                except:
                    created_formatted = ''
        
        # Build row
        row = [
            note.get('id', 'N/A'),
            title_formatted,
            category_formatted,
            created_formatted
        ]

        table_data.append(row)

    # Define table headers and column widths
    headers = ['ID', 'Title', 'Category', 'Created']
    col_widths = [4, 25, 15, 12]  # Fixed widths for notes table

    # Print table header
    header_row = []
    for i, header in enumerate(headers):
        header_row.append(header.ljust(col_widths[i]))
    print(' | '.join(header_row))

    # Print separator line
    separator_length = sum(col_widths) + len(headers) * 3 - 1
    print('-' * separator_length)

    # Print table rows
    for row in table_data:
        data_row = []
        for i, cell in enumerate(row):
            # Truncate if needed, but ensure proper display
            cell_str = str(cell)
            if i == 1:  # Title column
                if len(cell_str) > col_widths[i]:
                    cell_str = cell_str[:col_widths[i]-3] + '...'
            elif i == 2:  # Category column
                if len(cell_str) > col_widths[i]:
                    cell_str = cell_str[:col_widths[i]]
            
            data_row.append(cell_str.ljust(col_widths[i]))
        print(' | '.join(data_row))

    # Display summary
    print(f"\n[+] Total notes: {len(notes)}")

    # Display category summary with title case formatting
    categories = {}
    for note in notes:
        cat = note.get('category', 'Notes')
        # Convert category to title case (first letter of each word uppercase)
        cat_formatted = ' '.join(word.capitalize() for word in str(cat).split())
        categories[cat_formatted] = categories.get(cat_formatted, 0) + 1

    if categories:
        print("[+] Categories summary:")
        for cat in sorted(categories.keys()):
            print(f"  {cat}: {categories[cat]}")


def display_search_results(search_results: List[Dict]) -> None:
    """
    Display search results without preview.
    
    Args:
        search_results (List[Dict]): List of note dictionaries matching search
    
    Returns:
        None: Outputs directly to console
    """
    if not search_results:
        print("[-] No notes found matching your search")
        return
    
    print(f"[+] Found {len(search_results)} note(s) matching your search:")
    print("-" * 60)
    
    for i, note in enumerate(search_results, 1):
        # Format title
        title = note.get('title', 'Untitled')
        title_formatted = ' '.join(word.capitalize() for word in str(title).split())
        
        # Format category with proper capitalization
        category = note.get('category', 'Notes')
        category_formatted = ' '.join(word.capitalize() for word in str(category).split())
        
        # Format created timestamp
        created = note.get('created_at', '')
        created_formatted = ''
        if created:
            try:
                created_formatted = datetime.fromtimestamp(float(created)).strftime("%Y/%m/%d %H:%M:%S")
            except:
                created_formatted = str(created)[:19]
        
        print(f" {i}. ID: {note.get('id', 'N/A')}")
        print(f"    Title: {title_formatted}")
        print(f"    Category: {category_formatted}")
        print(f"    Created: {created_formatted}")
        
        print()  # Empty line between entries


def create_note_from_input() -> Optional[Dict]:
    """
    Interactive note creation using notepad-style input.
    Type 'END' on a new line to finish (END is not stored).

    Returns:
        Optional[Dict]: Note data dictionary or None if cancelled
    """
    from prompt_toolkit import prompt

    while True:
        title = prompt("Note title: ").strip()
        if not title:
            print("[-] Title required")
            continue
        if len(title) < 2:
            print("[-] Title too short")
            continue
        if len(title) > 200:
            print("[-] Title exceeds maximum length (200 characters)")
            continue
        break

    # Get category
    category = prompt("Category [Notes]: ").strip() or "Notes"

    print("-" * 60)
    print("Type your note below. Each line will be saved.")
    print("Type 'END' on a new line when finished (END will not be stored).")
    print("Press Ctrl+C to cancel.")
    print("-" * 60)

    # Collect multiline content with END marker
    lines = []
    line_number = 1

    try:
        while True:
            # Show line number prompt
            line_input = prompt(f"{line_number:3}> ")
            
            # Check for END marker (case-insensitive)
            if line_input.strip().upper() == "END":
                print("[+] Finished input")
                break
            
            lines.append(line_input)
            line_number += 1
            
            # Show progress every 10 lines
            if line_number % 10 == 0:
                current_chars = sum(len(line) for line in lines)
                print(f"[i] {line_number-1} lines, {current_chars} characters so far")
                
    except KeyboardInterrupt:
        print("\n[-] Note creation cancelled")
        return None

    # Join lines with newline (preserve original line breaks)
    content = '\n'.join(lines)

    if not content:
        print("[-] Note content cannot be empty")
        return None

    # Check content size (removed size limit)
    content_size = len(content.encode('utf-8'))

    return {
        'title': title,
        'content': content,
        'category': category,
        'content_size': content_size
    }


def edit_note_content(existing_content: str = "") -> Optional[str]:
    """
    Edit note content using notepad-style interface.
    
    Args:
        existing_content (str): Existing content to edit
        
    Returns:
        Optional[str]: Edited content or None if cancelled
    """
    from prompt_toolkit import prompt
    
    print("\n" + "=" * 60)
    print("EDIT NOTE CONTENT")
    print("-" * 60)
    print("Type your note below. Each line will be saved.")
    print("Type 'END' on a new line when finished (END will not be stored).")
    print("Press Ctrl+C to cancel.")
    print("-" * 60)
    
    # If there's existing content, show it with line numbers
    if existing_content:
        existing_lines = existing_content.split('\n')
        print("[i] Existing content:")
        for i, line in enumerate(existing_lines[:5], 1):
            print(f"{i:3}: {line}")
        if len(existing_lines) > 5:
            print(f"     ... and {len(existing_lines) - 5} more lines")
        print("-" * 60)
    
    # Start with existing lines or empty
    if existing_content:
        lines = existing_content.split('\n')
        line_number = len(lines) + 1
        print(f"[i] Continuing from line {line_number}")
    else:
        lines = []
        line_number = 1
    
    try:
        while True:
            # Show line number prompt
            line_input = prompt(f"{line_number:3}> ")
            
            # Check for END marker (case-insensitive)
            if line_input.strip().upper() == "END":
                print("[+] Finished editing")
                break
            
            # If we're editing existing content and want to delete a line,
            # allow typing "DELETE" or blank line to remove?
            # For simplicity, just append everything
            lines.append(line_input)
            line_number += 1
            
            # Show progress every 10 lines
            if line_number % 10 == 0:
                current_chars = sum(len(line) for line in lines)
                print(f"[i] {line_number-1} lines, {current_chars} characters so far")
                
    except KeyboardInterrupt:
        print("\n[-] Editing cancelled")
        return None
    
    # Join lines with newline
    content = '\n'.join(lines)
    
    if not content:
        print("[-] Note content cannot be empty")
        return None
    
    # Check content size (removed size limit)
    content_size = len(content.encode('utf-8'))
    
    # Show size info
    print(f"[+] Note size: {content_size} bytes")
    if content_size >= 1024 * 1024:
        print(f"[+] Note size: {content_size/(1024*1024):.2f} MB")
    elif content_size >= 1024:
        print(f"[+] Note size: {content_size/1024:.2f} KB")
    
    return content