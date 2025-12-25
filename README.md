# non_MS_Services

Non-Microsoft Services Audit Tool (non_MS_Services)
===================================================

Purpose:
--------
Lists all Windows services whose executable binaries are NOT
signed by Microsoft.

This allows identifying services that were added after the OS
installation by third-party software.

How it works:
-------------
- Enumerates Windows services
- Extracts executable path
- Filters Microsoft-signed binaries
- Uses file creation timestamp as install-time approximation

Requirements:
-------------
- Windows 10 / 11
- Python 3.10+
- Administrator privileges (recommended)
- tkinter and pywin32 (install it using the install.bat script)

Installation:
-------------
Run install.bat

Start:
------
venv\Scripts\python.exe run_gui.py

Source:
-------
github.com/zeittresor/non_MS_Services
