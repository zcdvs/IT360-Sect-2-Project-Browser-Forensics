# IT360 Project

## Overview
A tool for analyzing browser-related information such as cookies, extensions, download history, browsing history, login sessions, and cache/autofill data.

## Features
The tool can extract and analyze:

- **Cookies**
  - Name, value, domain, expiration
  - Secure & non-secure cookies
- **Browsing history**
  - URLs and timestamps
  - Chronological timeline creation
- **Download history**
  - File names and URLs
- **Extensions metadata**
  - Detect and flag suspicious extensions (based on permissions)

## Target Platform
- Primary: Chrome and Firefox on **Windows and MacOS**  
- Future: Potential support for **Linux** and other browsers

## Implementation
- **Language:** Python  
- **Artifact selection:** User-focused data (session history, browser data, login information, etc.)  
- **Output format:**  
  - Human-readable text logs  
  - CSV files for further analysis
  - HTML generated report of the data collection 

## Potential Features (Stretch Goals)
- Cross-platform support (Windows, MacOS, and Linux)
- Support for more browsers
- GUI interface
- Scheduling tool execution
- Data integrity through hashing

# Using `run_all.py` and `run_all_gui.py`

This document explains how to use the `run_all.py` and `run_all_gui.py` scripts included in this repository to collect browser artifacts for digital forensics purposes. The instructions assume the repository layout includes the `src/` scripts such as `Chrome_History.py`, `Firefox_Downloads.py`, etc., and that these driver scripts call those modules to extract data from browser profiles.

**Important:** Always work from forensic copies of profile files. Do not run these scripts directly against live user profiles without making a copy first. Closing the browsers before extraction reduces the risk of database locks and avoids writing to profiles during collection.

**Overview**
- **Purpose:** Automates extraction of common browser artifacts (history, downloads, sessions, extensions, autofill, decryptor functionality) for Chrome and Firefox.
- **Scripts:** `run_all.py` is a command-line driver that runs extraction modules; `run_all_gui.py` provides a graphical interface to select profiles and run the same extraction flows.

**Prerequisites**
- **Python:** Install Python 3.8+ (3.10+ recommended).
- **Virtual environment (recommended):** Create one to keep dependencies isolated.
- **Typical packages:** The extraction scripts commonly use built-in `sqlite3` plus packages for crypto and OS integration (for example `cryptography`, `pywin32`/`win32crypt` on Windows). If a `requirements.txt` is present, install it with `pip install -r requirements.txt`.
- **Permissions:** On Windows, run PowerShell with appropriate privileges if accessing profiles in protected locations.

**Running `run_all.py` (CLI)**
- **Basic usage:** Open PowerShell, change to the repository root, then run:

```powershell
cd 'c:\Users\dunnc\OneDrive - IL State University\Documents\GitHub\IT360-Sect-2-Project-Browser-Forensics-1\src'
python .\run_all.py
```

- **Options:** If the script supports arguments they will usually include options to set input profile paths, output directory, or to target only a specific browser. Run `python run_all.py -h` or `python run_all.py --help` to display supported flags.
- **Profile selection:** If the script doesn't provide flags, it will attempt to locate default browser profile locations. To analyze a specific profile, copy the profile folder (for example Chrome `Default` or a named profile) to a safe directory and pass that path if supported.

**Running `run_all_gui.py` (GUI)**
- **Start GUI:** In PowerShell run:

```powershell
cd '...\src'
python .\run_all_gui.py
```

- **What it does:** The GUI typically provides interactive selection of browser profiles (or directories) and lets you run extraction modules with buttons or checkboxes. Use it when you prefer an interactive workflow or need to point to forensic copies of profiles.

**Forensic Best Practices**
- **Copy first:** Always make a bit-for-bit or directory-level copy of the browser profile directories before analysis.
- **Preserve timestamps:** Do not modify original timestamps; work only on copies.
- **Close browsers:** Close Chrome/Firefox to avoid locked databases. If you cannot, use OS-level snapshotting (Volume Shadow Copy on Windows) or browser-specific export methods.
- **Document chain-of-custody:** Log who, when, where, and how the data were collected.
- **Hash evidence:** Compute and record hashes (MD5/SHA256) for files you collect.

**Expected Outputs and Where to Look**
- **Output files:** The scripts usually export CSV or JSON reports for artifacts such as:
  - browsing history (URLs, titles, visit times)
  - downloads (file names, source URLs, timestamps)
  - session data (open tabs, saved sessions)
  - extensions list (installed extensions, IDs)
  - autofill entries (form fields and values)
- **Output location:** By default, outputs are often written to a `data/` folder or a subfolder near the repository root. Check the top of `run_all.py` or the CLI help to confirm the configured output path.

**Interpreting Results for Forensics**
- **Timeline correlation:** Use visit and download timestamps to build event timelines. Convert times to UTC consistently.
- **Source attribution:** Look at source URLs and referer fields to connect browsing activity with downloads.
- **Session reconstruction:** Session files and tab lists are useful to reconstruct what a user had open during a session.
- **Extensions and privacy implications:** Installed extensions can modify browser behavior; note anything that could affect evidence integrity (privacy cleaners, automatic history removers, etc.).

**Troubleshooting & Common Issues**
- **Locked SQLite DB:** If you get errors opening `History` or `Cookies` DBs, ensure the browser is closed or use a copied DB file.
- **Decryption failures:** Decrypting saved passwords or cookies on Windows may require access to the original user account or DPAPI keys; run the decryptor as the same user or use exported keys.
- **Missing modules/errors:** If Python raises ImportError, install missing packages and retry. Use `pip install <package>` or the `requirements.txt` file if provided.

**Example PowerShell Workflow (for one profile)**

```powershell
# 1) Copy profile to analysis folder
Copy-Item -Path 'C:\Users\victim\AppData\Local\Google\Chrome\User Data\Default' -Destination 'C:\forensic\profiles\victim_default' -Recurse

# 2) Run the CLI against the copy (if script accepts profile path)
cd '...\src'
python .\run_all.py --chrome-profile 'C:\forensic\profiles\victim_default' --output 'C:\forensic\reports\victim'

# 3) Hash the report folder
Get-FileHash 'C:\forensic\reports\victim\*' -Algorithm SHA256
```

**Security, Privacy & Legal**
- Only analyze systems and data you are authorized to examine. Follow applicable laws, organizational policies, and privacy rules.