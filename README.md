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

## Project Overview

This project provides a set of Python scripts in the `src/` directory that extract browser artifacts for Chrome and Firefox. The intent is to centralize artifact extraction so outputs can be ingested into forensic analysis tools and timelines.

Below is a brief summary of the main files in `src/`, their purpose, typical inputs, outputs, and forensic notes.

- `Chrome_Autofill.py`: Extracts Chrome autofill/form data collected by the browser.
  - Inputs: Chrome profile `Web Data` SQLite file (copied).
  - Outputs: CSV/JSON rows of form field names, values, and timestamps.
  - Notes: Sensitive PII likely present. Treat outputs as evidence and hash accordingly.

- `chrome_decrypt.py`: Utilities to decrypt Chrome-protected data (saved passwords, cookies) on Windows.
  - Inputs: Encrypted blobs from Chrome (`Login Data`, `Cookies`) and access to DPAPI context (user account keys) or local master key where applicable.
  - Outputs: Decrypted plaintext values or an error/log indicating missing keys.
  - Notes: Decryption may require running as the same Windows user account or exported DPAPI keys; document access and authorization.

- `Chrome_Downloads.py`: Extracts download history and metadata from Chrome.
  - Inputs: Chrome `History` or `Downloads` SQLite DB fields.
  - Outputs: CSV/JSON of downloaded file names, source URLs, target paths, and timestamps.
  - Notes: Useful for correlating file artifacts on disk with browser activity.

- `Chrome_Extensions.py`: Lists installed Chrome extensions and metadata.
  - Inputs: Chrome profile extension state directories and `Preferences` JSON.
  - Outputs: CSV/JSON of extension IDs, names (where available), and install state.
  - Notes: Flag privacy/cleaner extensions that could alter browser artifact availability.

- `Chrome_History.py`: Parses Chrome browsing history entries.
  - Inputs: Chrome `History` SQLite (URLs, visits, visit_time fields).
  - Outputs: CSV/JSON of visited URLs, titles, visit counts, and timestamps.
  - Notes: Convert Chrome's internal timestamps (WebKit/epoch) to human-readable UTC for timelines.

- `Chrome_Sessions.py`: Extracts session/tab information (open tabs, saved sessions).
  - Inputs: Session files (e.g., `Current Session`, `Current Tabs`, `Session_*`) and session JSON blobs.
  - Outputs: Lists of open URLs, window/tab order, and last-write timestamps.
  - Notes: Helpful for reconstructing the user's browsing state at a point in time.

- `firefox_decryptor.py`: Decrypts Firefox-protected secrets (if implemented).
  - Inputs: Firefox `logins.json` and `key4.db` or `key3.db` depending on profile.
  - Outputs: Decrypted saved logins/cookies when keys are available.
  - Notes: Requires access to the profile's private keys; similar authorization considerations as Chrome.

- `Firefox_Downloads.py`: Extracts Firefox download history and metadata.
  - Inputs: Firefox `places.sqlite` and download-related DB/tables.
  - Outputs: CSV/JSON of downloads with timestamps and source URIs.

- `Firefox_Extensions.py`: Lists Firefox add-ons and extensions.
  - Inputs: Firefox profile extension metadata files.
  - Outputs: CSV/JSON of installed add-ons and relevant metadata.

- `Firefox_History.py`: Parses Firefox browsing history.
  - Inputs: `places.sqlite` (history/bookmarks) and other profile artifacts.
  - Outputs: CSV/JSON of visited URIs, titles, visit counts, and timestamps.

- `Firefox_Sessions.py`: Extracts Firefox session data (open tabs, session restore files).
  - Inputs: `sessionstore-backups` and current session files in the profile.
  - Outputs: Lists of open tabs, windows, and last-used timestamps.

- `run_all.py`: Command-line driver that orchestrates the extraction modules.
  - Inputs: May use default profile locations or accept profile paths and output directory arguments.
  - Outputs: Aggregated CSV/JSON reports written to the configured `data/` or output folder.
  - Notes: Best used against copies of profiles; check `--help` for supported flags.

- `run_all_gui.py`: GUI wrapper around the same extraction functionality.
  - Inputs/Outputs: Same as `run_all.py`, but presented via an interactive interface to choose profiles and run modules.
  - Notes: Convenient for analysts who prefer a guided workflow; still follow forensic copy practices.

Design Intent & Analysis Workflow
- Centralize artifact extraction: Each per-browser script focuses on a single artifact class so outputs are normalized for later ingestion.
- Support reproducible analysis: `run_all.py` and `run_all_gui.py` should produce consistent exports that can be hashed and archived.
- Enable timeline-building: Outputs (history, downloads, session timestamps) are intended to be combined into timelines or fed into timeline tools.
- Separate decryption logic: Decryptors are isolated (`chrome_decrypt.py`, `firefox_decryptor.py`) to make authorization and key handling explicit.

If you want, I can now inspect `run_all.py` and `run_all_gui.py` to extract their exact CLI flags and GUI options, and then update this document with specific commands and the precise output folder used by the current implementation.