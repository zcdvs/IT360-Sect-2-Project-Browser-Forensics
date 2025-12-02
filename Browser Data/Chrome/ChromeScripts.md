# Chrome Scripts

## Overview
These scripts are designed to pull various different types of cached data from a user's file management system and format it into a readable CSV file. The data includes URLs visited and when, the amount of visits, and login data. The scripts will work on both Windows and Mac operating systems.

## Data
Data that is extracted includes:

- **History**
    - URLs visited, date visited, amount of visits
    - Sorted in chronological order of date accessed

- **Login Data**
    - URLs visited sorted by most recent
    - Amount of times sites were visited
    - Usernames
    - Encrypted passwords

## Usage Examples

- Export Chrome history for the last 30 days to a file:
```
python "Chrome_History.py" --output chrome_history_30days.csv --days 30
```

 - Export saved logins and match to history (full report written to separate file):
```
python "Login_Data_withHistory.py" --debug --full-report --full-report-output login_full_report.csv --days 365 --include-no-history
```
Note: Decrypt saved Chrome passwords only works on Windows and requires `pywin32` and `pycryptodome`. Use `--decrypt-logins` with `Login_Data_withHistory.py` to attempt decrypt.

- Export Firefox history and correlate logins (masked passwords):
```
python "..\Firefox\Firefox_History.py" --debug --include-logins --decrypt-logins --mask-passwords
```

- Export Firefox sessions with heuristic flags:
```
python "..\Firefox\Firefox_Sessions.py" --output firefox_sessions.csv --debug --full-report
```

- Export Chrome sessions using History & Cookies DBs (approximate sessions):
```
python "Chrome_Sessions.py" --output chrome_sessions.csv --debug --days 30
```

Note: `Chrome_Sessions.py` can analyze profiles that have `History` or `Cookies` (or both). Use `--list-profiles` to print which profiles will be scanned and which DBs were found.

## Notes
- The `firefox_decryptor.py` script is included and used by the Firefox history script to decrypt saved logins; ensure `pycryptodome` and `win32crypt` (on Windows) are installed if decryption is needed.