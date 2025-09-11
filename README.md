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
- Primary: Chrome and Edge on **Windows**  
- Future: Potential support for **Linux** and other browsers

## Implementation
- **Language:** Python  
- **Artifact selection:** User-focused data (session history, browser data, etc.)  
- **Output format:**  
  - Human-readable text logs  
  - CSV files for further analysis  

## Potential Features (Stretch Goals)
- Cross-platform support (Windows + Linux)
- Support for more browsers
- GUI interface
- Scheduling tool execution
- Data integrity through hashing

