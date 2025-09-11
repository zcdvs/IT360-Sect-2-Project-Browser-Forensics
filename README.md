# IT360-Project

Project overview: A tool for analyzing information relating to browsers: cookies,
extension/plugin permissions, download history, browser history, login sessions, and
cache/autofill analysis.

Extract and analyze:
● Cookies (name, value, domain, expiration)
    ○ Secure & Non-secure
● Browsing history (URLs and timestamps)
    ○ Create chronological timeline
● Download history (file names and URLs)
● Extensions metadata
● Flag suspicious extensions (based on permissions)

Target platform: Chrome/Edge browsers on Windows. Potentially adding support for Linux or
other browsers if we have time.

Implementation language: We plan to write the script in Python.
Artifact selection: User-focused data - session history, browser data, etc.

Output format: Human-readable text logs, with additional CSV files for further analysis if
necessary.

Potential features (if time): Supporting Linux and Windows and more browsers than just Edge
and Chrome. Adding a GUI to the tool. Scheduling the tool’s execution. Maintaining data
integrity through hashing.
