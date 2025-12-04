#!/usr/bin/env python3
"""
Export Firefox session data and flag suspicious sessions.
- Reads sessionstore JSON (recovery.jsonlz4 or sessionstore.jsonlz4) per profile
- Reads cookies.sqlite per profile and correlates cookies to tabs
- Heuristics: token in URL, cookies insecure indicator (isSecure==0), HttpOnly missing, long expiry (>365 days), third-party cookie mismatch
- Outputs a CSV summarizing tabs and suspicious flags and optionally a full_report CSV with cookie details

Usage: python Firefox_Sessions.py --output firefox_sessions.csv --full-report
"""

import os
from pathlib import Path
import sys
import argparse
import tempfile
import shutil
import json
import csv
import datetime
import sqlite3
import re

try:
    import lz4.block as lz4_block
except Exception:
    lz4_block = None

from urllib.parse import urlparse

# Copy logic and helpers borrowed from Firefox_History.py
PROFILE_NAME_PATTERN = re.compile(r"^[A-Za-z0-9]{8}(\..*)?$")
PROFILES_SUBPATH = Path("Mozilla") / "Firefox" / "Profiles"
DAYS_BACK_DEFAULT = 14

TOKEN_RE = re.compile(r"(token|access_token|auth|session|sessionid|sid|jwt)=([A-Za-z0-9_\-\.]{20,})", re.IGNORECASE)
LONG_TOKEN_RE = re.compile(r"[A-Za-z0-9_\-]{30,}")


def get_profiles_dir():
    appdata = os.environ.get("APPDATA")
    if not appdata:
        print("ERROR: APPDATA environment variable not set. Are you on Windows?")
        return None
    profiles_dir = Path(appdata) / PROFILES_SUBPATH
    if not profiles_dir.exists():
        print(f"ERROR: Expected profiles folder not found: {profiles_dir}")
        return None
    return profiles_dir


def find_profiles_with_files(profiles_dir: Path):
    found = []
    for entry in profiles_dir.iterdir():
        if not entry.is_dir():
            continue
        print(f"[DEBUG] Found profile folder: {entry.name}")
        if PROFILE_NAME_PATTERN.match(entry.name):
            print(f"[DEBUG] profile name matched regex: {entry.name}")
            # session files can be present under sessionstore-backups
            session_candidates = []
            s1 = entry / 'sessionstore-backups' / 'recovery.jsonlz4'
            s2 = entry / 'sessionstore.jsonlz4'
            if s1.exists():
                if lz4_block is None:
                    print(f"[DEBUG] warning: lz4 not installed; sessionstore will not parse for {entry.name}")
            if s1.exists() or s2.exists():
                print(f"[DEBUG] session file exists for {entry.name}: recovery={s1.exists()}, sessionstore_jsonlz4={s2.exists()}")
            if s1.exists():
                session_candidates.append(s1)
            elif s2.exists():
                session_candidates.append(s2)
            # cookies
            cookies_db = entry / 'cookies.sqlite'
            # accept if either session file or cookies.sqlite exists (prefer both). If only cookies exist, session_path will be None
            if session_candidates or cookies_db.exists():
                print(f"[DEBUG] including profile {entry.name}: session_file={str(session_candidates[0]) if session_candidates else None}, cookies={cookies_db.exists()}")
                session_file = session_candidates[0] if session_candidates else None
                cookies_file = cookies_db if cookies_db.exists() else None
                found.append((entry.name, entry, session_file, cookies_file))
            else:
                # show what was present for debugging
                try:
                    print(f"[DEBUG] profile {entry.name}: session_candidates={len(session_candidates)}, cookies_exists={cookies_db.exists()}")
                except Exception:
                    pass
    return found


def make_temp_and_copy(found_list):
    temp_dir = Path(tempfile.mkdtemp(prefix="ff_sessions_"))
    copies = []
    for profile_name, profile_dir, session_src, cookie_src in found_list:
        session_dest = None
        cookie_dest = None
        if session_src and session_src.exists():
            session_dest = temp_dir / f"{profile_name}_session.jsonlz4"
            shutil.copy2(session_src, session_dest)
        if cookie_src and cookie_src.exists():
            cookie_dest = temp_dir / f"{profile_name}_cookies.sqlite"
            shutil.copy2(cookie_src, cookie_dest)
        copies.append((profile_name, profile_dir, session_dest, cookie_dest))
    return temp_dir, copies


def normalize_host(host: str) -> str:
    if not host:
        return ""
    try:
        h = host.lower().strip()
        if ':' in h:
            h = h.split(':', 1)[0]
        if h.endswith('.'):
            h = h[:-1]
        if h.startswith('www.'):
            h = h[4:]
        if 'xn--' in h:
            h = h.encode('ascii').decode('idna')
        return h
    except Exception:
        return host.lower()


def decompress_lz4(path: Path):
    if lz4_block is None:
        raise RuntimeError("lz4.block not installed. Install python-lz4 package to parse sessionstore files.")
    with open(path, 'rb') as f:
        magic = f.read(8)
        # Mozilla's LZ4 file starts with 'mozLz40\0' — first 8 bytes; actual block follows
        data = f.read()
    # decompress block
    try:
        json_bytes = lz4_block.decompress(data)
        return json.loads(json_bytes)
    except Exception as e:
        raise RuntimeError(f"Failed to decompress/parse {path}: {e}")


def load_cookies(sqlite_path: Path, debug=False):
    cookies = []
    try:
        if sqlite_path is None:
            return cookies
        conn = sqlite3.connect(str(sqlite_path))
        cur = conn.cursor()
        cur.execute("SELECT host, name, value, path, isSecure, isHttpOnly, expiry FROM moz_cookies")
        for host, name, value, path, isSecure, isHttpOnly, expiry in cur.fetchall():
            raw_host = host.lstrip('.') if host else host
            cookies.append({
                'host': normalize_host(raw_host),
                'name': name,
                'value': value,
                'path': path,
                'is_secure': bool(isSecure),
                'is_httponly': bool(isHttpOnly),
                'expiry': expiry,
            })
    except Exception as e:
        if debug:
            print(f"[DEBUG] failed to load cookies from {sqlite_path}: {e}")
    finally:
        try:
            conn.close()
        except Exception:
            pass
    return cookies


def find_cookies_for_host(host, cookies):
    if not host:
        return []
    host_candidates = [host]
    # allow matching subdomain-based cookies: .example.com should match foo.example.com
    parts = host.split('.')
    for i in range(len(parts) - 1):
        host_candidates.append('.'.join(parts[i:]))
    matches = [c for c in cookies if c['host'].endswith(host) or c['host'] in host_candidates]
    return matches


def detect_url_tokens(url: str):
    if not url:
        return None
    m = TOKEN_RE.search(url)
    if m:
        return m.group(0)
    # fallback to any long token substring
    m2 = LONG_TOKEN_RE.search(url)
    if m2:
        return m2.group(0)
    return None


def analyze_session_for_profile(profile_name, session_path: Path, cookies, days_back=14, debug=False):
    # parse session json
    try:
        j = decompress_lz4(session_path)
    except Exception as e:
        if debug:
            print(f"[DEBUG] failed to parse session {session_path}: {e}")
        return []

    now = datetime.datetime.now(datetime.timezone.utc)
    cutoff_dt = now - datetime.timedelta(days=days_back)

    sessions_out = []

    windows = j.get('windows', [])
    for widx, w in enumerate(windows):
        tabs = w.get('tabs', [])
        for tidx, t in enumerate(tabs):
            entries = t.get('entries', [])
            if not entries:
                continue
            # last entry as current URL
            last_entry = entries[-1]
            last_url = last_entry.get('url') or ''
            last_title = last_entry.get('title') or ''
            last_index = t.get('index')
            last_accessed = last_entry.get('lastAccessed')  # not always present
            if last_accessed:
                try:
                    last_accessed_dt = datetime.datetime.fromtimestamp(int(last_accessed) / 1000, tz=datetime.timezone.utc)
                except Exception:
                    last_accessed_dt = None
            else:
                last_accessed_dt = None

            # skip if days_back filter is set and last_accessed beyond cutoff
            if last_accessed_dt and last_accessed_dt < cutoff_dt:
                continue

            # heuristics
            suspicious_flags = []
            token = detect_url_tokens(last_url)
            if token:
                suspicious_flags.append('token_in_url')

            # Redirect chain length: entries length > 1
            if len(entries) > 5:
                suspicious_flags.append('long_redirect_chain')

            # associate cookies
            try:
                host_raw = urlparse(last_url).netloc.lower()
            except Exception:
                host_raw = ''
            host = normalize_host(host_raw)
            host_cookies = find_cookies_for_host(host, cookies)
            cookie_flags = []
            for c in host_cookies:
                if not c.get('is_secure'):
                    cookie_flags.append(f"cookie_insecure:{c['name']}")
                if not c.get('is_httponly'):
                    cookie_flags.append(f"cookie_http_non_httponly:{c['name']}")
                # long expiry heuristic: expiry is epoch seconds (mozilla uses seconds)
                try:
                    exp = int(c.get('expiry') or 0)
                    if exp > 0:
                        exp_dt = datetime.datetime.fromtimestamp(exp, tz=datetime.timezone.utc)
                        if exp_dt - now > datetime.timedelta(days=365):
                            cookie_flags.append(f"cookie_long_expiry:{c['name']}")
                except Exception:
                    pass

            suspicious_flags.extend(list(set(cookie_flags)))

            # third-party cookie detection: cookie host not a suffix of tab host
            third_party = []
            for c in host_cookies:
                c_host = c.get('host')
                if c_host and not host.endswith(c_host):
                    third_party.append(c['name'])
            if third_party:
                suspicious_flags.append('third_party_cookies')

            # build output
            sessions_out.append({
                'profile': profile_name,
                'window_index': widx,
                'tab_index': tidx,
                'last_url': last_url,
                'title': last_title,
                'last_accessed_utc': last_accessed_dt.isoformat() if last_accessed_dt else '',
                'entries_len': len(entries),
                'token_found': token or '',
                'cookies_count': len(host_cookies),
                'cookie_flags': ';'.join(cookie_flags) if cookie_flags else '',
                'suspicious_flags': ';'.join(suspicious_flags) if suspicious_flags else '',
            })

    return sessions_out


def analyze_cookies_only_for_profile(profile_name, cookie_path: Path, days_back=14, debug=False):
    """Analyze a cookie DB without sessionstore: build host-level heuristics."""
    rows = []
    cookies = load_cookies(cookie_path, debug=debug)
    if not cookies:
        return rows
    now = datetime.datetime.now(datetime.timezone.utc)
    cutoff_dt = now - datetime.timedelta(days=days_back)

    # Group cookies by host
    hosts = {}
    for c in cookies:
        h = c.get('host') or ''
        if not h:
            continue
        hosts.setdefault(h, []).append(c)

    for host, chks in hosts.items():
        cookie_flags = []
        suspicious_flags = []
        for c in chks:
            if not c.get('is_secure'):
                cookie_flags.append(f"cookie_insecure:{c['name']}")
            if not c.get('is_httponly'):
                cookie_flags.append(f"cookie_http_non_httponly:{c['name']}")
            try:
                exp = int(c.get('expiry') or 0)
                if exp > 0:
                    exp_dt = datetime.datetime.fromtimestamp(exp, tz=datetime.timezone.utc)
                    if exp_dt - now > datetime.timedelta(days=365):
                        cookie_flags.append(f"cookie_long_expiry:{c['name']}")
            except Exception:
                pass
            # wildcard cookies
            if c.get('host', '').startswith('.'):
                cookie_flags.append('cookie_wildcard')

        if cookie_flags:
            suspicious_flags.append('cookie_flags')

        rows.append({
            'profile': profile_name,
            'host': host,
            'cookies_count': len(chks),
            'cookie_flags': ';'.join(sorted(set(cookie_flags))) if cookie_flags else '',
            'suspicious_flags': ';'.join(sorted(set(suspicious_flags))) if suspicious_flags else '',
            'cookie_only': True,
        })
    return rows


def export_sessions(copies, output_csv='firefox_sessions.csv', days=14, debug=False, full_report=False, include_cookie_only=False):
    all_rows = []
    for profile_name, profile_dir, session_path, cookie_path in copies:
        cookies = load_cookies(cookie_path, debug=debug)
        if debug:
            print(f"[DEBUG] profile {profile_name}: loaded {len(cookies)} cookies")
        if session_path and session_path.exists():
            # If lz4 is not installed, we cannot parse the sessionstore; fallback to cookies-only analysis
            if lz4_block is None:
                if cookies:
                    if debug:
                        print(f"[DEBUG] profile {profile_name}: lz4 not installed, falling back to cookie-only analysis")
                    cookie_rows = analyze_cookies_only_for_profile(profile_name, cookie_path, days_back=days, debug=debug)
                    if cookie_rows:
                        all_rows.extend(cookie_rows)
            else:
                rows = analyze_session_for_profile(profile_name, session_path, cookies, days_back=days, debug=debug)
                if rows:
                    all_rows.extend(rows)
        else:
            # session file missing; fallback to cookie-only heuristics
            if cookies:
                if debug:
                    print(f"[DEBUG] profile {profile_name}: sessionstore missing, analyzing by cookies only")
                cookie_rows = analyze_cookies_only_for_profile(profile_name, cookie_path, days_back=days, debug=debug)
                if cookie_rows:
                    # normalize cookie-only rows into the same output shape used for CSV
                    for cr in cookie_rows:
                        all_rows.append(cr)
    # After analyzing sessions for each profile, optionally include cookie-only rows even when sessionstore exists
    if include_cookie_only and cookie_path and cookie_path.exists():
        cookie_rows = analyze_cookies_only_for_profile(profile_name, cookie_path, days_back=days, debug=debug)
        if cookie_rows:
            all_rows.extend(cookie_rows)

    # write CSV
    rows_written = 0
    with open(output_csv, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        if full_report:
            w.writerow(['profile', 'type', 'window_index', 'tab_index', 'title', 'last_url', 'last_accessed_utc', 'entries_len', 'token_found', 'cookies_count', 'cookie_flags', 'suspicious_flags', 'host'])
            for r in all_rows:
                if r.get('cookie_only'):
                    w.writerow([r['profile'], 'cookie-only', '', '', '', '', '', '', '', r['cookies_count'], r['cookie_flags'], r['suspicious_flags'], r.get('host', '')])
                else:
                    w.writerow([r['profile'], 'session', r.get('window_index', ''), r.get('tab_index', ''), r.get('title', ''), r.get('last_url', ''), r.get('last_accessed_utc', ''), r.get('entries_len', ''), r.get('token_found', ''), r.get('cookies_count', ''), r.get('cookie_flags', ''), r.get('suspicious_flags', ''), r.get('host', '')])
                rows_written += 1
        else:
            w.writerow(['profile', 'type', 'title', 'last_url', 'cookies_count', 'suspicious_flags', 'host'])
            for r in all_rows:
                if r.get('cookie_only'):
                    w.writerow([r['profile'], 'cookie-only', '', '', r['cookies_count'], r['suspicious_flags'], r.get('host', '')])
                else:
                    w.writerow([r['profile'], 'session', r.get('title', ''), r.get('last_url', ''), r.get('cookies_count', ''), r.get('suspicious_flags', ''), r.get('host', '')])
                rows_written += 1

    return output_csv, rows_written


def main():
    parser = argparse.ArgumentParser(description="Firefox session analysis — extract sessionstore and cookies and flag suspicious sessions.")
    parser.add_argument("--output", default="firefox_sessions.csv", help="CSV output file")
    parser.add_argument("--days", type=int, default=DAYS_BACK_DEFAULT, help="Days back cutoff for last access (default 14)")
    parser.add_argument("--debug", action="store_true", help="Print debug data")
    parser.add_argument("--full-report", action="store_true", help="Output full CSV with cookie details")
    parser.add_argument("--list-profiles", action="store_true", help="List found Firefox profiles and present what files exist (sessionstore/cookies)")
    parser.add_argument("--include-cookie-only", action="store_true", help="Include cookie-only analysis rows even when sessionstore is present")
    args = parser.parse_args()

    profiles_dir = get_profiles_dir()
    if not profiles_dir:
        sys.exit(1)

    found = find_profiles_with_files(profiles_dir)
    if not found:
        print(f"No matching profiles with session files and cookies under: {profiles_dir}")
        sys.exit(0)
    if args.list_profiles:
        print(f"Found profiles: {len(found)} (potentially) that we may consider; reporting per-profile file presence:")
        for n, p, s, c in found:
            print(f" - {n}: session={bool(s)}, cookies={bool(c)}")
        sys.exit(0)

    temp_dir, copies = make_temp_and_copy(found)
    if args.debug:
        print(f"[DEBUG] copied session and cookies files into temp folder: {temp_dir}")

    try:
        out, count = export_sessions(copies, output_csv=args.output, days=args.days, debug=args.debug, full_report=args.full_report, include_cookie_only=args.include_cookie_only)
        print(f"Wrote {count} session records to {out}")
    finally:
        # Keep temp data unless debug; owner can remove it manually
        if not args.debug:
            try:
                shutil.rmtree(temp_dir)
            except Exception:
                pass


if __name__ == '__main__':
    main()
