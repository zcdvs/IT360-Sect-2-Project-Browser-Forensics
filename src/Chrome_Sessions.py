#!/usr/bin/env python3
"""
Chrome session analysis (basic):
- Uses History and Cookies DBs to approximate sessions by grouping visits within a timeout window (default 30 minutes)
- Heuristics: token-in-URL, insecure cookies, HttpOnly missing, long expiry, third-party cookies
- Outputs CSV summarizing sessions
"""

import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import shutil
import csv
import datetime
import argparse
import re
from urllib.parse import urlparse

TOKEN_RE = re.compile(r"(token|access_token|auth|session|sessionid|sid|jwt)=([A-Za-z0-9_\-\.]{20,})", re.IGNORECASE)
LONG_TOKEN_RE = re.compile(r"[A-Za-z0-9_\-]{30,}")

CHROME_USERDATA = Path(os.environ.get('LOCALAPPDATA', '')) / 'Google' / 'Chrome' / 'User Data'
PROFILE_PATTERN = re.compile(r"^Profile|^Default$", re.IGNORECASE)


def normalize_host(h):
    if not h:
        return ""
    try:
        h = h.lower().strip()
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
        return h.lower()


def find_profiles(userdata_dir: Path):
    if not userdata_dir.exists():
        return []
    profiles = []
    for entry in userdata_dir.iterdir():
        if not entry.is_dir():
            continue
        # consider Default and Profile X
        # choose any with History and Cookies
        hist = entry / 'History'
        cookies = entry / 'Cookies'
        # allow profiles with History or Cookies (prefer both) so we still analyze sessions when cookies are missing
        if hist.exists() or cookies.exists():
            hist_path = hist if hist.exists() else None
            cookies_path = cookies if cookies.exists() else None
            profiles.append((entry.name, entry, hist_path, cookies_path))
    return profiles


def make_temp_copy_hist_cookies(found):
    temp_dir = Path(tempfile.mkdtemp(prefix='chrome_sessions_'))
    copies = []
    for name, profile_dir, hist, cookies in found:
        hist_dest = None
        cookies_dest = None
        if hist and hist.exists():
            hist_dest = temp_dir / f"{name}_History"
            shutil.copy2(hist, hist_dest)
        if cookies and cookies.exists():
            cookies_dest = temp_dir / f"{name}_Cookies"
            shutil.copy2(cookies, cookies_dest)
        copies.append((name, profile_dir, hist_dest, cookies_dest))
    return temp_dir, copies


def load_cookies(sqlite_path: Path):
    cookies = []
    try:
        if sqlite_path is None:
            return cookies
        conn = sqlite3.connect(str(sqlite_path))
        cur = conn.cursor()
        cur.execute('SELECT host_key, name, value, path, secure, httponly, expires_utc FROM cookies')
        for host, name, value, path, secure, httponly, expires in cur.fetchall():
            raw_host = host.lstrip('.') if host else host
            cookies.append({
                'host': normalize_host(raw_host),
                'name': name,
                'value': value,
                'path': path,
                'is_secure': bool(secure),
                'is_httponly': bool(httponly),
                'expiry': expires,
            })
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass
    return cookies


def find_cookies_for_host(host, cookies):
    if not host:
        return []
    matches = [c for c in cookies if c['host'].endswith(host) or host.endswith(c['host'])]
    return matches


def detect_url_token(url: str):
    if not url:
        return None
    m = TOKEN_RE.search(url)
    if m:
        return m.group(0)
    m2 = LONG_TOKEN_RE.search(url)
    if m2:
        return m2.group(0)
    return None


def chrome_ts_to_utc(chrome_time):
    # Chrome datetime is microseconds since 1601-01-01 UTC
    try:
        if chrome_time and int(chrome_time) > 0:
            epoch = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
            return epoch + datetime.timedelta(microseconds=int(chrome_time))
    except Exception:
        pass
    return None


def analyze_profile(profile_name, hist_path: Path, cookies_path: Path, days=14, session_timeout_minutes=30, debug=False):
    # load cookies
    cookies = load_cookies(cookies_path)
    # build cutoff
    cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days)
    cutoff_micro = int(cutoff.timestamp() * 1_000_000)

    sessions = []
    try:
        # If history is missing, we can still do cookie-only analysis
        if hist_path is None:
            if cookies_path:
                return analyze_cookies_only_for_profile(profile_name, cookies_path, debug=debug)
            return []
        conn = sqlite3.connect(str(hist_path))
        cur = conn.cursor()
        cur.execute('SELECT url, title, last_visit_time FROM urls WHERE last_visit_time >= ? ORDER BY last_visit_time ASC', (cutoff_micro,))
        rows = cur.fetchall()
    except Exception:
        rows = []
    finally:
        try:
            conn.close()
        except Exception:
            pass

    # sessionize
    current = None
    timeout_micro = int(session_timeout_minutes * 60 * 1_000_000)
    for url, title, last_visit in rows:
        if not url or last_visit is None:
            continue
        visit_dt = chrome_ts_to_utc(last_visit)
        if visit_dt is None:
            continue
        if current is None:
            current = {
                'profile': profile_name,
                'start_time': visit_dt,
                'end_time': visit_dt,
                'visits': [(url, title, visit_dt)],
                'hosts': set(),
                'tokens': [],
                'cookie_flags': [],
            }
            current['hosts'].add(normalize_host(urlparse(url).netloc.lower()))
        else:
            prev_time = current['end_time']
            diff = (visit_dt - prev_time).total_seconds() * 1_000_000  # microseconds
            if diff > timeout_micro:
                # close and emit
                sessions.append(current)
                current = {
                    'profile': profile_name,
                    'start_time': visit_dt,
                    'end_time': visit_dt,
                    'visits': [(url, title, visit_dt)],
                    'hosts': set(),
                    'tokens': [],
                    'cookie_flags': [],
                }
                current['hosts'].add(normalize_host(urlparse(url).netloc.lower()))
            else:
                current['end_time'] = visit_dt
                current['visits'].append((url, title, visit_dt))
                current['hosts'].add(normalize_host(urlparse(url).netloc.lower()))

    if current is not None:
        sessions.append(current)

    # analyze sessions for heuristics
    analyzed = []

    for idx, s in enumerate(sessions):
        token_found = None
        cookies_count = 0
        cookie_flags = []
        suspicious = []
        for url, title, vt in s['visits']:
            token = detect_url_token(url)
            if token:
                token_found = token
            host = normalize_host(urlparse(url).netloc.lower())
            host_cookies = find_cookies_for_host(host, cookies)
            cookies_count += len(host_cookies)
            for c in host_cookies:
                if not c['is_secure']:
                    cookie_flags.append(f"cookie_insecure:{c['name']}")
                if not c['is_httponly']:
                    cookie_flags.append(f"cookie_http_non_httponly:{c['name']}")
                try:
                    exp = int(c.get('expiry') or 0)
                    if exp > 0:
                        exp_dt = datetime.datetime.fromtimestamp(exp, tz=datetime.timezone.utc)
                        if exp_dt - datetime.datetime.now(datetime.timezone.utc) > datetime.timedelta(days=365):
                            cookie_flags.append(f"cookie_long_expiry:{c['name']}")
                except Exception:
                    pass
            # third-party detection
            for c in host_cookies:
                ch = c['host']
                if ch and not host.endswith(ch):
                    cookie_flags.append(f"third_party:{c['name']}")

        if token_found:
            suspicious.append('token_in_url')
        if cookie_flags:
            suspicious.append('cookie_flags')

        analyzed.append({
            'profile': s['profile'],
            'session_index': idx,
            'start_time_utc': s['start_time'].isoformat(),
            'end_time_utc': s['end_time'].isoformat(),
            'visits_count': len(s['visits']),
            'hosts': ','.join(sorted(list(s['hosts']))) if s['hosts'] else '',
            'token_found': token_found or '',
            'cookies_count': cookies_count,
            'cookie_flags': ';'.join(sorted(set(cookie_flags))) if cookie_flags else '',
            'suspicious_flags': ';'.join(suspicious) if suspicious else '',
        })

    return analyzed


def analyze_cookies_only_for_profile(profile_name, cookies_path: Path, debug=False):
    # load cookies
    cookies = load_cookies(cookies_path)
    if not cookies:
        return []
    rows = []
    # group cookies by host
    hosts = {}
    for c in cookies:
        h = c.get('host') or ''
        if not h:
            continue
        hosts.setdefault(h, []).append(c)
    for host, ch in hosts.items():
        cookie_flags = []
        suspicious = []
        for c in ch:
            if not c['is_secure']:
                cookie_flags.append(f"cookie_insecure:{c['name']}")
            if not c['is_httponly']:
                cookie_flags.append(f"cookie_http_non_httponly:{c['name']}")
            try:
                exp = int(c.get('expiry') or 0)
                if exp > 0:
                    exp_dt = datetime.datetime.fromtimestamp(exp / 1_000_000 if exp > 999999999999 else exp, tz=datetime.timezone.utc)
                    if exp_dt - datetime.datetime.now(datetime.timezone.utc) > datetime.timedelta(days=365):
                        cookie_flags.append(f"cookie_long_expiry:{c['name']}")
            except Exception:
                pass
            if c.get('host','').startswith('.'):
                cookie_flags.append('cookie_wildcard')
        if cookie_flags:
            suspicious.append('cookie_flags')
        rows.append({
            'profile': profile_name,
            'session_index': '',
            'start_time_utc': '',
            'end_time_utc': '',
            'visits_count': '',
            'hosts': host,
            'token_found': '',
            'cookies_count': len(ch),
            'cookie_flags': ';'.join(sorted(set(cookie_flags))) if cookie_flags else '',
            'suspicious_flags': ';'.join(suspicious) if suspicious else '',
            'cookie_only': True,
        })
    return rows


def export_sessions_for_profiles(copies, output_csv='chrome_sessions.csv', days=14, debug=False, include_cookie_only=False, full_report=False):
    all_rows = []
    for profile_name, profile_dir, hist_path, cookies_path in copies:
        rows = analyze_profile(profile_name, hist_path, cookies_path, days=days, debug=debug)
        all_rows.extend(rows)
        # optionally include cookie-only rows even when history exists
        if include_cookie_only and cookies_path and cookies_path.exists():
            cookie_rows = analyze_cookies_only_for_profile(profile_name, cookies_path, debug=debug)
            if cookie_rows:
                all_rows.extend(cookie_rows)

    with open(output_csv, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        if full_report:
            w.writerow(['profile', 'type', 'session_index', 'start_time_utc', 'end_time_utc', 'visits_count', 'hosts', 'visits', 'cookies_count', 'cookie_flags', 'suspicious_flags', 'token_found'])
            for r in all_rows:
                if r.get('cookie_only'):
                    w.writerow([r['profile'], 'cookie-only', r.get('session_index', ''), r.get('start_time_utc', ''), r.get('end_time_utc', ''), r.get('visits_count', ''), r.get('hosts', ''), '', r.get('cookies_count', ''), r.get('cookie_flags', ''), r.get('suspicious_flags', ''), r.get('token_found', '')])
                else:
                    visits_field = '|'.join([v[0] for v in r.get('visits', [])]) if r.get('visits') else ''
                    w.writerow([r['profile'], 'session', r.get('session_index', ''), r.get('start_time_utc', ''), r.get('end_time_utc', ''), r.get('visits_count', ''), r.get('hosts', ''), visits_field, r.get('cookies_count', ''), r.get('cookie_flags', ''), r.get('suspicious_flags', ''), r.get('token_found', '')])
        else:
            w.writerow(['profile', 'session_index', 'start_time_utc', 'end_time_utc', 'visits_count', 'hosts', 'cookies_count', 'cookie_flags', 'suspicious_flags', 'token_found'])
            for r in all_rows:
                w.writerow([r['profile'], r['session_index'], r['start_time_utc'], r['end_time_utc'], r['visits_count'], r['hosts'], r['cookies_count'], r['cookie_flags'], r['suspicious_flags'], r['token_found']])

    return output_csv, len(all_rows)


def main():
    parser = argparse.ArgumentParser(description='Chrome session analysis (uses History and Cookies DBs to approximate sessions and flag suspicious patterns).')
    parser.add_argument('--output', default='chrome_sessions.csv')
    parser.add_argument('--days', type=int, default=14)
    parser.add_argument('--debug', action='store_true')
    parser.add_argument('--session-timeout', type=int, default=30, help='Sessionization timeout in minutes (default: 30)')
    parser.add_argument('--include-cookie-only', action='store_true', help='Include cookie-only analysis rows even when History is present')
    parser.add_argument('--full-report', action='store_true', help='Write an expanded CSV report with additional fields')
    parser.add_argument('--list-profiles', action='store_true', help='List Chrome profiles and which DB files exist (History/Cookies)')
    args = parser.parse_args()

    found = find_profiles(CHROME_USERDATA)
    if not found:
        print(f"No Chrome profiles with History & Cookies found under: {CHROME_USERDATA}")
        sys.exit(0)
    if args.list_profiles:
        print(f"Found {len(found)} candidate profiles under {CHROME_USERDATA}:")
        for name, profile_dir, h, c in found:
            print(f" - {name}: History={bool(h)}, Cookies={bool(c)}")
        sys.exit(0)

    temp_dir, copies = make_temp_copy_hist_cookies(found)
    if args.debug:
        print(f"[DEBUG] copied History & Cookies DB to: {temp_dir}")

    try:
        out, count = export_sessions_for_profiles(copies, output_csv=args.output, days=args.days, debug=args.debug, include_cookie_only=args.include_cookie_only, full_report=args.full_report)
        print(f"Wrote {count} session records to {out}")
    finally:
        if not args.debug:
            try:
                shutil.rmtree(temp_dir)
            except Exception:
                pass


if __name__ == '__main__':
    main()
