#!/usr/bin/env python3
"""
Export Chrome download history and perform heuristics.
- Reads the `History` DB and the `downloads` table (or `downloads` DB if present)
- Writes CSV with download metadata and suspicious flags
"""

import os
import sqlite3
import tempfile
import shutil
import csv
import argparse
import datetime
from pathlib import Path
from urllib.parse import urlparse

CHROME_USERDATA = Path(os.environ.get('LOCALAPPDATA', '')) / 'Google' / 'Chrome' / 'User Data'

EXECUTABLE_EXTS = set(['exe','msi','dll','bat','cmd','scr'])
ARCHIVE_EXTS = set(['zip','tar','gz','rar','7z'])


def normalize_host(host):
    if not host:
        return ''
    try:
        h = host.lower().strip()
        if ':' in h:
            h = h.split(':', 1)[0]
        if h.startswith('www.'):
            h = h[4:]
        if h.endswith('.'):
            h = h[:-1]
        return h
    except Exception:
        return host


def find_profiles(userdata_dir: Path):
    profiles = []
    if not userdata_dir.exists():
        return profiles
    for entry in userdata_dir.iterdir():
        if not entry.is_dir():
            continue
        hist = entry / 'History'
        downloads = entry / 'Downloads'
        # include profiles which have History or Downloads
        if hist.exists() or downloads.exists():
            profiles.append((entry.name, entry, hist if hist.exists() else None, downloads if downloads.exists() else None))
    return profiles


def copy_db(src_path: Path):
    if src_path is None or not src_path.exists():
        return None
    tmp = tempfile.NamedTemporaryFile(prefix='chrome_dl_', delete=False)
    tmp.close()
    shutil.copy2(str(src_path), tmp.name)
    return tmp.name


def analyze_downloads_for_profile(profile_name, hist_path: Path, days=90, debug=False):
    tmp_hist = copy_db(hist_path)
    if tmp_hist is None:
        return []
    rows = []
    try:
        conn = sqlite3.connect(tmp_hist)
        cur = conn.cursor()
        # check for 'downloads' table
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name IN ('downloads','downloads_url_chains')")
        found = cur.fetchall()
        # typical Chrome schema: downloads table with id, current_path, target_path, tab_url, referrer, start_time microseconds
        if any('downloads' in t for t in found):
            try:
                cur.execute('''SELECT id, current_path, target_path, tab_url, referrer, start_time, received_bytes, total_bytes FROM downloads''')
                for rid, current_path, target_path, tab_url, referrer, start_time, recieved, total in cur.fetchall():
                    try:
                        dt = datetime.datetime(1601,1,1,tzinfo=datetime.timezone.utc) + datetime.timedelta(microseconds=int(start_time)) if start_time else None
                    except Exception:
                        dt = None
                    host = ''
                    try:
                        host = normalize_host(urlparse(tab_url).netloc.lower())
                    except Exception:
                        host = ''
                    fname = os.path.basename(target_path) if target_path else os.path.basename(current_path) if current_path else ''
                    ext = fname.split('.')[-1].lower() if '.' in fname else ''
                    reasons = []
                    if ext in EXECUTABLE_EXTS:
                        reasons.append('executable')
                    if ext in ARCHIVE_EXTS:
                        reasons.append('archive')
                    if host and (host.endswith('.zip') or host.endswith('.rar')):
                        reasons.append('suspicious_host')
                    rows.append({
                        'profile': profile_name,
                        'id': rid,
                        'filename': fname,
                        'url': tab_url,
                        'referrer': referrer,
                        'time_utc': dt.isoformat() if dt else '',
                        'bytes_received': recieved,
                        'bytes_total': total,
                        'host': host,
                        'reasons': ';'.join(reasons),
                    })
            except Exception:
                pass
        else:
            # fallback: query `downloads` table in other schema or see 'downloads_url_chains'
            try:
                cur.execute('SELECT id, url, path, start_time, danger_type FROM downloads')
                for rid, url, path, start_time, danger in cur.fetchall():
                    dt = None
                    try:
                        dt = datetime.datetime(1601,1,1,tzinfo=datetime.timezone.utc) + datetime.timedelta(microseconds=int(start_time)) if start_time else None
                    except Exception:
                        dt = None
                    host = ''
                    try:
                        host = normalize_host(urlparse(url).netloc.lower())
                    except Exception:
                        host = ''
                    fname = os.path.basename(path) if path else ''
                    ext = fname.split('.')[-1].lower() if '.' in fname else ''
                    reasons = []
                    if ext in EXECUTABLE_EXTS:
                        reasons.append('executable')
                    if ext in ARCHIVE_EXTS:
                        reasons.append('archive')
                    if danger and danger != 0:
                        reasons.append('danger')
                    rows.append({
                        'profile': profile_name,
                        'id': rid,
                        'filename': fname,
                        'url': url,
                        'time_utc': dt.isoformat() if dt else '',
                        'bytes_received': None,
                        'bytes_total': None,
                        'host': host,
                        'reasons': ';'.join(reasons),
                    })
            except Exception:
                pass
    finally:
        try:
            conn.close()
        except Exception:
            pass
        try:
            if os.path.exists(tmp_hist):
                os.remove(tmp_hist)
        except Exception:
            pass
    return rows


def export_downloads(userdata_root, output='chrome_downloads.csv', days=365, debug=False):
    profiles = find_profiles(userdata_root)
    all_rows = []
    for p_name, p_dir, hist, dl in profiles:
        if hist:
            rows = analyze_downloads_for_profile(p_name, hist, days=days, debug=debug)
            all_rows.extend(rows)
        elif dl:
            rows = analyze_downloads_for_profile(p_name, dl, days=days, debug=debug)
            all_rows.extend(rows)

    with open(output, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['profile','id','filename','url','referrer','time_utc','bytes_received','bytes_total','host','reasons'])
        for r in all_rows:
            w.writerow([r['profile'], r['id'], r['filename'], r.get('url',''), r.get('referrer',''), r.get('time_utc',''), r.get('bytes_received',''), r.get('bytes_total',''), r.get('host',''), r.get('reasons','')])
    return output, len(all_rows)


def main():
    parser = argparse.ArgumentParser(description='Chrome downloads analysis')
    parser.add_argument('--output', default='chrome_downloads.csv')
    parser.add_argument('--debug', action='store_true')
    parser.add_argument('--days', type=int, default=365)
    parser.add_argument('--list-profiles', action='store_true', help='List candidate profiles with History/Downloads presence')
    args = parser.parse_args()

    profiles = find_profiles(CHROME_USERDATA)
    if args.list_profiles:
        print('Found profiles:')
        for p, d, h, dl in profiles:
            print(p, 'History=', bool(h), 'Downloads=', bool(dl))
        return 0

    out, count = export_downloads(CHROME_USERDATA, output=args.output, days=args.days, debug=args.debug)
    print(f'Wrote {count} download rows to {out}')


if __name__ == '__main__':
    main()
