#!/usr/bin/env python3
"""
Export Firefox download history and perform heuristics.
- Looks for profile-level `downloads.sqlite` (moz_downloads table), otherwise looks in `places.sqlite` for download annotations.
- Writes CSV with download metadata and suspicious flags
"""

import os
from pathlib import Path
import sqlite3
import tempfile
import shutil
import csv
import argparse
import datetime
from urllib.parse import urlparse

PROFILES_SUBPATH = Path('Mozilla') / 'Firefox' / 'Profiles'
DAYS_BACK = 365

EXECUTABLE_EXTS = set(['exe','msi','dll','bat','cmd','scr'])
ARCHIVE_EXTS = set(['zip','tar','gz','rar','7z'])


def get_profiles_dir():
    appdata = os.environ.get('APPDATA')
    if not appdata:
        return None
    return Path(appdata) / PROFILES_SUBPATH


def find_profiles_with_downloads(profiles_dir: Path):
    found = []
    for entry in profiles_dir.iterdir():
        if not entry.is_dir():
            continue
        # check for downloads.sqlite or places.sqlite
        downloads_db = entry / 'downloads.sqlite'
        places_db = entry / 'places.sqlite'
        if downloads_db.exists() or places_db.exists():
            found.append((entry.name, entry, downloads_db if downloads_db.exists() else None, places_db if places_db.exists() else None))
    return found


def copy_db(src: Path):
    if not src or not src.exists():
        return None
    tmp = tempfile.NamedTemporaryFile(prefix='ff_dl_', delete=False)
    tmp.close()
    shutil.copy2(str(src), tmp.name)
    return tmp.name


def analyze_downloads_sqlite(profile_name, downloads_sqlite: Path, debug=False):
    tmp = copy_db(downloads_sqlite)
    if not tmp:
        return []
    rows = []
    try:
        conn = sqlite3.connect(tmp)
        cur = conn.cursor()
        # Common table: moz_downloads (id, source, target, startTime, state)
        try:
            cur.execute('SELECT id, source, target, startTime, state FROM moz_downloads')
            for rid, source, target, start_time, state in cur.fetchall():
                try:
                    dt = datetime.datetime.fromtimestamp(int(start_time) / 1000, tz=datetime.timezone.utc) if start_time else None
                except Exception:
                    dt = None
                host = ''
                try:
                    host = urlparse(source).netloc.lower()
                except Exception:
                    host = ''
                fname = os.path.basename(target) if target else ''
                ext = fname.split('.')[-1].lower() if '.' in fname else ''
                reasons = []
                if ext in EXECUTABLE_EXTS:
                    reasons.append('executable')
                if ext in ARCHIVE_EXTS:
                    reasons.append('archive')
                rows.append({'profile': profile_name, 'id': rid, 'filename': fname, 'url': source, 'time_utc': dt.isoformat() if dt else '', 'host': host, 'reasons': ';'.join(reasons)})
        except Exception:
            pass
    finally:
        try:
            conn.close()
        except Exception:
            pass
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except Exception:
            pass
    return rows


def analyze_places_for_downloads(profile_name, places_sqlite: Path, debug=False):
    tmp = copy_db(places_sqlite)
    if not tmp:
        return []
    rows = []
    try:
        conn = sqlite3.connect(tmp)
        cur = conn.cursor()
        # Quick heuristic: the place type for download may be stored as GET params or url contains 'download'
        cur.execute("SELECT url, title, last_visit_date FROM moz_places WHERE url LIKE '%download%' OR url LIKE '%.zip%' OR url LIKE '%.exe%'")
        for url, title, last_visit in cur.fetchall():
            try:
                dt = datetime.datetime.fromtimestamp(int(last_visit) / 1000000, tz=datetime.timezone.utc) if last_visit else None
            except Exception:
                dt = None
            host = ''
            try:
                host = urlparse(url).netloc.lower()
            except Exception:
                host = ''
            fname = os.path.basename(urlparse(url).path)
            ext = fname.split('.')[-1].lower() if '.' in fname else ''
            reasons = []
            if ext in EXECUTABLE_EXTS:
                reasons.append('executable')
            if ext in ARCHIVE_EXTS:
                reasons.append('archive')
            rows.append({'profile': profile_name, 'filename': fname, 'url': url, 'time_utc': dt.isoformat() if dt else '', 'host': host, 'reasons': ';'.join(reasons)})
    finally:
        try:
            conn.close()
        except Exception:
            pass
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except Exception:
            pass
    return rows


def export_downloads(profiles_root, output='firefox_downloads.csv', debug=False):
    found = find_profiles_with_downloads(profiles_root)
    all_rows = []
    for profile_name, profile_dir, downloads_db, places_db in found:
        if downloads_db:
            rows = analyze_downloads_sqlite(profile_name, downloads_db, debug=debug)
            all_rows.extend(rows)
        if places_db:
            rows = analyze_places_for_downloads(profile_name, places_db, debug=debug)
            all_rows.extend(rows)
    with open(output, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['profile','id','filename','url','time_utc','host','reasons'])
        for r in all_rows:
            w.writerow([r.get('profile',''), r.get('id',''), r.get('filename',''), r.get('url',''), r.get('time_utc',''), r.get('host',''), r.get('reasons','')])
    return output, len(all_rows)


def main():
    parser = argparse.ArgumentParser(description='Firefox downloads analysis')
    parser.add_argument('--output', default='firefox_downloads.csv')
    parser.add_argument('--debug', action='store_true')
    parser.add_argument('--list-profiles', action='store_true')
    args = parser.parse_args()

    profiles_dir = get_profiles_dir()
    if not profiles_dir:
        print('Cannot determine profiles dir')
        return 1
    found = find_profiles_with_downloads(profiles_dir)
    if args.list_profiles:
        print('Found profiles (downloads/places presence):')
        for p, d, dd, pd in found:
            print(p, 'downloads=', bool(dd), 'places=', bool(pd))
        return 0
    out, count = export_downloads(profiles_dir, output=args.output, debug=args.debug)
    print(f'Wrote {count} download rows to {out}')
    return 0


if __name__ == '__main__':
    main()
