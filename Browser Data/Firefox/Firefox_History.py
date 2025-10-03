#!/usr/bin/env python3
"""
Export last 2 weeks of Firefox history (places.sqlite) to CSV,
copying the DB to a temp folder so Firefox can remain open.

- Scans: %APPDATA%\Mozilla\Firefox\Profiles
- Matches profile folders: 8-char random string (optionally with suffix)
- Timezone: converts timestamps to America/Chicago and respects DST
"""

import os
import sys
import sqlite3
import shutil
import tempfile
import csv
import datetime
import re
from pathlib import Path

# Timezone support: use zoneinfo if available (Python 3.9+), else try pytz
try:
    from zoneinfo import ZoneInfo  # Python 3.9+
    _HAS_ZONEINFO = True
except Exception:
    _HAS_ZONEINFO = False
    try:
        import pytz  # type: ignore # fallback; not guaranteed to be installed
    except Exception:
        pytz = None

PROFILES_SUBPATH = Path("Mozilla") / "Firefox" / "Profiles"
PROFILE_NAME_PATTERN = re.compile(r"^[A-Za-z0-9]{8}(\..*)?$")  # e.g. "abcd1234" or "abcd1234.default-release"
CSV_OUTPUT = "firefox_history_2weeks.csv"
CHICAGO_TZ_NAME = "America/Chicago"
DAYS_BACK = 14  # last 2 weeks


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


def find_places_files(profiles_dir: Path):
    """Return list of tuples (profile_name, places.sqlite Path) for matching profiles."""
    found = []
    for entry in profiles_dir.iterdir():
        if not entry.is_dir():
            continue
        if PROFILE_NAME_PATTERN.match(entry.name):
            candidate = entry / "places.sqlite"
            if candidate.exists():
                found.append((entry.name, candidate))
    return found


def make_temp_and_copy_places(found_list):
    """Create one temp folder and copy each places.sqlite there (unique filenames)."""
    temp_dir = Path(tempfile.mkdtemp(prefix="ff_history_"))
    copies = []
    for profile_name, src_path in found_list:
        dest_name = f"{profile_name}_places.sqlite"
        dest = temp_dir / dest_name
        shutil.copy2(src_path, dest)
        copies.append((profile_name, dest))
    return temp_dir, copies


def tz_chicago():
    """Return a tz object / zone identifier usable with datetime.astimezone()."""
    if _HAS_ZONEINFO:
        return ZoneInfo(CHICAGO_TZ_NAME)
    elif pytz:
        return pytz.timezone(CHICAGO_TZ_NAME)
    else:
        # As a fallback, use fixed-offset US Central (not DST-aware) — but we warn the user.
        print("WARNING: zoneinfo and pytz not available; timezone conversion will not handle DST correctly.")
        # Central Time offset during DST is -5, otherwise -6. We'll use -5 as a coarse fallback.
        return datetime.timezone(datetime.timedelta(hours=-5))


def export_history(copies, output_csv=CSV_OUTPUT, days_back=DAYS_BACK):
    """Read copied DBs and export last `days_back` days of history (Chicago time) to CSV."""
    # compute cutoff in UTC microseconds
    tz_chi = tz_chicago()
    now_chicago = datetime.datetime.now(tz_chi)
    cutoff_chicago = now_chicago - datetime.timedelta(days=days_back)

    # convert cutoff_chicago to UTC and to microseconds since epoch
    # note: if tz_chi is zoneinfo or pytz tzinfo, astimezone works; if fallback timezone, still works.
    cutoff_utc = cutoff_chicago.astimezone(datetime.timezone.utc)
    cutoff_micro = int(cutoff_utc.timestamp() * 1_000_000)

    rows_out = []

    query = """
        SELECT 
            p.url,
            COALESCE(p.title, ''),
            v.visit_date
        FROM moz_places p
        JOIN moz_historyvisits v ON v.place_id = p.id
        WHERE v.visit_date >= ?
        ORDER BY v.visit_date DESC
    """

    for profile_name, db_copy in copies:
        try:
            conn = sqlite3.connect(str(db_copy))
            cur = conn.cursor()
            cur.execute(query, (cutoff_micro,))
            for url, title, visit_date in cur.fetchall():
                if visit_date is None:
                    continue
                # visit_date is stored as microseconds since epoch (UTC)
                try:
                    visit_ts = int(visit_date) / 1_000_000
                except Exception:
                    continue
                dt_utc = datetime.datetime.fromtimestamp(visit_ts, tz=datetime.timezone.utc)
                # convert to Chicago
                if _HAS_ZONEINFO or pytz:
                    dt_chi = dt_utc.astimezone(tz_chi)
                else:
                    # fallback: convert using offset tz object
                    dt_chi = dt_utc.astimezone(tz_chi)

                # Format string like: 2025-10-02 19:32:45 CDT-0500
                try:
                    nice = dt_chi.strftime("%Y-%m-%d %H:%M:%S %Z%z")
                except Exception:
                    # if %Z or %z fails, fallback to ISO + offset
                    nice = dt_chi.isoformat()

                rows_out.append((dt_chi, nice, title, url, profile_name))
        except sqlite3.DatabaseError as e:
            print(f"Warning: couldn't read DB for profile {profile_name}: {e}")
        finally:
            try:
                conn.close()
            except Exception:
                pass

    # sort globally by dt_chi desc (newest first)
    rows_out.sort(key=lambda r: r[0], reverse=True)

    # write CSV
    with open(output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Last Visit (America/Chicago)", "Title", "URL", "Profile"])
        for _dt, nice, title, url, profile_name in rows_out:
            writer.writerow([nice, title, url, profile_name])

    return output_csv, len(rows_out), cutoff_chicago, now_chicago


def main():
    profiles_dir = get_profiles_dir()
    if not profiles_dir:
        sys.exit(1)

    found = find_places_files(profiles_dir)
    if not found:
        print(f"No matching profiles with places.sqlite found under: {profiles_dir}")
        sys.exit(1)

    print(f"[+] Found {len(found)} matching profile(s). Copying places.sqlite files to a temp folder...")
    temp_dir, copies = make_temp_and_copy_places(found)
    print(f"[+] Copied DBs to: {temp_dir}")

    output_csv, count, cutoff_chi, now_chi = export_history(copies)
    print(f"[+] Export completed — {count} rows (visits since {cutoff_chi.strftime('%Y-%m-%d %H:%M:%S %Z')})")
    print(f"[+] CSV output: {output_csv}")
    print(f"[+] Temporary DB copies are in: {temp_dir}")
    print("NOTE: you can safely delete the temp folder when you're done.")


if __name__ == "__main__":
    main()
