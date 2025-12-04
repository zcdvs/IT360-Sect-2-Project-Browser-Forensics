#!/usr/bin/env python3
"""
Export last 2 weeks of Firefox history (places.sqlite) to CSV,
copying the DB to a temp folder so Firefox can remain open.

- Scans: %APPDATA%\\Mozilla\\Firefox\\Profiles
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
from urllib.parse import urlparse
import json
import heapq

# Timezone support: use zoneinfo if available (Python 3.9+), else try pytz
try:
    # Import ZoneInfo; note that ZoneInfo may be present but tzdata package
    # might not be installed on some Windows Python builds which causes
    # ZoneInfo(tz_name) to raise ZoneInfoNotFoundError at runtime. We still
    # mark _HAS_ZONEINFO True and handle missing tzdata at use time.
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
    # Prefer zoneinfo when available — but ZoneInfo(...) can raise when the
    # system doesn't have tzdata (ZoneInfoNotFoundError). Catch that and
    # fall back to pytz if available or a fixed-offset tz otherwise.
    if _HAS_ZONEINFO:
        try:
            return ZoneInfo(CHICAGO_TZ_NAME)
        except Exception:
            # likely ZoneInfoNotFoundError due to missing tzdata
            if pytz:
                return pytz.timezone(CHICAGO_TZ_NAME)
            else:
                print("WARNING: zoneinfo is available but tzdata not found; falling back to fixed CST offset (-6 hrs). DST will not be handled.")
                return datetime.timezone(datetime.timedelta(hours=-6))
    elif pytz:
        return pytz.timezone(CHICAGO_TZ_NAME)
    else:
        # As a fallback, use fixed-offset US Central (not DST-aware) — warn the user.
        print("WARNING: zoneinfo and pytz not available; timezone conversion will NOT handle DST correctly. Using a fixed CST offset (-6 hrs).")
        return datetime.timezone(datetime.timedelta(hours=-6))


def normalize_host(host: str) -> str:
    """Normalize hostnames for matching and output.

    - lowercases
    - strips port if present
    - strips leading 'www.'
    - strips trailing dot
    - attempts to decode punycode (xn--) to Unicode
    Returns the normalized host string or the input lowercased on failure.
    """
    if not host:
        return ""
    try:
        h = host.lower().strip()
        # remove port
        if ":" in h:
            h = h.split(":", 1)[0]
        # remove any trailing dot
        if h.endswith('.'):
            h = h[:-1]
        # remove leading www.
        if h.startswith("www."):
            h = h[4:]
        # try to decode punycode to unicode (e.g., xn--)
        try:
            if "xn--" in h:
                h = h.encode('ascii').decode('idna')
        except Exception:
            pass
        return h
    except Exception:
        return host.lower()


def mask_password(pw: str, mask: bool) -> str:
    if not pw:
        return pw
    if not mask:
        return pw
    # Simple mask: show nothing and mark as [REDACTED]
    try:
        return "[REDACTED]"
    except Exception:
        return "[REDACTED]"


def export_history(copies, output_csv=CSV_OUTPUT, days_back=DAYS_BACK, debug=False, full_report=False):
    """Read copied DBs and export last `days_back` days of history (Chicago time) to CSV.

    debug: print per-profile diagnostics
    full_report: include raw UTC timestamp and host column in output
    """
    # compute cutoff in UTC microseconds
    tz_chi = tz_chicago()
    now_chicago = datetime.datetime.now(tz_chi)
    cutoff_chicago = now_chicago - datetime.timedelta(days=days_back)

    # convert cutoff_chicago to UTC and to microseconds since epoch
    # note: if tz_chi is zoneinfo or pytz tzinfo, astimezone works; if fallback timezone, still works.
    cutoff_utc = cutoff_chicago.astimezone(datetime.timezone.utc)
    cutoff_micro = int(cutoff_utc.timestamp() * 1_000_000)

    # We'll stream merged rows across profiles to avoid storing everything in memory.
    # Each per-profile iterator will yield tuples keyed by -visit_date (so newest first).
    rows_out = None
    gens = []
    per_profile_counts = {}

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
        # quick count for debug without pulling everything into memory
        try:
            conn = sqlite3.connect(str(db_copy))
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM moz_historyvisits v JOIN moz_places p ON v.place_id = p.id WHERE v.visit_date >= ?", (cutoff_micro,))
            row = cur.fetchone()
            count = int(row[0]) if row and row[0] is not None else 0
            per_profile_counts[profile_name] = count
            if debug:
                print(f"[DEBUG] profile {profile_name}: {count} visit rows since cutoff")
        except Exception:
            per_profile_counts[profile_name] = 0
        finally:
            try:
                conn.close()
            except Exception:
                pass

        # create a generator for this profile that yields (key, utc_iso, nice, title, url, profile_name, host)
        def profile_iter(db_path, profile_name_local):
            conn2 = None
            try:
                conn2 = sqlite3.connect(str(db_path))
                cur2 = conn2.cursor()
                # iterate in descending order; we'll use -visit_date as key so the negative values are ascending
                for url, title, visit_date in cur2.execute(query, (cutoff_micro,)):
                    if visit_date is None:
                        continue
                    try:
                        visit_ts_micro = int(visit_date)
                    except Exception:
                        continue
                    # key for heapq.merge (ascending): negative microtimestamp so newest appears first
                    key = -visit_ts_micro
                    dt_utc = datetime.datetime.fromtimestamp(visit_ts_micro / 1_000_000, tz=datetime.timezone.utc)
                    if _HAS_ZONEINFO or pytz:
                        dt_chi = dt_utc.astimezone(tz_chi)
                    else:
                        dt_chi = dt_utc.astimezone(tz_chi)
                    try:
                        nice = dt_chi.strftime("%Y-%m-%d %H:%M:%S %Z%z")
                    except Exception:
                        nice = dt_chi.isoformat()
                    try:
                        host_raw = urlparse(url).netloc.lower()
                    except Exception:
                        host_raw = ""
                    host = normalize_host(host_raw)
                    utc_iso = dt_utc.isoformat()
                    yield (key, utc_iso, nice, title, url, profile_name_local, host)
            finally:
                try:
                    if conn2:
                        conn2.close()
                except Exception:
                    pass

        gens.append(profile_iter(db_copy, profile_name))

    # stream-merge generators using heapq.merge; each yielded tuple begins with key so merge orders by key
    merged = heapq.merge(*gens)

    # write CSV as we consume merged rows (no large memory use)
    rows_written = 0
    with open(output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if full_report:
            writer.writerow(["UTC", "Last Visit (America/Chicago)", "Title", "URL", "Profile", "Host"])
            for key, utc_iso, nice, title, url, profile_name, host in merged:
                writer.writerow([utc_iso, nice, title, url, profile_name, host])
                rows_written += 1
        else:
            writer.writerow(["Last Visit (America/Chicago)", "Title", "URL", "Profile"])
            for key, utc_iso, nice, title, url, profile_name, host in merged:
                writer.writerow([nice, title, url, profile_name])
                rows_written += 1

    return output_csv, rows_written, cutoff_chicago, now_chicago


def main():
    # kept for backwards compatibility; prefer using CLI in __main__ below
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
    import argparse

    parser = argparse.ArgumentParser(description="Export Firefox history to CSV (copies places.sqlite to temp folder).")
    parser.add_argument("--output", default=CSV_OUTPUT, help="Output CSV file")
    parser.add_argument("--days", type=int, default=DAYS_BACK, help="Days back cutoff (default 14)")
    parser.add_argument("--debug", action="store_true", help="Print debug diagnostics")
    parser.add_argument("--cleanup", action="store_true", help="Remove temporary DB copies after run")
    parser.add_argument("--full-report", action="store_true", help="Include UTC timestamp and host column in CSV output")
    parser.add_argument("--include-logins", action="store_true", help="Attempt to read logins.json (encrypted) and correlate origins to history (writes a separate CSV)")
    parser.add_argument("--logins-output", default="firefox_logins_with_history.csv", help="Output CSV file for login+history correlation")
    parser.add_argument("--decrypt-logins", action="store_true", help="Attempt to decrypt saved logins (requires an external decryptor module/script to be installed).")
    parser.add_argument("--mask-passwords", action="store_true", help="Mask passwords in output CSVs")
    args = parser.parse_args()

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

    output_csv, count, cutoff_chi, now_chi = export_history(copies, output_csv=args.output, days_back=args.days, debug=args.debug, full_report=args.full_report)
    print(f"[+] Export completed — {count} rows (visits since {cutoff_chi.strftime('%Y-%m-%d %H:%M:%S %Z')})")
    print(f"[+] CSV output: {output_csv}")
    if args.cleanup:
        try:
            shutil.rmtree(temp_dir)
            if args.debug:
                print(f"[DEBUG] removed temp folder: {temp_dir}")
        except Exception as e:
            print(f"Warning: failed to remove temp folder {temp_dir}: {e}")
    else:
        print(f"[+] Temporary DB copies are in: {temp_dir}")
        print("NOTE: you can safely delete the temp folder when you're done.")

    # Optionally read logins.json from each profile and correlate to history
    if args.include_logins:
        try:
            # If user requested decryption, load the local firefox_decryptor.py
            decrypt_module = None
            if args.decrypt_logins:
                try:
                    import importlib.util
                    local_path = Path(__file__).parent / 'firefox_decryptor.py'
                    if local_path.exists():
                        spec = importlib.util.spec_from_file_location('firefox_decryptor', str(local_path))
                        module = importlib.util.module_from_spec(spec)
                        spec.loader.exec_module(module)
                        decrypt_module = module
                        if args.debug:
                            print(f"[DEBUG] using local decryptor module: {local_path}")
                    else:
                        print(f"WARNING: firefox_decryptor.py not found at {local_path}. Decryption will be skipped.")
                except Exception as e:
                    print(f"WARNING: failed to load firefox_decryptor.py: {e}. Decryption will be skipped.")
            # Build a lightweight history_map: host -> (last_visit_micro, visit_count)
            history_map = {}
            for profile_name, db_copy in copies:
                try:
                    conn = sqlite3.connect(str(db_copy))
                    cur = conn.cursor()
                    cur.execute("SELECT p.url, v.visit_date FROM moz_places p JOIN moz_historyvisits v ON v.place_id = p.id")
                    for h_url, h_visit in cur.fetchall():
                        try:
                            h_host_raw = urlparse(h_url).netloc.lower()
                        except Exception:
                            continue
                        if not h_host_raw:
                            continue
                        h_host = normalize_host(h_host_raw)
                        if not h_host:
                            continue
                        curv = history_map.get(h_host)
                        if curv is None:
                            history_map[h_host] = (h_visit or 0, 1)
                        else:
                            last_micro, cnt = curv
                            new_last = h_visit if (h_visit is not None and h_visit > (last_micro or 0)) else last_micro
                            history_map[h_host] = (new_last, cnt + 1)
                except Exception:
                    continue
                finally:
                    try:
                        conn.close()
                    except Exception:
                        pass

            # Now read logins.json from original profile folders (found variable created earlier)
            # We reconstruct 'found' by scanning profiles directory again (same logic as earlier)
            profiles_dir = get_profiles_dir()
            found_profiles = find_places_files(profiles_dir)
            logins_out = []
            for profile_name, places_path in found_profiles:
                profile_dir = places_path.parent
                login_json_path = profile_dir / 'logins.json'
                if not login_json_path.exists():
                    if args.debug:
                        print(f"[DEBUG] no logins.json for profile {profile_name}")
                    continue
                try:
                    # If we have a decryptor module, prefer it and attempt to extract decrypted logins.
                    decrypted_entries = None
                    if decrypt_module is not None:
                        # try common function names; this is best-effort and depends on the installed tool's API
                        for fn_name in ("get_logins", "decrypt_profile", "extract_logins", "get_decrypted_logins"):
                            fn = getattr(decrypt_module, fn_name, None)
                            if callable(fn):
                                try:
                                    # many tools expect a profile directory path
                                    decrypted_entries = fn(str(profile_dir))
                                    if args.debug:
                                        print(f"[DEBUG] {fn_name} returned {len(decrypted_entries) if decrypted_entries else 0} entries for {profile_name}")
                                except Exception as e:
                                    if args.debug:
                                        print(f"[DEBUG] decryptor {fn_name} failed for {profile_name}: {e}")
                                break

                    if decrypted_entries is None:
                        # Fallback: copy and read the JSON and use encrypted fields (no decryption)
                        dest = Path(temp_dir) / f"{profile_name}_logins.json"
                        shutil.copy2(str(login_json_path), str(dest))
                        with open(dest, 'r', encoding='utf-8') as ljf:
                            j = json.load(ljf)
                        entries = j.get('logins', [])
                        if args.debug:
                            print(f"[DEBUG] profile {profile_name}: loaded {len(entries)} saved logins (encrypted)")
                        for ent in entries:
                            origin = ent.get('hostname', '')
                            enc_user = ent.get('encryptedUsername')
                            enc_pass = ent.get('encryptedPassword')
                            time_created = ent.get('timeCreated')
                            # Normalize host and try to find history match
                            try:
                                login_host_raw = urlparse(origin).netloc.lower()
                            except Exception:
                                login_host_raw = ''
                            login_host = normalize_host(login_host_raw)
                            matched = False
                            last_visit_iso = ''
                            visit_count = 0
                            if login_host:
                                hist = history_map.get(login_host)
                                if hist:
                                    last_micro, cnt = hist
                                    if last_micro:
                                        dt = datetime.datetime.fromtimestamp(int(last_micro) / 1_000_000, tz=datetime.timezone.utc)
                                        last_visit_iso = dt.isoformat()
                                    visit_count = cnt or 0
                                    matched = True
                            logins_out.append({
                                'origin': origin,
                                'username': enc_user or '',
                                'password': enc_pass or '',
                                'timeCreated': time_created or '',
                                'profile': profile_name,
                            })
                    else:
                        # decrypted_entries expected to be an iterable of dicts with keys hostname, username, password, timeCreated (best-effort)
                        if args.debug:
                            print(f"[DEBUG] using decrypted entries for {profile_name}: {len(decrypted_entries)} items")
                        for ent in decrypted_entries:
                            # accommodate a few possible key names
                            origin = ent.get('hostname') or ent.get('origin') or ent.get('url') or ''
                            username = ent.get('username') or ent.get('user') or ent.get('login') or ''
                            password = ent.get('password') or ent.get('pass') or ent.get('decryptedPassword') or ''
                            time_created = ent.get('timeCreated') or ent.get('time_created') or ''
                            try:
                                login_host_raw = urlparse(origin).netloc.lower()
                            except Exception:
                                login_host_raw = ''
                            login_host = normalize_host(login_host_raw)
                            matched = False
                            last_visit_iso = ''
                            visit_count = 0
                            if login_host:
                                hist = history_map.get(login_host)
                                if hist:
                                    last_micro, cnt = hist
                                    if last_micro:
                                        dt = datetime.datetime.fromtimestamp(int(last_micro) / 1_000_000, tz=datetime.timezone.utc)
                                        last_visit_iso = dt.isoformat()
                                    visit_count = cnt or 0
                                    matched = True
                            logins_out.append({
                                'origin': origin,
                                'username': username or '',
                                'password': password or '',
                                'timeCreated': time_created or '',
                                'profile': profile_name,
                            })
                except Exception as e:
                    if args.debug:
                        print(f"[DEBUG] error reading logins for {profile_name}: {e}")
                    continue

            # write Chrome-style login-first CSV merged with history info
            try:
                tz_chi_local = tz_chicago()
                now_chi_local = datetime.datetime.now(tz_chi_local)
                cutoff_chi_local = now_chi_local - datetime.timedelta(days=args.days)
                cutoff_utc_local = cutoff_chi_local.astimezone(datetime.timezone.utc)
                cutoff_micro_local = int(cutoff_utc_local.timestamp() * 1_000_000)

                with open(args.logins_output, 'w', newline='', encoding='utf-8') as lf:
                    lw = csv.writer(lf)
                    lw.writerow(["origin_url", "username", "password", "timeCreated", "history_last_visit_utc", "visit_count", "match_method", "included", "reason", "profile"])
                    for ent in logins_out:
                        origin = ent.get('origin', '')
                        username = ent.get('username', '')
                        password = ent.get('password', '')
                        time_created = ent.get('timeCreated', '')
                        profile_name = ent.get('profile', '')

                        # normalize login host and look up history
                        try:
                            login_host_raw = urlparse(origin).netloc.lower()
                        except Exception:
                            login_host_raw = ''
                        login_host = normalize_host(login_host_raw)

                        matched = False
                        history_last_visit = ''
                        visit_count = 0
                        match_method = 'none'
                        included = False
                        reason = 'no-history'

                        if login_host:
                            h = history_map.get(login_host)
                            if h:
                                last_micro, cnt = h
                                match_method = 'host'
                                matched = True
                                visit_count = cnt or 0
                                if last_micro:
                                    try:
                                        dt = datetime.datetime.fromtimestamp(int(last_micro) / 1_000_000, tz=datetime.timezone.utc)
                                        history_last_visit = dt.isoformat()
                                    except Exception:
                                        history_last_visit = ''
                                # recency check
                                if last_micro and int(last_micro) >= cutoff_micro_local:
                                    included = True
                                    reason = 'included'
                                else:
                                    included = False
                                    reason = 'filtered'

                        if args.mask_passwords:
                            password_field = mask_password(password, True)
                        else:
                            password_field = password
                        lw.writerow([origin, username, password_field, time_created, history_last_visit, visit_count, match_method, str(included), reason, profile_name])

                print(f"[+] Login correlation CSV written: {args.logins_output} ({len(logins_out)} rows)")
            except Exception as e:
                print(f"Warning: failed to write login-output CSV: {e}")

        except Exception as e:
            print(f"Warning: could not correlate logins: {e}")
