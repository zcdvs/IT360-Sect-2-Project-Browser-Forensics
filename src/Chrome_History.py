import os
import sqlite3
import csv
import shutil
import tempfile

# Path to Chrome History file
import argparse

USER_DATA_ROOT = os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\User Data")
history_db = os.path.join(USER_DATA_ROOT, "Default", "History")

# Path for output CSV file (default)
output_csv = "chrome_history.csv"

# Query: join visits with urls to get full visit history
query = None
DEFAULT_DAYS = 14

def build_query(days_back: int):
    return f"""
SELECT 
    urls.url, 
    urls.title, 
    datetime(visits.visit_time/1000000-11644473600,'unixepoch') as visit_time
FROM visits
JOIN urls ON visits.url = urls.id
WHERE datetime(visits.visit_time/1000000-11644473600,'unixepoch') >= datetime('now','-{days_back} days')
ORDER BY visit_time DESC;
"""


def main(output_csv_arg=None, days_back=DEFAULT_DAYS, profile_name='Default'):
    global history_db
    history_db = os.path.join(USER_DATA_ROOT, profile_name, 'History')
    if not os.path.exists(history_db):
        print(f"ERROR: Chrome History DB not found: {history_db}")
        return 1

    temp_dir = None
    temp_path = None
    conn = None
    cursor = None

    try:
        # create a temporary directory and copy the History DB so Chrome's lock doesn't interfere
        temp_dir = tempfile.mkdtemp(prefix="chrome_history_")
        temp_path = os.path.join(temp_dir, "History.copy")
        shutil.copy2(history_db, temp_path)

        conn = sqlite3.connect(temp_path)
        cursor = conn.cursor()
        q = build_query(days_back)
        cursor.execute(q)
        rows = cursor.fetchall()

        # Write results into CSV
        outpath = output_csv if output_csv_arg is None else output_csv_arg
        with open(outpath, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["URL", "Title", "Visit Time"])
            writer.writerows(rows)

        print(f"History successfully exported to {outpath}")
        return 0

    except sqlite3.Error as e:
        print(f"SQLite error: {e}")
        return 2
    except Exception as e:
        print(f"Unexpected error: {e}")
        return 3
    finally:
        try:
            if cursor:
                cursor.close()
        except Exception:
            pass
        try:
            if conn:
                conn.close()
        except Exception:
            pass
        # cleanup temp copy
        try:
            if temp_path and os.path.exists(temp_path):
                os.remove(temp_path)
            if temp_dir and os.path.exists(temp_dir):
                os.rmdir(temp_dir)
        except Exception:
            # don't crash on cleanup failures
            pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Export Chrome history to CSV (copies History DB to temp folder)")
    parser.add_argument("--output", help="Output CSV file (default chrome_history.csv)")
    parser.add_argument("--days", type=int, default=DEFAULT_DAYS, help="Days back cutoff (default 14)")
    parser.add_argument("--profile", default='Default', help="Chrome profile folder name (Default or Profile 1 etc.)")
    args = parser.parse_args()
    raise SystemExit(main(output_csv_arg=args.output, days_back=args.days))
