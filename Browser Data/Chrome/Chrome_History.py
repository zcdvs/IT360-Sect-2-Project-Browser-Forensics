import os
import sqlite3
import csv
import shutil
import tempfile

# Path to Chrome History file
history_db = os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\History")

# Path for output CSV file
output_csv = "chrome_history.csv"

# Query: join visits with urls to get full visit history
query = """
SELECT 
    urls.url, 
    urls.title, 
    datetime(visits.visit_time/1000000-11644473600,'unixepoch') as visit_time
FROM visits
JOIN urls ON visits.url = urls.id
WHERE datetime(visits.visit_time/1000000-11644473600,'unixepoch') >= datetime('now','-14 days')
ORDER BY visit_time DESC;
"""


def main():
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
        cursor.execute(query)
        rows = cursor.fetchall()

        # Write results into CSV
        with open(output_csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["URL", "Title", "Visit Time"])
            writer.writerows(rows)

        print(f"History successfully exported to {output_csv}")
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
    raise SystemExit(main())
