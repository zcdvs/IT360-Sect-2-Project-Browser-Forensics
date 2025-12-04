import os
import sqlite3
import csv
import shutil
import tempfile
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

def chrome_time_to_local(chrome_time):
    """Convert various Chrome timestamps to local Chicago time.

    Chrome/SQLite may store timestamps in different units/epochs depending on
    the table or Chrome version. This helper tries the common formats and
    picks the one that yields a sensible year (between 1970 and 2100):
      - WebKit / Chrome time: microseconds since 1601-01-01 UTC
      - Unix milliseconds since 1970-01-01 UTC
      - Unix seconds since 1970-01-01 UTC

    If none produce a reasonable year, it falls back to the WebKit conversion
    (which previously produced dates around year 1600 when the input was
    actually a Unix timestamp).
    """
    try:
        ts = int(chrome_time)
    except Exception:
        return ""

    if ts == 0:
        return ""

    def to_chicago(dt: datetime) -> str:
        try:
            return dt.astimezone(ZoneInfo("America/Chicago")).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return ""

    # Use magnitude-based detection:
    #   webkit microseconds since 1601: typically >= 1e16
    #   unix milliseconds since 1970: typically around 1e12
    #   unix seconds since 1970: typically around 1e9
    ts_abs = abs(ts)

    try:
        if ts_abs > 1e14:
            # WebKit (microseconds since 1601)
            dt = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=ts)
            return to_chicago(dt)
        elif ts_abs > 1e11:
            # Milliseconds since 1970
            dt = datetime.fromtimestamp(ts / 1000, tz=timezone.utc)
            return to_chicago(dt)
        elif ts_abs > 1e8:
            # Seconds since 1970
            dt = datetime.fromtimestamp(ts, tz=timezone.utc)
            return to_chicago(dt)
        else:
            # Too small to be a valid timestamp we can parse
            return ""
    except Exception:
        return ""

def table_exists(cursor, table_name):
    """Check if a table exists and return list of all tables."""
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [row[0] for row in cursor.fetchall()]
    return table_name in tables, tables

def fetch_table_data(db_path, table_name):
    """Fetch and clean up data for a given Chrome Web Data table."""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        exists, all_tables = table_exists(cursor, table_name)
        if not exists:
            print(f"[!] Table '{table_name}' not found. Available tables:")
            print(all_tables)
            conn.close()
            return [], []

        if table_name == "address_type_tokens":
            # Dynamically get columns and drop unwanted ones
            cursor.execute("PRAGMA table_info(address_type_tokens)")
            cols = [c[1] for c in cursor.fetchall()]
            selected_cols = [c for c in cols if c not in (
                "type", "column", "verification_status", "observation"
            )]
            query = f"SELECT {', '.join(selected_cols)} FROM address_type_tokens"

        elif table_name == "autofill":
            cursor.execute("PRAGMA table_info(autofill)")
            cols = [c[1] for c in cursor.fetchall()]
            selected_cols = [c for c in cols if c != "value_lower"]
            query = f"SELECT {', '.join(selected_cols)} FROM autofill"

        else:
            conn.close()
            return [], []

        cursor.execute(query)
        rows = cursor.fetchall()
        columns = [desc[0] for desc in cursor.description]
        conn.close()

        # Convert Chrome timestamps for autofill
        if table_name == "autofill":
            date_cols = [c for c in ["date_created", "date_last_used"] if c in columns]
            date_indices = [columns.index(c) for c in date_cols]
            converted_rows = []
            for row in rows:
                row = list(row)
                for idx in date_indices:
                    if row[idx]:
                        row[idx] = chrome_time_to_local(row[idx])
                converted_rows.append(row)
            rows = converted_rows

        return columns, rows

    except sqlite3.Error as e:
        print(f"[ERROR] Could not read table {table_name}: {e}")
        return [], []

def write_csv(filename, data_dict):
    """Write table data to a clean CSV with headers."""
    with open(filename, mode="w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        for table_name, (columns, rows) in data_dict.items():
            if columns and rows:
                writer.writerow(columns)
                for row in rows:
                    writer.writerow(row)
            else:
                print(f"[!] No data found for table: {table_name}")
    print(f"[+] Data exported to {filename}")

def export_chrome_autofill_data(output_file=None):
    """Main export function."""
    chrome_data_path = os.path.join(os.environ["LOCALAPPDATA"], 
                                    r"Google\Chrome\User Data\Default")
    web_data_path = os.path.join(chrome_data_path, "Web Data")

    if not os.path.exists(web_data_path):
        print(f"[ERROR] Chrome Web Data file not found at: {web_data_path}")
        return

    # Copy DB to temp file to avoid locking issues when Chrome is open
    temp_dir = tempfile.mkdtemp(prefix="chrome_autofill_")
    temp_db = os.path.join(temp_dir, "Web Data")
    try:
        shutil.copy2(web_data_path, temp_db)
    except Exception as e:
        print(f"[ERROR] Could not copy Web Data to temp: {e}")
        return

    output_filename = output_file if output_file else "Autofill & Address.csv"

    print(f"[*] Reading from: {web_data_path}")
    print("[*] Extracting table: 'autofill'...")

    # Only export the autofill table; address_type_tokens removed from output
    tables_to_export = ["autofill"]
    data = {}

    for table in tables_to_export:
        columns, rows = fetch_table_data(temp_db, table)
        data[table] = (columns, rows)

    write_csv(output_filename, data)
    
    # Cleanup temp
    try:
        os.remove(temp_db)
        os.rmdir(temp_dir)
    except Exception:
        pass

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Export Chrome autofill data to CSV")
    parser.add_argument("--output", "-o", help="Output CSV file path")
    args = parser.parse_args()
    export_chrome_autofill_data(output_file=args.output)