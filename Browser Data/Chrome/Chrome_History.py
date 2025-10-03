import os
import sqlite3
import csv

# Path to Chrome History file
history_db = os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\History")

# Path for output CSV file
output_csv = "chrome_history.csv"

# Connect to the SQLite DB
conn = sqlite3.connect(history_db)
cursor = conn.cursor()

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

cursor.execute(query)
rows = cursor.fetchall()

# Write results into CSV
with open(output_csv, "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(["URL", "Title", "Visit Time"])
    writer.writerows(rows)

cursor.close()
conn.close()

print(f"History successfully exported to {output_csv}")
