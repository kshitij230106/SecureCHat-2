import sqlite3

conn = sqlite3.connect("database.db")
cursor = conn.cursor()

cursor.execute("DELETE FROM users")

conn.commit()
conn.close()

print("All registered users cleared.")
