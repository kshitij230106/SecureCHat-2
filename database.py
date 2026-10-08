import sqlite3

import hashlib

import os

from datetime import datetime

DATABASE = "database.db"


# ============================================================
# DATABASE CONNECTION
# ============================================================


def connect():

    conn = sqlite3.connect(DATABASE, timeout=30, check_same_thread=False)

    conn.execute("PRAGMA journal_mode=WAL")

    conn.execute("PRAGMA busy_timeout=5000")

    return conn


# ============================================================
# CREATE TABLES
# ============================================================


def create_tables():

    conn = connect()

    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT NOT NULL,
            receiver TEXT NOT NULL,
            message TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            status TEXT DEFAULT 'sent'
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            group_name TEXT UNIQUE NOT NULL,
            owner TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS group_members (
            group_id INTEGER,
            username TEXT,
            PRIMARY KEY(group_id, username)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS group_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id INTEGER,
            sender TEXT NOT NULL,
            message TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )
    """)

    try:

        cursor.execute("ALTER TABLE users ADD COLUMN public_key TEXT")

    except sqlite3.OperationalError:

        pass

    conn.commit()

    conn.close()


# ============================================================
# PASSWORD HASHING
# ============================================================


def hash_password(password):

    salt = os.urandom(16)

    hashed = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000)

    return salt.hex() + ":" + hashed.hex()


def verify_password(password, stored_password):

    try:

        salt_hex, hash_hex = stored_password.split(":")

        salt = bytes.fromhex(salt_hex)

        hashed = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000)

        return hashed.hex() == hash_hex

    except Exception:

        return False


# ============================================================
# USERS
# ============================================================


def create_user(username, password):

    conn = connect()

    cursor = conn.cursor()

    try:

        hashed = hash_password(password)

        cursor.execute(
            """
            INSERT INTO users (username, password, created_at)
            VALUES (?, ?, ?)
            """,
            (username, hashed, datetime.now().isoformat()),
        )

        conn.commit()

        return True

    except sqlite3.IntegrityError:

        return False

    finally:

        conn.close()


def get_user(username):

    conn = connect()

    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))

    user = cursor.fetchone()

    conn.close()

    return user


def get_all_usernames():
    """All registered usernames (online or not). Read-only helper."""

    conn = connect()

    cursor = conn.cursor()

    cursor.execute("SELECT username FROM users ORDER BY username")

    rows = cursor.fetchall()

    conn.close()

    return [row[0] for row in rows]


def verify_login(username, password):

    user = get_user(username)

    if not user:

        return False

    stored_password = user[2]

    return verify_password(password, stored_password)


def reset_password(username, new_password):

    conn = connect()

    cursor = conn.cursor()

    hashed = hash_password(new_password)

    cursor.execute(
        "UPDATE users SET password = ? WHERE username = ?",
        (hashed, username),
    )

    changed = cursor.rowcount

    conn.commit()

    conn.close()

    return changed > 0


# ============================================================
# PUBLIC KEYS
# ============================================================


def save_public_key(username, public_key):

    conn = connect()

    cursor = conn.cursor()

    cursor.execute(
        "UPDATE users SET public_key = ? WHERE username = ?",
        (public_key, username),
    )

    conn.commit()

    conn.close()


def update_public_key(username, public_key):

    save_public_key(username, public_key)


def get_public_key(username):

    conn = connect()

    cursor = conn.cursor()

    cursor.execute("SELECT public_key FROM users WHERE username = ?", (username,))

    result = cursor.fetchone()

    conn.close()

    if result:

        return result[0]

    return None


# ============================================================
# PRIVATE MESSAGES
# ============================================================


def save_message(sender, receiver, message, status="sent"):

    conn = connect()

    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO messages (sender, receiver, message, timestamp, status)
        VALUES (?, ?, ?, ?, ?)
        """,
        (sender, receiver, message, datetime.now().isoformat(), status),
    )

    message_id = cursor.lastrowid

    conn.commit()

    conn.close()

    return message_id


def get_messages(user1, user2):

    conn = connect()

    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT sender, receiver, message, timestamp, status
        FROM messages
        WHERE (sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?)
        ORDER BY id
        """,
        (user1, user2, user2, user1),
    )

    messages = cursor.fetchall()

    conn.close()

    return messages


def get_messages_between_users(user1, user2):

    conn = connect()

    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT timestamp, sender, receiver, message
        FROM messages
        WHERE (sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?)
        ORDER BY id
        """,
        (user1, user2, user2, user1),
    )

    messages = cursor.fetchall()

    conn.close()

    return messages


def get_pending_messages(username):

    conn = connect()

    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT id, sender, message
        FROM messages
        WHERE receiver = ? AND status = 'sent'
        ORDER BY id
        """,
        (username,),
    )

    messages = cursor.fetchall()

    conn.close()

    return messages


def update_message_status(message_id, status):

    conn = connect()

    cursor = conn.cursor()

    cursor.execute(
        "UPDATE messages SET status = ? WHERE id = ?",
        (status, message_id),
    )

    conn.commit()

    conn.close()


# ============================================================
# GROUPS
# ============================================================


def create_group(group_name, owner):

    conn = connect()

    cursor = conn.cursor()

    try:

        cursor.execute(
            """
            INSERT INTO groups (group_name, owner, created_at)
            VALUES (?, ?, ?)
            """,
            (group_name, owner, datetime.now().isoformat()),
        )

        group_id = cursor.lastrowid

        # The owner is automatically a member

        cursor.execute(
            "INSERT INTO group_members (group_id, username) VALUES (?, ?)",
            (group_id, owner),
        )

        conn.commit()

        return True

    except sqlite3.IntegrityError:

        return False

    finally:

        conn.close()


def get_group(group_name):

    conn = connect()

    cursor = conn.cursor()

    cursor.execute(
        'SELECT id, group_name, owner FROM "groups" WHERE group_name = ?',
        (group_name,),
    )

    group = cursor.fetchone()

    conn.close()

    return group


def get_groups():

    conn = connect()

    cursor = conn.cursor()

    cursor.execute('SELECT group_name FROM "groups" ORDER BY group_name')

    groups = cursor.fetchall()

    conn.close()

    return [group[0] for group in groups]


def get_groups_for_user(username):
    """Only the groups this user is a member of. Read-only helper."""

    conn = connect()

    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT g.group_name
        FROM "groups" g
        JOIN group_members m ON m.group_id = g.id
        WHERE m.username = ?
        ORDER BY g.group_name
        """,
        (username,),
    )

    rows = cursor.fetchall()

    conn.close()

    return [row[0] for row in rows]


def add_member(group_name, username):

    group = get_group(group_name)

    if not group:

        return False

    if not get_user(username):

        return False

    conn = connect()

    cursor = conn.cursor()

    try:

        cursor.execute(
            "INSERT INTO group_members (group_id, username) VALUES (?, ?)",
            (group[0], username),
        )

        conn.commit()

        return True

    except sqlite3.IntegrityError:

        return False

    finally:

        conn.close()


def remove_member(group_name, username):

    group = get_group(group_name)

    if not group:

        return False

    conn = connect()

    cursor = conn.cursor()

    cursor.execute(
        "DELETE FROM group_members WHERE group_id = ? AND username = ?",
        (group[0], username),
    )

    removed = cursor.rowcount

    conn.commit()

    conn.close()

    return removed > 0


def leave_group(group_name, username):

    return remove_member(group_name, username)


def get_group_members(group_name):

    group = get_group(group_name)

    if not group:

        return []

    conn = connect()

    cursor = conn.cursor()

    cursor.execute(
        "SELECT username FROM group_members WHERE group_id = ? ORDER BY username",
        (group[0],),
    )

    members = cursor.fetchall()

    conn.close()

    return [member[0] for member in members]


def is_group_member(group_name, username):

    return username in get_group_members(group_name)


def get_group_owner(group_name):

    group = get_group(group_name)

    if not group:

        return None

    return group[2]


# ============================================================
# GROUP MESSAGES
# ============================================================


def save_group_message(group_name, sender, message):

    group = get_group(group_name)

    if not group:

        return False

    conn = connect()

    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO group_messages (group_id, sender, message, timestamp)
        VALUES (?, ?, ?, ?)
        """,
        (group[0], sender, message, datetime.now().isoformat()),
    )

    conn.commit()

    conn.close()

    return True


def get_group_messages(group_name):

    group = get_group(group_name)

    if not group:

        return []

    conn = connect()

    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT sender, message, timestamp
        FROM group_messages
        WHERE group_id = ?
        ORDER BY id
        """,
        (group[0],),
    )

    messages = cursor.fetchall()

    conn.close()

    return messages


# ============================================================
# MAINTENANCE
# ============================================================


def clear_users():

    conn = connect()

    cursor = conn.cursor()

    cursor.execute("DELETE FROM users")

    conn.commit()

    conn.close()

    print("All users cleared.")


def clear_messages():

    conn = connect()

    cursor = conn.cursor()

    cursor.execute("DELETE FROM messages")

    conn.commit()

    conn.close()

    print("All private messages cleared.")


def clear_group_messages():

    conn = connect()

    cursor = conn.cursor()

    cursor.execute("DELETE FROM group_messages")

    conn.commit()

    conn.close()

    print("All group messages cleared.")


def clear_group_members():

    conn = connect()

    cursor = conn.cursor()

    cursor.execute("DELETE FROM group_members")

    conn.commit()

    conn.close()

    print("All group memberships cleared.")


def clear_groups():

    conn = connect()

    cursor = conn.cursor()

    cursor.execute("DELETE FROM group_messages")

    cursor.execute("DELETE FROM group_members")

    cursor.execute('DELETE FROM "groups"')

    conn.commit()

    conn.close()

    print("All groups cleared.")


def clear_all():

    conn = connect()

    cursor = conn.cursor()

    cursor.execute("DELETE FROM group_messages")

    cursor.execute("DELETE FROM group_members")

    cursor.execute('DELETE FROM "groups"')

    cursor.execute("DELETE FROM messages")

    cursor.execute("DELETE FROM users")

    conn.commit()

    conn.close()

    print("Database completely cleared.")


# ============================================================
# INITIALIZE
# ============================================================


if __name__ == "__main__":

    create_tables()

    print("Database initialized successfully.")
