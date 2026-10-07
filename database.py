import sqlite3

import hashlib

import os

from datetime import datetime

DATABASE = "database.db"


# ============================================================

# DATABASE CONNECTION

# ============================================================


def connect():

    return sqlite3.connect(DATABASE)


# ============================================================

# CREATE TABLES

# ============================================================


def create_tables():

    conn = connect()

    cursor = conn.cursor()

    # ========================================================

    # USERS

    # ========================================================

    cursor.execute("""

        CREATE TABLE IF NOT EXISTS users (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            username TEXT UNIQUE NOT NULL,

            password TEXT NOT NULL,

            created_at TEXT NOT NULL

        )

    """)

    # ========================================================

    # PRIVATE MESSAGES

    # ========================================================

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

    # ========================================================

    # GROUPS

    # ========================================================

    cursor.execute("""

        CREATE TABLE IF NOT EXISTS groups (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            group_name TEXT UNIQUE NOT NULL,

            owner TEXT NOT NULL,

            created_at TEXT NOT NULL

        )

    """)

    # ========================================================

    # GROUP MEMBERS

    # ========================================================

    cursor.execute("""

        CREATE TABLE IF NOT EXISTS group_members (

            group_id INTEGER,

            username TEXT,

            PRIMARY KEY(group_id, username)

        )

    """)

    # ========================================================

    # GROUP MESSAGES

    # ========================================================

    cursor.execute("""

        CREATE TABLE IF NOT EXISTS group_messages (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            group_id INTEGER,

            sender TEXT NOT NULL,

            message TEXT NOT NULL,

            timestamp TEXT NOT NULL

        )

    """)

    # ========================================================

    # PUBLIC KEY

    # ========================================================

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


# ============================================================

# VERIFY PASSWORD

# ============================================================


def verify_password(password, stored_password):

    try:

        salt_hex, hash_hex = stored_password.split(":")

        salt = bytes.fromhex(salt_hex)

        hashed = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000)

        return hashed.hex() == hash_hex

    except Exception:

        return False


# ============================================================

# CREATE USER

# ============================================================


def create_user(username, password):

    conn = connect()

    cursor = conn.cursor()

    try:

        hashed = hash_password(password)

        cursor.execute(
            """

            INSERT INTO users

            (

                username,

                password,

                created_at

            )

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


# ============================================================

# GET USER

# ============================================================


def get_user(username):

    conn = connect()

    cursor = conn.cursor()

    cursor.execute(
        """

        SELECT *

        FROM users

        WHERE username = ?

        """,
        (username,),
    )

    user = cursor.fetchone()

    conn.close()

    return user


# ============================================================

# VERIFY LOGIN

# ============================================================


def verify_login(username, password):

    user = get_user(username)

    if not user:

        return False

    stored_password = user[2]

    return verify_password(password, stored_password)


# ============================================================

# RESET PASSWORD

# ============================================================


def reset_password(username, new_password):

    conn = connect()

    cursor = conn.cursor()

    hashed = hash_password(new_password)

    cursor.execute(
        """

        UPDATE users

        SET password = ?

        WHERE username = ?

        """,
        (hashed, username),
    )

    changed = cursor.rowcount

    conn.commit()

    conn.close()

    return changed > 0


# ============================================================

# SAVE PUBLIC KEY

# ============================================================


def save_public_key(username, public_key):

    conn = connect()

    cursor = conn.cursor()

    cursor.execute(
        """

        UPDATE users

        SET public_key = ?

        WHERE username = ?

        """,
        (public_key, username),
    )

    conn.commit()

    conn.close()


# ============================================================

# UPDATE PUBLIC KEY

# Used by server.py

# ============================================================


def update_public_key(username, public_key):

    save_public_key(username, public_key)


# ============================================================

# GET PUBLIC KEY

# ============================================================


def get_public_key(username):

    conn = connect()

    cursor = conn.cursor()

    cursor.execute(
        """

        SELECT public_key

        FROM users

        WHERE username = ?

        """,
        (username,),
    )

    result = cursor.fetchone()

    conn.close()

    if result:

        return result[0]

    return None


# ============================================================

# SAVE PRIVATE MESSAGE

# ============================================================


def save_message(sender, receiver, message, status="sent"):

    conn = connect()

    cursor = conn.cursor()

    cursor.execute(
        """

        INSERT INTO messages

        (

            sender,

            receiver,

            message,

            timestamp,

            status

        )

        VALUES (?, ?, ?, ?, ?)

        """,
        (sender, receiver, message, datetime.now().isoformat(), status),
    )

    message_id = cursor.lastrowid

    conn.commit()

    conn.close()

    return message_id


# ============================================================

# GET MESSAGES

# ============================================================


def get_messages(user1, user2):

    conn = connect()

    cursor = conn.cursor()

    cursor.execute(
        """

        SELECT

            sender,

            receiver,

            message,

            timestamp,

            status

        FROM messages

        WHERE

            (sender = ? AND receiver = ?)

            OR

            (sender = ? AND receiver = ?)

        ORDER BY id

        """,
        (user1, user2, user2, user1),
    )

    messages = cursor.fetchall()

    conn.close()

    return messages


# ============================================================

# GET MESSAGES BETWEEN USERS

# Used by server.py

# ============================================================


def get_messages_between_users(user1, user2):

    conn = connect()

    cursor = conn.cursor()

    cursor.execute(
        """

        SELECT

            timestamp,

            sender,

            receiver,

            message

        FROM messages

        WHERE

            (sender = ? AND receiver = ?)

            OR

            (sender = ? AND receiver = ?)

        ORDER BY id

        """,
        (user1, user2, user2, user1),
    )

    messages = cursor.fetchall()

    conn.close()

    return messages


# ============================================================

# GET PENDING MESSAGES

# ============================================================


def get_pending_messages(username):

    conn = connect()

    cursor = conn.cursor()

    cursor.execute(
        """

        SELECT

            id,

            sender,

            message

        FROM messages

        WHERE

            receiver = ?

            AND status = 'sent'

        ORDER BY id

        """,
        (username,),
    )

    messages = cursor.fetchall()

    conn.close()

    return messages


# ============================================================

# UPDATE MESSAGE STATUS

# ============================================================


def update_message_status(message_id, status):

    conn = connect()

    cursor = conn.cursor()

    cursor.execute(
        """

        UPDATE messages

        SET status = ?

        WHERE id = ?

        """,
        (status, message_id),
    )

    conn.commit()

    conn.close()


# ============================================================

# CREATE GROUP

# ============================================================


def create_group(group_name, owner):

    conn = connect()

    cursor = conn.cursor()

    try:

        cursor.execute(
            """

            INSERT INTO groups

            (

                group_name,

                owner,

                created_at

            )

            VALUES (?, ?, ?)

            """,
            (group_name, owner, datetime.now().isoformat()),
        )

        group_id = cursor.lastrowid

        # Automatically add owner

        cursor.execute(
            """

            INSERT INTO group_members

            (

                group_id,

                username

            )

            VALUES (?, ?)

            """,
            (group_id, owner),
        )

        conn.commit()

        return True

    except sqlite3.IntegrityError:

        return False

    finally:

        conn.close()


# ============================================================

# GET GROUP

# ============================================================


def get_group(group_name):

    conn = connect()

    cursor = conn.cursor()

    cursor.execute(
        """

        SELECT

            id,

            group_name,

            owner

        FROM groups

        WHERE group_name = ?

        """,
        (group_name,),
    )

    group = cursor.fetchone()

    conn.close()

    return group


# ============================================================

# GET ALL GROUPS

# ============================================================


def get_groups():

    conn = connect()

    cursor = conn.cursor()

    cursor.execute("""

        SELECT group_name

        FROM groups

        ORDER BY group_name

        """)

    groups = cursor.fetchall()

    conn.close()

    return [group[0] for group in groups]


# ============================================================

# ADD GROUP MEMBER

# ============================================================


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
            """

            INSERT INTO group_members

            (

                group_id,

                username

            )

            VALUES (?, ?)

            """,
            (group[0], username),
        )

        conn.commit()

        return True

    except sqlite3.IntegrityError:

        return False

    finally:

        conn.close()


# ============================================================

# REMOVE GROUP MEMBER

# ============================================================


def remove_member(group_name, username):

    group = get_group(group_name)

    if not group:

        return False

    conn = connect()

    cursor = conn.cursor()

    cursor.execute(
        """

        DELETE FROM group_members

        WHERE

            group_id = ?

            AND username = ?

        """,
        (group[0], username),
    )

    removed = cursor.rowcount

    conn.commit()

    conn.close()

    return removed > 0


# ============================================================

# LEAVE GROUP

# ============================================================


def leave_group(group_name, username):

    return remove_member(group_name, username)


# ============================================================

# GET GROUP MEMBERS

# ============================================================


def get_group_members(group_name):

    group = get_group(group_name)

    if not group:

        return []

    conn = connect()

    cursor = conn.cursor()

    cursor.execute(
        """

        SELECT username

        FROM group_members

        WHERE group_id = ?

        ORDER BY username

        """,
        (group[0],),
    )

    members = cursor.fetchall()

    conn.close()

    return [member[0] for member in members]


# ============================================================

# CHECK GROUP MEMBERSHIP

# ============================================================


def is_group_member(group_name, username):

    members = get_group_members(group_name)

    return username in members


# ============================================================

# GET GROUP OWNER

# ============================================================


def get_group_owner(group_name):

    group = get_group(group_name)

    if not group:

        return None

    return group[2]


# ============================================================

# SAVE GROUP MESSAGE

# ============================================================


def save_group_message(group_name, sender, message):

    group = get_group(group_name)

    if not group:

        return False

    conn = connect()

    cursor = conn.cursor()

    cursor.execute(
        """

        INSERT INTO group_messages

        (

            group_id,

            sender,

            message,

            timestamp

        )

        VALUES (?, ?, ?, ?)

        """,
        (group[0], sender, message, datetime.now().isoformat()),
    )

    conn.commit()

    conn.close()

    return True


# ============================================================

# GET GROUP MESSAGES

# ============================================================


def get_group_messages(group_name):

    group = get_group(group_name)

    if not group:

        return []

    conn = connect()

    cursor = conn.cursor()

    cursor.execute(
        """

        SELECT

            sender,

            message,

            timestamp

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

# CLEAR USERS

# ============================================================


def clear_users():

    conn = connect()

    cursor = conn.cursor()

    cursor.execute("DELETE FROM users")

    conn.commit()

    conn.close()

    print("All users cleared.")


# ============================================================

# CLEAR PRIVATE MESSAGES

# ============================================================


def clear_messages():

    conn = connect()

    cursor = conn.cursor()

    cursor.execute("DELETE FROM messages")

    conn.commit()

    conn.close()

    print("All private messages cleared.")


# ============================================================

# CLEAR GROUP MESSAGES

# ============================================================


def clear_group_messages():

    conn = connect()

    cursor = conn.cursor()

    cursor.execute("DELETE FROM group_messages")

    conn.commit()

    conn.close()

    print("All group messages cleared.")


# ============================================================

# CLEAR GROUP MEMBERS

# ============================================================


def clear_group_members():

    conn = connect()

    cursor = conn.cursor()

    cursor.execute("DELETE FROM group_members")

    conn.commit()

    conn.close()

    print("All group memberships cleared.")


# ============================================================

# CLEAR GROUPS

# ============================================================


def clear_groups():

    conn = connect()

    cursor = conn.cursor()

    cursor.execute("DELETE FROM group_messages")

    cursor.execute("DELETE FROM group_members")

    cursor.execute("DELETE FROM groups")

    conn.commit()

    conn.close()

    print("All groups cleared.")


# ============================================================

# CLEAR EVERYTHING

# ============================================================


def clear_all():

    conn = connect()

    cursor = conn.cursor()

    cursor.execute("DELETE FROM group_messages")

    cursor.execute("DELETE FROM group_members")

    cursor.execute("DELETE FROM groups")

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
