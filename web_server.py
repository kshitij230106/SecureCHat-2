import socket

import threading

import base64

import hmac

import secrets

from datetime import datetime

from urllib.parse import unquote

from flask import Flask, render_template, request

from flask_socketio import SocketIO

import database

import key_manager

import encryption

from cryptography.hazmat.primitives.asymmetric import padding

from cryptography.hazmat.primitives import hashes

# ============================================================
# CONFIG
# ============================================================

TCP_HOST = "127.0.0.1"

TCP_PORT = 5000

WEB_HOST = "127.0.0.1"

WEB_PORT = 8000

# A browser that disappears (closed tab) keeps its TCP session for this
# long so a page refresh / page change can re-attach. After that the TCP
# session is closed and the user is shown as offline.

GRACE_SECONDS = 20

LOGIN_ATTACH_SECONDS = 60

MAX_TEXT_LENGTH = 4000

QUEUE_LIMIT = 500

COALESCED_EVENTS = {"users", "groups", "all_users"}

# ============================================================
# FLASK
# ============================================================

app = Flask(
    __name__, static_folder="web", static_url_path="/static", template_folder="web"
)

# Browser <-> web_server uses the WebSocket transport (simple-websocket).

socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="threading",
    logger=True,
    engineio_logger=True,
    ping_interval=25,
    ping_timeout=60,
)

# ============================================================
# GLOBAL STATE
# ============================================================

web_clients = {}  # username -> TCP socket to server.py

browser_ids = {}  # username -> current Socket.IO sid (only while attached)

session_tokens = {}  # username -> secret required to attach

pending_events = {}  # username -> events waiting for the browser to attach

history_requests = {}  # username -> queue of private-history targets

cleanup_timers = {}  # username -> threading.Timer

clients_lock = threading.Lock()

tcp_send_locks = {}

tcp_send_locks_lock = threading.Lock()

# ============================================================
# ROUTES
# ============================================================


@app.route("/")
def index():

    return render_template("index.html")


@app.route("/chat")
def chat_page():

    return render_template("chat.html")


# IMPORTANT: do NOT add a catch-all route such as "/<path:path>";
# Flask-SocketIO must handle /socket.io/ itself.

# ============================================================
# TCP SEND / RECEIVE
# ============================================================


def tcp_send(client, message):

    if client is None:

        return False

    lock_id = id(client)

    with tcp_send_locks_lock:

        send_lock = tcp_send_locks.setdefault(lock_id, threading.Lock())

    try:

        with send_lock:

            client.sendall((message + "\n").encode("utf-8"))

        return True

    except Exception as e:

        print("[TCP SEND ERROR]", e)

        return False


def tcp_receive_line(client, buffer):

    try:

        while b"\n" not in buffer:

            data = client.recv(8192)

            if not data:

                return None, buffer

            buffer += data

        line, buffer = buffer.split(b"\n", 1)

        return line.decode("utf-8", errors="replace").strip(), buffer

    except Exception as e:

        print("[TCP RECEIVE ERROR]", e)

        return None, buffer


# ============================================================
# SESSION HELPERS
# ============================================================


def get_session(sid):

    with clients_lock:

        for username, browser_sid in browser_ids.items():

            if browser_sid == sid:

                return username, web_clients.get(username)

    return None, None


def get_username_from_sid(sid):

    return get_session(sid)[0]


def clean_arg(value):
    """Strip a value coming from the browser; reject control characters
    that could inject extra TCP commands."""

    value = str(value if value is not None else "").strip()

    if "\n" in value or "\r" in value:

        return ""

    return value


def group_arg(data):

    data = data or {}

    return clean_arg(data.get("groupname") or data.get("group"))


def emit_error(sid, message):

    socketio.emit("error", {"message": message}, to=sid)


def send_command(command, quiet=False):
    """Send a TCP command on behalf of the browser that raised the event."""

    sid = request.sid

    username, tcp_client = get_session(sid)

    if not username or not tcp_client:

        if not quiet:

            emit_error(sid, "Session not found. Please log in again.")

        return False

    return tcp_send(tcp_client, command)


# ------------------------------------------------------------
# Delivery to the browser. If the browser is not attached yet
# (page change, short reconnect) the event is queued and flushed
# on attach, and message ACKs are only sent once delivered.
# ------------------------------------------------------------


def deliver(username, event, data=None, ack_id=None):

    with clients_lock:

        sid = browser_ids.get(username)

        tcp_client = web_clients.get(username)

        if not sid:

            if tcp_client is None:

                return False

            queue = pending_events.setdefault(username, [])

            if event in COALESCED_EVENTS:

                queue[:] = [item for item in queue if item[0] != event]

            queue.append((event, data, ack_id))

            if len(queue) > QUEUE_LIMIT:

                del queue[0]

            return False

    try:

        socketio.emit(event, data, to=sid)

    except Exception as e:

        print("[SOCKET EMIT ERROR]", e)

    if ack_id and tcp_client:

        tcp_send(tcp_client, "/ack|" + ack_id)

    return True


def flush_pending(username):

    with clients_lock:

        queue = pending_events.pop(username, [])

        sid = browser_ids.get(username)

        tcp_client = web_clients.get(username)

    if not sid:

        return

    for event, data, ack_id in queue:

        try:

            socketio.emit(event, data, to=sid)

        except Exception as e:

            print("[SOCKET EMIT ERROR]", e)

        if ack_id and tcp_client:

            tcp_send(tcp_client, "/ack|" + ack_id)


def broadcast_users():

    with clients_lock:

        users = list(web_clients.keys())

    for username in users:

        deliver(username, "users", {"users": users})


# ------------------------------------------------------------
# Session lifetime
# ------------------------------------------------------------


def cancel_cleanup(username):

    with clients_lock:

        timer = cleanup_timers.pop(username, None)

    if timer:

        timer.cancel()


def schedule_cleanup(username, delay):

    cancel_cleanup(username)

    timer = threading.Timer(delay, cleanup_if_detached, args=(username,))

    timer.daemon = True

    with clients_lock:

        cleanup_timers[username] = timer

    timer.start()


def cleanup_if_detached(username):

    with clients_lock:

        cleanup_timers.pop(username, None)

        attached = username in browser_ids

    if not attached:

        print("[SESSION EXPIRED]", username)

        end_session(username)


def end_session(username):

    with clients_lock:

        tcp_client = web_clients.pop(username, None)

        browser_ids.pop(username, None)

        session_tokens.pop(username, None)

        pending_events.pop(username, None)

        history_requests.pop(username, None)

        timer = cleanup_timers.pop(username, None)

    if timer:

        timer.cancel()

    if tcp_client:

        try:

            tcp_send(tcp_client, "/exit")

            tcp_client.close()

        except Exception:

            pass

        with tcp_send_locks_lock:

            tcp_send_locks.pop(id(tcp_client), None)

    broadcast_users()


# ============================================================
# AUTHENTICATION  ->  (success, message)
# ============================================================


def authenticate_web_user(tcp_client, choice, username, password):

    try:

        response, buffer = tcp_receive_line(tcp_client, b"")

        if response != "AUTH_REQUEST":

            return False, "Unexpected response from chat server"

        for value, expected in ((choice, "USERNAME"), (username, "PASSWORD")):

            tcp_send(tcp_client, value)

            response, buffer = tcp_receive_line(tcp_client, buffer)

            if response and response.startswith("AUTH_FAILED|"):

                return False, response.split("|", 1)[1]

            if response != expected:

                return False, "Unexpected response from chat server"

        tcp_send(tcp_client, password)

        response, buffer = tcp_receive_line(tcp_client, buffer)

        print("[AUTH]", response)

        if response is None:

            return False, "Chat server closed the connection"

        if response.startswith("AUTH_FAILED|"):

            return False, response.split("|", 1)[1]

        if not response.startswith("AUTH_SUCCESS|"):

            return False, "Unexpected response from chat server"

        success_message = response.split("|", 1)[1]

        # Registration ends here: server.py closes the connection
        # after AUTH_SUCCESS and sends no READY handshake.

        if choice == "REGISTER":

            return True, success_message

        response, buffer = tcp_receive_line(tcp_client, buffer)

        if response != "READY_REQUEST":

            return False, "Handshake failed"

        tcp_send(tcp_client, "READY")

        response, buffer = tcp_receive_line(tcp_client, buffer)

        if response != "READY_OK":

            return False, "Handshake failed"

        return True, success_message

    except Exception as e:

        print("[AUTH ERROR]", e)

        return False, "Authentication error"


# ============================================================
# ENCRYPTION KEYS
# ============================================================


def ensure_user_keys(username):

    try:

        key_manager.generate_keys(username)

        print("[KEYS READY]", username)

        return True

    except Exception as e:

        print("[KEY ERROR]", username, e)

        return False


def register_public_key(username, tcp_client):

    try:

        public_key = key_manager.get_public_key_text(username)

        command = "PUBLIC_KEY|" + username + "|" + public_key

        return tcp_send(tcp_client, command)

    except Exception as e:

        print("[PUBLIC KEY ERROR]", e)

        return False


# ============================================================
# ENCRYPT / DECRYPT
#
# Each private message is stored encrypted TWICE inside one string:
# once for the receiver and once for the sender, so both people can
# read the conversation in their history:
#
#     V2#<receiver blob>#S#<sender blob>
#
# A blob is the original format:  <RSA-wrapped key>||<ciphertext>
# Messages stored in the old single-blob format still work (for the
# receiver).
# ============================================================


def _encrypt_blob(public_key_text, text):

    public_key = key_manager.public_key_from_text(public_key_text)

    symmetric_key = encryption.generate_key()

    encrypted_message = encryption.encrypt_message(text, symmetric_key)

    encrypted_key = public_key.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    encrypted_key_text = base64.b64encode(encrypted_key).decode("utf-8")

    return encrypted_key_text + "||" + encrypted_message


def encrypt_for_conversation(sender, receiver, text):

    try:

        receiver_key = database.get_public_key(receiver)

        if not receiver_key:

            print("[ENCRYPT ERROR] Public key not found:", receiver)

            return None

        receiver_blob = _encrypt_blob(receiver_key, text)

        sender_key = database.get_public_key(sender)

        if not sender_key:

            return receiver_blob

        sender_blob = _encrypt_blob(sender_key, text)

        return "V2#" + receiver_blob + "#S#" + sender_blob

    except Exception as e:

        print("[ENCRYPT ERROR]", sender, "->", receiver, e)

        return None


def _decrypt_blob(username, blob):

    try:

        encrypted_key, encrypted_message = blob.split("||", 1)

        private_key = key_manager.load_private_key(username)

        encrypted_key_bytes = base64.b64decode(encrypted_key)

        symmetric_key = private_key.decrypt(
            encrypted_key_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        return encryption.decrypt_message(encrypted_message, symmetric_key)

    except Exception as e:

        print("[DECRYPT ERROR]", username, e)

        return None


def decrypt_payload(username, payload, as_sender=False):

    if payload.startswith("V2#"):

        body = payload[3:]

        if "#S#" not in body:

            return None

        receiver_blob, sender_blob = body.split("#S#", 1)

        return _decrypt_blob(username, sender_blob if as_sender else receiver_blob)

    # Old single-blob format: only the receiver can read it.

    if as_sender:

        return None

    return _decrypt_blob(username, payload)


# ============================================================
# TCP RECEIVER (server.py -> browser)
# ============================================================


def receive_from_tcp(username, tcp_client):

    buffer = b""

    print("[TCP RECEIVER STARTED]", username)

    try:

        while True:

            message, buffer = tcp_receive_line(tcp_client, buffer)

            if message is None:

                break

            if not message:

                continue

            print("[TCP -> WEB]", username, ":", message[:200])

            # USERS

            if message.startswith("USERS|"):

                users_text = message.split("|", 1)[1]

                users = users_text.split("|") if users_text else []

                deliver(username, "users", {"users": users})

            # ALL REGISTERED USERS

            elif message.startswith("ALLUSERS|"):

                users_text = message.split("|", 1)[1]

                users = users_text.split("|") if users_text else []

                deliver(username, "all_users", {"users": users})

            # GROUPS

            elif message.startswith("GROUPS|"):

                groups_text = message.split("|", 1)[1]

                groups = groups_text.split("|") if groups_text else []

                deliver(username, "groups", {"groups": groups})

            # PUBLIC KEY

            elif message.startswith("PUBLIC_KEY|"):

                parts = message.split("|", 2)

                if len(parts) == 3:

                    deliver(
                        username, "public_key", {"username": parts[1], "key": parts[2]}
                    )

            elif message.startswith("KEY_SUCCESS|"):

                deliver(username, "key_success", {"message": message.split("|", 1)[1]})

            # PRIVATE MESSAGE

            elif message.startswith("MESSAGE|"):

                parts = message.split("|", 3)

                if len(parts) != 4:

                    continue

                sender = parts[1]

                message_id = parts[2]

                payload = parts[3]

                text = decrypt_payload(username, payload)

                if text is None:

                    deliver(
                        username,
                        "error",
                        {"message": "Could not decrypt a message from " + sender},
                    )

                    continue

                deliver(
                    username,
                    "message",
                    {
                        "sender": sender,
                        "message_id": message_id,
                        "message": text,
                        "timestamp": datetime.now().isoformat(),
                    },
                    ack_id=message_id if message_id != "0" else None,
                )

            # PRIVATE HISTORY

            elif message.startswith("HISTORY|"):

                history_text = message.split("|", 1)[1]

                history = []

                if history_text:

                    for record in history_text.split(";;"):

                        try:

                            parts = record.split(" | ", 2)

                            if len(parts) != 3:

                                continue

                            timestamp = parts[0]

                            user_parts = parts[1].split(" -> ")

                            if len(user_parts) != 2:

                                continue

                            sender = user_parts[0]

                            receiver = user_parts[1]

                            text = decrypt_payload(
                                username, parts[2], as_sender=(sender == username)
                            )

                            if text is None:

                                if sender != username:

                                    continue

                                text = "[Earlier message - not available to sender]"

                            history.append(
                                {
                                    "sender": sender,
                                    "receiver": receiver,
                                    "message": text,
                                    "timestamp": timestamp,
                                }
                            )

                        except Exception as e:

                            print("[HISTORY ERROR]", e)

                with clients_lock:

                    queue = history_requests.get(username) or []

                    peer = queue.pop(0) if queue else ""

                deliver(username, "history", {"with": peer, "history": history})

            # GROUP MESSAGE

            elif message.startswith("GROUP|"):

                parts = message.split("|", 3)

                if len(parts) == 4:

                    group_name = parts[1]

                    sender = parts[2]

                    text = parts[3]

                elif len(parts) == 3:

                    group_name = parts[1]

                    sender = ""

                    text = parts[2]

                else:

                    continue

                deliver(
                    username,
                    "group_message",
                    {
                        "group": group_name,
                        "sender": sender,
                        "message": text,
                        "timestamp": datetime.now().isoformat(),
                    },
                )

            # GROUP HISTORY

            elif message.startswith("GROUP_HISTORY|"):

                parts = message.split("|", 2)

                group_name = parts[1] if len(parts) >= 2 else ""

                history = []

                if len(parts) == 3 and parts[2]:

                    for record in parts[2].split(";;"):

                        fields = record.split(" | ", 2)

                        if len(fields) != 3:

                            continue

                        history.append(
                            {
                                "timestamp": fields[0],
                                "sender": fields[1],
                                "message": unquote(fields[2]),
                            }
                        )

                deliver(
                    username, "group_history", {"group": group_name, "history": history}
                )

            # MEMBERS  ->  MEMBERS|group|admin|m1|m2...

            elif message.startswith("MEMBERS|"):

                parts = message.split("|")

                if len(parts) >= 3:

                    deliver(
                        username,
                        "members",
                        {
                            "group": parts[1],
                            "admin": parts[2],
                            "members": [m for m in parts[3:] if m],
                        },
                    )

            elif message.startswith("GROUP_CREATED|"):

                deliver(username, "group_created", {"group": message.split("|", 1)[1]})

            elif message.startswith("JOINED|"):

                deliver(username, "joined", {"group": message.split("|", 1)[1]})

            elif message.startswith("LEFT|"):

                deliver(username, "left", {"group": message.split("|", 1)[1]})

            elif message.startswith("GROUP_UPDATED|"):

                deliver(username, "group_updated", {"group": message.split("|", 1)[1]})

            elif message.startswith("MEMBER_ADDED|"):

                parts = message.split("|", 2)

                if len(parts) == 3:

                    deliver(
                        username,
                        "member_added",
                        {"group": parts[1], "username": parts[2]},
                    )

            elif message.startswith("MEMBER_REMOVED|"):

                parts = message.split("|", 2)

                if len(parts) == 3:

                    deliver(
                        username,
                        "member_removed",
                        {"group": parts[1], "username": parts[2]},
                    )

            elif message == "SENT":

                deliver(username, "sent", {"success": True})

            elif message.startswith("SERVER|"):

                deliver(username, "server", {"message": message.split("|", 1)[1]})

            elif message.startswith("ERROR|"):

                deliver(username, "error", {"message": message.split("|", 1)[1]})

            elif message == "SERVER_SHUTDOWN":

                deliver(username, "server_shutdown", {})

                break

    except Exception as e:

        print("[TCP RECEIVER ERROR]", username, e)

    finally:

        print("[TCP RECEIVER CLOSED]", username)

        with clients_lock:

            mine = web_clients.get(username) is tcp_client

            sid = browser_ids.get(username) if mine else None

        if mine:

            if sid:

                socketio.emit(
                    "session_closed",
                    {"message": "Connection to the chat server was lost."},
                    to=sid,
                )

            end_session(username)

        else:

            try:

                tcp_client.close()

            except Exception:

                pass


# ============================================================
# LOGIN
# ============================================================


@socketio.on("login")
def login(data):

    sid = request.sid

    data = data or {}

    username = str(data.get("username", "")).strip()

    password = str(data.get("password", ""))

    if not username or not password:

        socketio.emit(
            "login_error", {"message": "Username and password required"}, to=sid
        )

        return

    with clients_lock:

        if username in web_clients:

            socketio.emit("login_error", {"message": "User already online"}, to=sid)

            return

    try:

        tcp_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        tcp_client.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

        tcp_client.settimeout(15)

        tcp_client.connect((TCP_HOST, TCP_PORT))

    except Exception as e:

        print("[TCP CONNECTION ERROR]", e)

        socketio.emit(
            "login_error", {"message": "Could not connect to chat server"}, to=sid
        )

        return

    success, reason = authenticate_web_user(tcp_client, "LOGIN", username, password)

    if not success:

        tcp_client.close()

        socketio.emit("login_error", {"message": reason}, to=sid)

        return

    tcp_client.settimeout(None)

    if not ensure_user_keys(username):

        tcp_client.close()

        socketio.emit(
            "login_error", {"message": "Could not prepare encryption keys"}, to=sid
        )

        return

    if not register_public_key(username, tcp_client):

        tcp_client.close()

        socketio.emit(
            "login_error", {"message": "Could not register public key"}, to=sid
        )

        return

    token = secrets.token_urlsafe(24)

    with clients_lock:

        web_clients[username] = tcp_client

        session_tokens[username] = token

        pending_events[username] = []

        history_requests[username] = []

        browser_ids.pop(username, None)

    print("[LOGIN SUCCESS]", username)

    threading.Thread(
        target=receive_from_tcp, args=(username, tcp_client), daemon=True
    ).start()

    # The browser now moves from the login page to /chat and attaches
    # with the token. If it never does, the session is closed.

    schedule_cleanup(username, LOGIN_ATTACH_SECONDS)

    socketio.emit("login_success", {"username": username, "token": token}, to=sid)

    broadcast_users()


# ============================================================
# REGISTER
# ============================================================


@socketio.on("register")
def register(data):

    sid = request.sid

    data = data or {}

    username = str(data.get("username", "")).strip()

    password = str(data.get("password", ""))

    if not username or not password:

        socketio.emit(
            "register_error", {"message": "Username and password required"}, to=sid
        )

        return

    try:

        tcp_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        tcp_client.settimeout(15)

        tcp_client.connect((TCP_HOST, TCP_PORT))

    except Exception as e:

        print("[REGISTER TCP ERROR]", e)

        socketio.emit(
            "register_error", {"message": "Could not connect to chat server"}, to=sid
        )

        return

    success, message = authenticate_web_user(tcp_client, "REGISTER", username, password)

    try:

        tcp_client.close()

    except Exception:

        pass

    if success:

        socketio.emit(
            "register_success",
            {"message": "Registration successful. Please login."},
            to=sid,
        )

    else:

        socketio.emit("register_error", {"message": message}, to=sid)


# ============================================================
# ATTACH (browser <-> existing TCP session, token protected)
# ============================================================


@socketio.on("attach")
def attach(data):

    sid = request.sid

    data = data or {}

    username = str(data.get("username", "")).strip()

    token = str(data.get("token", ""))

    with clients_lock:

        tcp_client = web_clients.get(username)

        expected = session_tokens.get(username)

        valid = (
            tcp_client is not None
            and expected is not None
            and hmac.compare_digest(expected.encode(), token.encode())
        )

        if valid:

            browser_ids[username] = sid

    if not valid:

        socketio.emit(
            "attach_error",
            {"message": "Session expired. Please log in again."},
            to=sid,
        )

        return

    cancel_cleanup(username)

    socketio.emit("attach_success", {"username": username}, to=sid)

    flush_pending(username)

    tcp_send(tcp_client, "/users")

    tcp_send(tcp_client, "/groups")

    tcp_send(tcp_client, "/allusers")


# ============================================================
# PRIVATE MESSAGE
# ============================================================


@socketio.on("chat_message")
def chat_message(data):

    data = data or {}

    receiver = clean_arg(data.get("receiver"))

    text = str(data.get("message", ""))

    if not receiver or not text.strip():

        return

    if len(text) > MAX_TEXT_LENGTH:

        emit_error(request.sid, "Message is too long")

        return

    username, tcp_client = get_session(request.sid)

    if not username or not tcp_client:

        emit_error(request.sid, "Session not found. Please log in again.")

        return

    payload = encrypt_for_conversation(username, receiver, text)

    if not payload:

        emit_error(
            request.sid,
            "Could not encrypt message. Recipient public key may be unavailable.",
        )

        return

    tcp_send(tcp_client, "/encrypted|" + receiver + "|" + payload)


# ============================================================
# USERS / GROUPS
# ============================================================


@socketio.on("get_users")
def get_users(data=None):

    send_command("/users", quiet=True)


@socketio.on("get_all_users")
def get_all_users(data=None):

    send_command("/allusers", quiet=True)


@socketio.on("get_groups")
def get_groups(data=None):

    send_command("/groups", quiet=True)


# ============================================================
# PRIVATE HISTORY
# ============================================================


@socketio.on("get_history")
@socketio.on("history")
def get_history(data=None):

    data = data or {}

    target = clean_arg(data.get("username"))

    if not target:

        return

    username, tcp_client = get_session(request.sid)

    if not username or not tcp_client:

        return

    with clients_lock:

        history_requests.setdefault(username, []).append(target)

    tcp_send(tcp_client, "/history " + target)


# ============================================================
# PUBLIC KEY
# ============================================================


@socketio.on("get_public_key")
def get_public_key(data=None):

    target = clean_arg((data or {}).get("username"))

    if target:

        send_command("/key " + target)


# ============================================================
# GROUPS
# ============================================================


@socketio.on("create_group")
def create_group(data=None):

    groupname = group_arg(data)

    if groupname:

        send_command("/create " + groupname)


@socketio.on("join_group")
def join_group(data=None):

    groupname = group_arg(data)

    if groupname:

        send_command("/join " + groupname)


@socketio.on("group_message")
def group_message(data=None):

    data = data or {}

    groupname = group_arg(data)

    text = str(data.get("message", ""))

    # A newline would end the TCP line and be read as a second command.

    text = text.replace("\r\n", " ").replace("\r", " ").replace("\n", " ").strip()

    if not groupname or not text:

        return

    if len(text) > MAX_TEXT_LENGTH:

        emit_error(request.sid, "Message is too long")

        return

    # Pipe protocol preserves spaces in the message.

    command = "/groupmsg|" + groupname + "|" + text

    username, tcp_client = get_session(request.sid)

    if not username or not tcp_client:

        emit_error(request.sid, "Session not found. Please log in again.")

        return

    if not tcp_send(tcp_client, command):

        emit_error(request.sid, "Could not send group message")


@socketio.on("get_group_history")
@socketio.on("group_history")
def get_group_history(data=None):

    groupname = group_arg(data)

    if groupname:

        send_command("/grouphistory " + groupname)


@socketio.on("get_members")
def get_members(data=None):

    groupname = group_arg(data)

    if groupname:

        send_command("/members " + groupname)


@socketio.on("add_member")
def add_member(data=None):

    data = data or {}

    groupname = group_arg(data)

    target_user = clean_arg(data.get("username"))

    if not groupname or not target_user:

        emit_error(request.sid, "Group name and username are required")

        return

    send_command("/addmember " + groupname + " " + target_user)


@socketio.on("remove_member")
def remove_member(data=None):

    data = data or {}

    groupname = group_arg(data)

    target_user = clean_arg(data.get("username"))

    if not groupname or not target_user:

        emit_error(request.sid, "Group name and username are required")

        return

    send_command("/removemember " + groupname + " " + target_user)


@socketio.on("leave_group")
def leave_group(data=None):

    groupname = group_arg(data)

    if groupname:

        send_command("/leave " + groupname)


# ============================================================
# LOGOUT
# ============================================================


@socketio.on("logout")
def logout(data=None):

    username = get_username_from_sid(request.sid)

    if username:

        end_session(username)


# ============================================================
# BROWSER DISCONNECT
# ============================================================


@socketio.on("disconnect")
def disconnect(*args):

    sid = request.sid

    username = None

    with clients_lock:

        for user, browser_sid in browser_ids.items():

            if browser_sid == sid:

                username = user

                break

        if username:

            browser_ids.pop(username, None)

    # Keep the TCP session briefly so a refresh can re-attach.

    if username:

        schedule_cleanup(username, GRACE_SECONDS)


# ============================================================
# MAIN
# ============================================================


if __name__ == "__main__":

    print("====================================")

    print("       SECURE CHAT WEB SERVER")

    print("====================================")

    print(f"Web server: http://{WEB_HOST}:{WEB_PORT}")

    print(f"TCP server: {TCP_HOST}:{TCP_PORT}")

    print("Encryption: ENABLED")

    print("Socket.IO: ENABLED")

    print("Socket.IO transport: WEBSOCKET")

    print("====================================")

    socketio.run(
        app, host=WEB_HOST, port=WEB_PORT, debug=False, allow_unsafe_werkzeug=True
    )
