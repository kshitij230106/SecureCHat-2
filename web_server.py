import socket

import threading

import base64


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


# ============================================================

# FLASK

# ============================================================


app = Flask(
    __name__, static_folder="web", static_url_path="/static", template_folder="web"
)


# FIXED SOCKET.IO CONFIGURATION

#

# The previous configuration allowed Socket.IO to negotiate

# transports automatically. In your setup this was causing:

#

# POST /socket.io/?EIO=4&transport=polling... 400

#

# Threading + polling keeps the browser connection stable.


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


web_clients = {}

browser_ids = {}


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


# IMPORTANT:

#

# DO NOT ADD:

#

# @app.route("/<path:path>")

#

# Flask-SocketIO must handle /socket.io/ itself.


# ============================================================

# TCP SEND

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


# ============================================================

# TCP RECEIVE

# ============================================================


def tcp_receive_line(client, buffer):

    try:

        while "\n" not in buffer:

            data = client.recv(8192)

            if not data:

                return None, buffer

            buffer += data.decode("utf-8", errors="replace")

        line, buffer = buffer.split("\n", 1)

        return line.strip(), buffer

    except Exception as e:

        print("[TCP RECEIVE ERROR]", e)

        return None, buffer


# ============================================================

# SOCKET.IO HELPERS

# ============================================================


def emit_to_user(username, event, data=None):

    with clients_lock:

        sid = browser_ids.get(username)

    if not sid:

        return

    try:

        socketio.emit(event, data, to=sid)

    except Exception as e:

        print("[SOCKET EMIT ERROR]", e)


def get_username_from_sid(sid):

    with clients_lock:

        for username, browser_sid in browser_ids.items():

            if browser_sid == sid:

                return username

    return None


# ============================================================

# AUTHENTICATION

# ============================================================


def authenticate_web_user(tcp_client, choice, username, password):

    try:

        response, buffer = tcp_receive_line(tcp_client, "")

        if response != "AUTH_REQUEST":

            return False

        tcp_send(tcp_client, choice)

        response, buffer = tcp_receive_line(tcp_client, buffer)

        if response != "USERNAME":

            return False

        tcp_send(tcp_client, username)

        response, buffer = tcp_receive_line(tcp_client, buffer)

        if response != "PASSWORD":

            return False

        tcp_send(tcp_client, password)

        response, buffer = tcp_receive_line(tcp_client, buffer)

        print("[AUTH]", response)

        if not response:

            return False

        if response.startswith("AUTH_FAILED|"):

            return False

        if not response.startswith("AUTH_SUCCESS|"):

            return False

        response, buffer = tcp_receive_line(tcp_client, buffer)

        if response != "READY_REQUEST":

            return False

        tcp_send(tcp_client, "READY")

        response, buffer = tcp_receive_line(tcp_client, buffer)

        if response != "READY_OK":

            return False

        return True

    except Exception as e:

        print("[AUTH ERROR]", e)

        return False


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

        if not tcp_send(tcp_client, command):

            return False

        return True

    except Exception as e:

        print("[PUBLIC KEY ERROR]", e)

        return False


# ============================================================

# ENCRYPT MESSAGE

# ============================================================


def encrypt_for_user(sender, receiver, text):

    try:

        public_key_text = database.get_public_key(receiver)

        if not public_key_text:

            print("[ENCRYPT ERROR] Public key not found:", receiver)

            return None

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

    except Exception as e:

        print("[ENCRYPT ERROR]", sender, "->", receiver, e)

        return None


# ============================================================

# DECRYPT MESSAGE

# ============================================================


def decrypt_message_for_user(username, encrypted_data):

    try:

        encrypted_key, encrypted_message = encrypted_data.split("||", 1)

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


# ============================================================

# TCP RECEIVER

# ============================================================


def receive_from_tcp(username, tcp_client):

    buffer = ""

    print("[TCP RECEIVER STARTED]", username)

    try:

        while True:

            message, buffer = tcp_receive_line(tcp_client, buffer)

            if message is None:

                break

            if not message:

                continue

            print("[TCP -> WEB]", username, ":", message)

            # =================================================

            # USERS

            # =================================================

            if message.startswith("USERS|"):

                users_text = message.split("|", 1)[1]

                users = users_text.split("|") if users_text else []

                emit_to_user(username, "users", {"users": users})

            # =================================================

            # GROUPS

            # =================================================

            elif message.startswith("GROUPS|"):

                groups_text = message.split("|", 1)[1]

                groups = groups_text.split("|") if groups_text else []

                emit_to_user(username, "groups", {"groups": groups})

            # =================================================

            # PUBLIC KEY

            # =================================================

            elif message.startswith("PUBLIC_KEY|"):

                parts = message.split("|", 2)

                if len(parts) == 3:

                    emit_to_user(
                        username, "public_key", {"username": parts[1], "key": parts[2]}
                    )

            # =================================================

            # KEY SUCCESS

            # =================================================

            elif message.startswith("KEY_SUCCESS|"):

                emit_to_user(
                    username, "key_success", {"message": message.split("|", 1)[1]}
                )

            # =================================================

            # PRIVATE MESSAGE

            # =================================================

            elif message.startswith("MESSAGE|"):

                parts = message.split("|", 3)

                if len(parts) != 4:

                    continue

                sender = parts[1]

                message_id = parts[2]

                encrypted_data = parts[3]

                decrypted_text = decrypt_message_for_user(username, encrypted_data)

                if decrypted_text is None:

                    emit_to_user(
                        username, "error", {"message": "Could not decrypt message"}
                    )

                    continue

                emit_to_user(
                    username,
                    "message",
                    {
                        "sender": sender,
                        "message_id": message_id,
                        "message": decrypted_text,
                    },
                )

                if message_id != "0":

                    tcp_send(tcp_client, "/ack|" + message_id)

            # =================================================

            # PRIVATE HISTORY

            # =================================================

            elif message.startswith("HISTORY|"):

                history_text = message.split("|", 1)[1]

                history = []

                if history_text:

                    records = history_text.split(";;")

                    for record in records:

                        try:

                            parts = record.split(" | ", 2)

                            if len(parts) != 3:

                                continue

                            timestamp = parts[0]

                            users_part = parts[1]

                            encrypted_data = parts[2]

                            user_parts = users_part.split(" -> ")

                            if len(user_parts) != 2:

                                continue

                            sender = user_parts[0]

                            receiver = user_parts[1]

                            decrypted_text = decrypt_message_for_user(
                                username, encrypted_data
                            )

                            if decrypted_text is None:

                                continue

                            history.append(
                                {
                                    "sender": sender,
                                    "receiver": receiver,
                                    "message": decrypted_text,
                                    "timestamp": timestamp,
                                }
                            )

                        except Exception as e:

                            print("[HISTORY ERROR]", e)

                emit_to_user(username, "history", {"history": history})

            # =================================================

            # GROUP MESSAGE

            # =================================================

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

                emit_to_user(
                    username,
                    "group_message",
                    {"group": group_name, "sender": sender, "message": text},
                )

            # =================================================

            # GROUP HISTORY

            # =================================================

            elif message.startswith("GROUP_HISTORY|"):

                parts = message.split("|", 2)

                group_name = parts[1] if len(parts) >= 2 else ""

                history = []

                if len(parts) == 3 and parts[2]:

                    records = parts[2].split(";;")

                    for record in records:

                        try:

                            fields = record.split(" | ", 2)

                            if len(fields) != 3:

                                continue

                            history.append(
                                {
                                    "timestamp": fields[0],
                                    "sender": fields[1],
                                    "message": fields[2],
                                }
                            )

                        except Exception as e:

                            print("[GROUP HISTORY ERROR]", e)

                emit_to_user(
                    username, "group_history", {"group": group_name, "history": history}
                )

            # =================================================

            # MEMBERS

            # =================================================

            elif message.startswith("MEMBERS|"):

                parts = message.split("|")

                if len(parts) >= 2:

                    group_name = parts[1]

                    members = parts[2:]

                    emit_to_user(
                        username, "members", {"group": group_name, "members": members}
                    )

            # =================================================

            # GROUP CREATED

            # =================================================

            elif message.startswith("GROUP_CREATED|"):

                group_name = message.split("|", 1)[1]

                emit_to_user(username, "group_created", {"group": group_name})

            # =================================================

            # JOINED

            # =================================================

            elif message.startswith("JOINED|"):

                group_name = message.split("|", 1)[1]

                emit_to_user(username, "joined", {"group": group_name})

            # =================================================

            # LEFT

            # =================================================

            elif message.startswith("LEFT|"):

                group_name = message.split("|", 1)[1]

                emit_to_user(username, "left", {"group": group_name})

            # =================================================

            # GROUP UPDATED

            # =================================================

            elif message.startswith("GROUP_UPDATED|"):

                group_name = message.split("|", 1)[1]

                emit_to_user(username, "group_updated", {"group": group_name})

            # =================================================

            # MEMBER ADDED

            # =================================================

            elif message.startswith("MEMBER_ADDED|"):

                parts = message.split("|", 2)

                if len(parts) == 3:

                    emit_to_user(
                        username,
                        "member_added",
                        {"group": parts[1], "username": parts[2]},
                    )

            # =================================================

            # MEMBER REMOVED

            # =================================================

            elif message.startswith("MEMBER_REMOVED|"):

                parts = message.split("|", 2)

                if len(parts) == 3:

                    emit_to_user(
                        username,
                        "member_removed",
                        {"group": parts[1], "username": parts[2]},
                    )

            # =================================================

            # SENT

            # =================================================

            elif message == "SENT":

                emit_to_user(username, "sent", {"success": True})

            # =================================================

            # SERVER MESSAGE

            # =================================================

            elif message.startswith("SERVER|"):

                emit_to_user(username, "server", {"message": message.split("|", 1)[1]})

            # =================================================

            # ERROR

            # =================================================

            elif message.startswith("ERROR|"):

                emit_to_user(username, "error", {"message": message.split("|", 1)[1]})

            # =================================================

            # SHUTDOWN

            # =================================================

            elif message == "SERVER_SHUTDOWN":

                emit_to_user(username, "server_shutdown", {})

                break

    except Exception as e:

        print("[TCP RECEIVER ERROR]", username, e)

    finally:

        print("[TCP RECEIVER CLOSED]", username)

        with clients_lock:

            if web_clients.get(username) is tcp_client:

                web_clients.pop(username, None)

            browser_ids.pop(username, None)

        with tcp_send_locks_lock:

            tcp_send_locks.pop(id(tcp_client), None)

        try:

            tcp_client.close()

        except Exception:

            pass

        broadcast_users()


# ============================================================

# LOGIN

# ============================================================


@socketio.on("login")
def login(data):

    sid = request.sid

    username = data.get("username", "").strip()

    password = data.get("password", "")

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

        tcp_client.connect((TCP_HOST, TCP_PORT))

    except Exception as e:

        print("[TCP CONNECTION ERROR]", e)

        socketio.emit(
            "login_error", {"message": "Could not connect to chat server"}, to=sid
        )

        return

    success = authenticate_web_user(tcp_client, "LOGIN", username, password)

    if not success:

        tcp_client.close()

        socketio.emit(
            "login_error", {"message": "Invalid username or password"}, to=sid
        )

        return

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

    with clients_lock:

        web_clients[username] = tcp_client

        browser_ids[username] = sid

    print("[LOGIN SUCCESS]", username)

    socketio.emit("login_success", {"username": username}, to=sid)

    threading.Thread(
        target=receive_from_tcp, args=(username, tcp_client), daemon=True
    ).start()

    broadcast_users()


# ============================================================

# REGISTER

# ============================================================


@socketio.on("register")
def register(data):

    sid = request.sid

    username = data.get("username", "").strip()

    password = data.get("password", "")

    if not username or not password:

        socketio.emit(
            "register_error", {"message": "Username and password required"}, to=sid
        )

        return

    try:

        tcp_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        tcp_client.connect((TCP_HOST, TCP_PORT))

    except Exception as e:

        print("[REGISTER TCP ERROR]", e)

        socketio.emit(
            "register_error", {"message": "Could not connect to chat server"}, to=sid
        )

        return

    success = authenticate_web_user(tcp_client, "REGISTER", username, password)

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

        socketio.emit(
            "register_error",
            {"message": "Registration failed. Username may already exist."},
            to=sid,
        )


# ============================================================

# ATTACH

# ============================================================


@socketio.on("attach")
def attach(data):

    sid = request.sid

    username = data.get("username", "").strip()

    if not username:

        return

    with clients_lock:

        tcp_client = web_clients.get(username)

        if tcp_client is None:

            socketio.emit(
                "attach_error", {"message": "TCP connection not found"}, to=sid
            )

            return

        browser_ids[username] = sid

    socketio.emit("attach_success", {"username": username}, to=sid)

    tcp_send(tcp_client, "/users")

    tcp_send(tcp_client, "/groups")


# ============================================================

# PRIVATE MESSAGE

# ============================================================


@socketio.on("chat_message")
def chat_message(data):

    username = get_username_from_sid(request.sid)

    if not username:

        return

    receiver = data.get("receiver", "").strip()

    text = data.get("message", "")

    if not receiver or not text:

        return

    with clients_lock:

        tcp_client = web_clients.get(username)

    if not tcp_client:

        socketio.emit(
            "error", {"message": "TCP connection unavailable"}, to=request.sid
        )

        return

    encrypted_data = encrypt_for_user(username, receiver, text)

    if not encrypted_data:

        socketio.emit(
            "error",
            {
                "message": "Could not encrypt message. Recipient public key may be unavailable."
            },
            to=request.sid,
        )

        return

    command = "/encrypted|" + receiver + "|" + encrypted_data

    tcp_send(tcp_client, command)


# ============================================================

# GET USERS

# ============================================================


@socketio.on("get_users")
def get_users():

    username = get_username_from_sid(request.sid)

    if not username:

        return

    with clients_lock:

        tcp_client = web_clients.get(username)

    if tcp_client:

        tcp_send(tcp_client, "/users")


# ============================================================

# GET GROUPS

# ============================================================


@socketio.on("get_groups")
def get_groups():

    username = get_username_from_sid(request.sid)

    if not username:

        return

    with clients_lock:

        tcp_client = web_clients.get(username)

    if tcp_client:

        tcp_send(tcp_client, "/groups")


# ============================================================

# PRIVATE HISTORY

# ============================================================


@socketio.on("get_history")
def get_history(data):

    username = get_username_from_sid(request.sid)

    if not username:

        return

    target = data.get("username", "").strip()

    if not target:

        return

    with clients_lock:

        tcp_client = web_clients.get(username)

    if tcp_client:

        tcp_send(tcp_client, "/history " + target)


# ============================================================

# PUBLIC KEY

# ============================================================


@socketio.on("get_public_key")
def get_public_key(data):

    username = get_username_from_sid(request.sid)

    if not username:

        return

    target = data.get("username", "").strip()

    if not target:

        return

    with clients_lock:

        tcp_client = web_clients.get(username)

    if tcp_client:

        tcp_send(tcp_client, "/key " + target)


# ============================================================

# CREATE GROUP

# ============================================================


@socketio.on("create_group")
def create_group(data):

    username = get_username_from_sid(request.sid)

    if not username:

        return

    groupname = data.get("groupname", "").strip()

    if not groupname:

        return

    with clients_lock:

        tcp_client = web_clients.get(username)

    if tcp_client:

        tcp_send(tcp_client, "/create " + groupname)


# ============================================================

# JOIN GROUP

# ============================================================


@socketio.on("join_group")
def join_group(data):

    username = get_username_from_sid(request.sid)

    if not username:

        return

    groupname = data.get("groupname", "").strip()

    if not groupname:

        return

    with clients_lock:

        tcp_client = web_clients.get(username)

    if tcp_client:

        tcp_send(tcp_client, "/join " + groupname)


# ============================================================

# GROUP MESSAGE

# ============================================================


@socketio.on("group_message")
def group_message(data):

    username = get_username_from_sid(request.sid)

    if not username:

        return

    groupname = data.get("groupname", "").strip()

    text = data.get("message", "")

    if not groupname or not text:

        return

    with clients_lock:

        tcp_client = web_clients.get(username)

    if not tcp_client:

        socketio.emit(
            "error", {"message": "TCP connection unavailable"}, to=request.sid
        )

        return

    # Pipe protocol preserves spaces in message.

    command = "/groupmsg|" + groupname + "|" + text

    if not tcp_send(tcp_client, command):

        socketio.emit(
            "error", {"message": "Could not send group message"}, to=request.sid
        )


# ============================================================

# GROUP HISTORY

# ============================================================


@socketio.on("get_group_history")
def get_group_history(data):

    username = get_username_from_sid(request.sid)

    if not username:

        return

    groupname = data.get("groupname", "").strip()

    if not groupname:

        return

    with clients_lock:

        tcp_client = web_clients.get(username)

    if tcp_client:

        tcp_send(tcp_client, "/grouphistory " + groupname)


# ============================================================

# GET MEMBERS

# ============================================================


@socketio.on("get_members")
def get_members(data):

    username = get_username_from_sid(request.sid)

    if not username:

        return

    groupname = data.get("groupname", "").strip()

    if not groupname:

        return

    with clients_lock:

        tcp_client = web_clients.get(username)

    if tcp_client:

        tcp_send(tcp_client, "/members " + groupname)


# ============================================================

# ADD MEMBER

# ============================================================


@socketio.on("add_member")
def add_member(data):

    username = get_username_from_sid(request.sid)

    if not username:

        return

    groupname = data.get("groupname", "").strip()

    target_user = data.get("username", "").strip()

    if not groupname or not target_user:

        socketio.emit(
            "error", {"message": "Group name and username are required"}, to=request.sid
        )

        return

    with clients_lock:

        tcp_client = web_clients.get(username)

    if not tcp_client:

        socketio.emit(
            "error", {"message": "TCP connection unavailable"}, to=request.sid
        )

        return

    command = "/addmember " + groupname + " " + target_user

    tcp_send(tcp_client, command)


# ============================================================

# REMOVE MEMBER

# ============================================================


@socketio.on("remove_member")
def remove_member(data):

    username = get_username_from_sid(request.sid)

    if not username:

        return

    groupname = data.get("groupname", "").strip()

    target_user = data.get("username", "").strip()

    if not groupname or not target_user:

        return

    with clients_lock:

        tcp_client = web_clients.get(username)

    if not tcp_client:

        return

    command = "/removemember " + groupname + " " + target_user

    tcp_send(tcp_client, command)


# ============================================================

# LOGOUT

# ============================================================


@socketio.on("logout")
def logout():

    username = get_username_from_sid(request.sid)

    if not username:

        return

    with clients_lock:

        tcp_client = web_clients.get(username)

        web_clients.pop(username, None)

        browser_ids.pop(username, None)

    if tcp_client:

        try:

            tcp_send(tcp_client, "/exit")

            tcp_client.close()

        except Exception:

            pass

    broadcast_users()


# ============================================================

# BROWSER DISCONNECT

# ============================================================


@socketio.on("disconnect")
def disconnect():

    sid = request.sid

    username = None

    with clients_lock:

        for user, browser_sid in browser_ids.items():

            if browser_sid == sid:

                username = user

                break

        if username:

            browser_ids.pop(username, None)


# ============================================================

# BROADCAST USERS

# ============================================================


def broadcast_users():

    with clients_lock:

        users = list(web_clients.keys())

    for username in users:

        emit_to_user(username, "users", {"users": users})


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
