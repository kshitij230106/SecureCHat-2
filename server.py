import socket


import threading


import database

HOST = "0.0.0.0"


PORT = 5000


clients = {}


public_keys = {}


clients_lock = threading.Lock()


keys_lock = threading.Lock()


send_locks = {}


send_locks_lock = threading.Lock()


server = None


running = True


database.create_tables()


# =========================================================


# SEND


# =========================================================


def send_message(client, message):

    if client is None:

        return False

    socket_id = id(client)

    with send_locks_lock:

        lock = send_locks.setdefault(socket_id, threading.Lock())

    try:

        with lock:

            client.sendall((message + "\n").encode("utf-8"))

        return True

    except Exception as e:

        print("[SEND ERROR]", e)

        return False


# =========================================================


# RECEIVE LINE


# =========================================================


def receive_line(client, buffer):

    try:

        while "\n" not in buffer:

            data = client.recv(4096)

            if not data:

                return None, buffer

            buffer += data.decode("utf-8")

        line, buffer = buffer.split("\n", 1)

        return line.strip(), buffer

    except Exception as e:

        print("[RECEIVE ERROR]", e)

        return None, buffer


# =========================================================


# BROADCAST


# =========================================================


def broadcast(message, exclude=None):

    with clients_lock:

        current_clients = list(clients.items())

    for username, client in current_clients:

        if username == exclude:

            continue

        send_message(client, message)


# =========================================================


# USER LIST


# =========================================================


def send_user_list():

    with clients_lock:

        users = list(clients.keys())

    message = "USERS|" + "|".join(users)

    broadcast(message)


# =========================================================


# GROUP NAMES


# =========================================================


def get_group_names():

    try:

        group_list = database.get_groups()

    except Exception as e:

        print("[GROUP ERROR]", e)

        return []

    names = []

    for group in group_list:

        if isinstance(group, str):

            names.append(group)

        elif isinstance(group, (tuple, list)):

            if len(group) >= 2:

                names.append(str(group[1]))

    return names


# =========================================================


# GROUP LIST


# =========================================================


def send_group_list(client):

    names = get_group_names()

    if names:

        message = "GROUPS|" + "|".join(names)

    else:

        message = "GROUPS|"

    send_message(client, message)


# =========================================================


# AUTHENTICATION


# =========================================================


def authenticate(client):

    buffer = ""

    try:

        send_message(client, "AUTH_REQUEST")

        choice, buffer = receive_line(client, buffer)

        if choice is None:

            return None, buffer

        choice = choice.strip().upper()

        if choice not in ["LOGIN", "REGISTER"]:

            send_message(client, "AUTH_FAILED|Invalid choice")

            return None, buffer

        # -------------------------------------------------

        # USERNAME

        # -------------------------------------------------

        send_message(client, "USERNAME")

        username, buffer = receive_line(client, buffer)

        if username is None:

            return None, buffer

        username = username.strip()

        if not username:

            send_message(client, "AUTH_FAILED|Invalid username")

            return None, buffer

        # -------------------------------------------------

        # PASSWORD

        # -------------------------------------------------

        send_message(client, "PASSWORD")

        password, buffer = receive_line(client, buffer)

        if password is None:

            return None, buffer

        password = password.strip()

        if not password:

            send_message(client, "AUTH_FAILED|Invalid password")

            return None, buffer

        # =================================================

        # REGISTER

        # =================================================

        if choice == "REGISTER":

            if database.create_user(username, password):

                send_message(client, "AUTH_SUCCESS|Registration successful")

                print(f"[REGISTERED] {username}")

            else:

                send_message(client, "AUTH_FAILED|Username already exists")

            return None, buffer

        # =================================================

        # LOGIN

        # =================================================

        if not database.verify_login(username, password):

            send_message(client, "AUTH_FAILED|Invalid username or password")

            print(f"[LOGIN FAILED] {username}")

            return None, buffer

        # -------------------------------------------------

        # DUPLICATE LOGIN

        # -------------------------------------------------

        with clients_lock:

            if username in clients:

                send_message(client, "AUTH_FAILED|User already online")

                print(f"[LOGIN FAILED] {username} already online")

                return None, buffer

            clients[username] = client

        # -------------------------------------------------

        # SUCCESS

        # -------------------------------------------------

        send_message(client, f"AUTH_SUCCESS|Welcome {username}")

        print(f"[LOGIN SUCCESS] {username}")

        # -------------------------------------------------

        # READY HANDSHAKE

        # -------------------------------------------------

        send_message(client, "READY_REQUEST")

        ready, buffer = receive_line(client, buffer)

        if ready is None:

            with clients_lock:

                clients.pop(username, None)

            return None, buffer

        if ready != "READY":

            with clients_lock:

                clients.pop(username, None)

            send_message(client, "AUTH_FAILED|Handshake failed")

            return None, buffer

        send_message(client, "READY_OK")

        return username, buffer

    except Exception as e:

        print("[AUTH ERROR]", e)

        return None, buffer


# =========================================================


# PENDING MESSAGES


# =========================================================


def send_pending_messages(username, client):

    try:

        messages = database.get_pending_messages(username)

        for message_id, sender, encrypted_message in messages:

            send_message(client, f"MESSAGE|{sender}|{message_id}|{encrypted_message}")

            print(f"[OFFLINE MESSAGE] " f"{sender} -> {username}")

            database.update_message_status(message_id, "delivered")

    except Exception as e:

        print("[OFFLINE MESSAGE ERROR]", e)


# =========================================================


# PRIVATE ENCRYPTED MESSAGE


# =========================================================


def handle_private_message(username, command):

    try:

        parts = command.split("|", 2)

        if len(parts) != 3:

            return "ERROR|Invalid encrypted message format"

        receiver = parts[1].strip()

        encrypted_message = parts[2]

        # -------------------------------------------------

        # RECEIVER CHECK

        # -------------------------------------------------

        if not database.get_user(receiver):

            return "ERROR|User does not exist"

        # -------------------------------------------------

        # SELF MESSAGE

        # -------------------------------------------------

        if receiver == username:

            return "ERROR|Cannot message yourself"

        # -------------------------------------------------

        # SAVE MESSAGE

        # -------------------------------------------------

        message_id = database.save_message(
            username, receiver, encrypted_message, "sent"
        )

        # -------------------------------------------------

        # FIND RECEIVER

        # -------------------------------------------------

        with clients_lock:

            receiver_client = clients.get(receiver)

        # -------------------------------------------------

        # ONLINE

        # -------------------------------------------------

        if receiver_client:

            success = send_message(
                receiver_client,
                f"MESSAGE|{username}|" f"{message_id}|" f"{encrypted_message}",
            )

            if success:

                database.update_message_status(message_id, "delivered")

                print(f"[ENCRYPTED] " f"{username} -> {receiver}")

            else:

                print(f"[DELIVERY FAILED] " f"{username} -> {receiver}")

        # -------------------------------------------------

        # OFFLINE

        # -------------------------------------------------

        else:

            print(f"[OFFLINE ENCRYPTED] " f"{username} -> {receiver}")

        return "SENT"

    except Exception as e:

        print("[PRIVATE MESSAGE ERROR]", e)

        return "ERROR|Could not send encrypted message"


# =========================================================


# GROUP MESSAGE


# =========================================================


def handle_group_message(username, command):

    try:

        parts = command.split("|", 2)

        if len(parts) != 3:

            return "ERROR|Invalid group message"

        group_name = parts[1].strip()

        message = parts[2]

        # -------------------------------------------------

        # GROUP

        # -------------------------------------------------

        group = database.get_group(group_name)

        if not group:

            return "ERROR|Group does not exist"

        # -------------------------------------------------

        # MEMBERS

        # -------------------------------------------------

        members = database.get_group_members(group_name)

        if username not in members:

            return "ERROR|You are not a member of this group"

        # -------------------------------------------------

        # SAVE

        # -------------------------------------------------

        database.save_group_message(group_name, username, message)

        # -------------------------------------------------

        # ONLINE CLIENTS

        # -------------------------------------------------

        with clients_lock:

            current_clients = dict(clients)

        # -------------------------------------------------

        # SEND

        # -------------------------------------------------

        for member in members:

            if member == username:

                continue

            if member in current_clients:

                send_message(
                    current_clients[member],
                    f"GROUP|{group_name}|" f"{username}|{message}",
                )

        print(f"[GROUP] " f"{username} -> " f"{group_name}: " f"{message}")

        return "SENT"

    except Exception as e:

        print("[GROUP MESSAGE ERROR]", e)

        return "ERROR|Could not send group message"


# =========================================================


# CREATE GROUP


# =========================================================


def handle_create_group(username, group_name):

    group_name = group_name.strip()

    if not group_name:

        return "ERROR|Group name required"

    try:

        success = database.create_group(group_name, username)

        if not success:

            return "ERROR|Group already exists " "or could not be created"

        print(f"[GROUP CREATED] " f"{username} -> {group_name}")

        return f"GROUP_CREATED|{group_name}"

    except Exception as e:

        print("[CREATE GROUP ERROR]", e)

        return "ERROR|Could not create group"


# =========================================================


# JOIN GROUP


# =========================================================


def handle_join_group(username, group_name):

    group_name = group_name.strip()

    if not group_name:

        return "ERROR|Group name required"

    try:

        group = database.get_group(group_name)

        if not group:

            return "ERROR|Group does not exist"

        members = database.get_group_members(group_name)

        if username in members:

            return f"JOINED|{group_name}"

        success = database.add_member(group_name, username)

        if not success:

            return "ERROR|Could not join group"

        print(f"[GROUP JOIN] " f"{username} -> {group_name}")

        return f"JOINED|{group_name}"

    except Exception as e:

        print("[JOIN GROUP ERROR]", e)

        return "ERROR|Could not join group"


# =========================================================


# GROUP MEMBERS


# =========================================================


def handle_group_members(username, group_name):

    try:

        group_name = group_name.strip()

        group = database.get_group(group_name)

        if not group:

            return "ERROR|Group does not exist"

        members = database.get_group_members(group_name)

        if username not in members:

            return "ERROR|You are not a member"

        member_text = "|".join(members)

        return f"MEMBERS|{group_name}|" f"{member_text}"

    except Exception as e:

        print("[MEMBERS ERROR]", e)

        return "ERROR|Could not get group members"


# =========================================================


# ADD MEMBER


# =========================================================


def handle_add_member(username, group_name, target_user):

    try:

        group_name = group_name.strip()

        target_user = target_user.strip()

        group = database.get_group(group_name)

        if not group:

            return "ERROR|Group does not exist"

        # -------------------------------------------------

        # OWNER

        # -------------------------------------------------

        owner = None

        if isinstance(group, (tuple, list)):

            if len(group) >= 3:

                owner = str(group[2])

        if owner != username:

            return "ERROR|Only the group owner " "can add members"

        # -------------------------------------------------

        # USER

        # -------------------------------------------------

        if not database.get_user(target_user):

            return "ERROR|User does not exist"

        # -------------------------------------------------

        # ALREADY MEMBER

        # -------------------------------------------------

        members = database.get_group_members(group_name)

        if target_user in members:

            return "ERROR|User already in group"

        success = database.add_member(group_name, target_user)

        if not success:

            return "ERROR|Could not add member"

        print(f"[GROUP ADD] " f"{username} added " f"{target_user} to " f"{group_name}")

        return f"MEMBER_ADDED|" f"{group_name}|" f"{target_user}"

    except Exception as e:

        print("[ADD MEMBER ERROR]", e)

        return "ERROR|Could not add member"


# =========================================================


# REMOVE MEMBER


# =========================================================


def handle_remove_member(username, group_name, target_user):

    try:

        group_name = group_name.strip()

        target_user = target_user.strip()

        group = database.get_group(group_name)

        if not group:

            return "ERROR|Group does not exist"

        # -------------------------------------------------

        # OWNER

        # -------------------------------------------------

        owner = None

        if isinstance(group, (tuple, list)):

            if len(group) >= 3:

                owner = str(group[2])

        if owner != username:

            return "ERROR|Only the group owner " "can remove members"

        # -------------------------------------------------

        # CANNOT REMOVE OWNER

        # -------------------------------------------------

        if target_user == owner:

            return "ERROR|Owner cannot be removed"

        members = database.get_group_members(group_name)

        if target_user not in members:

            return "ERROR|User is not a member"

        success = database.remove_member(group_name, target_user)

        if not success:

            return "ERROR|Could not remove member"

        print(
            f"[GROUP REMOVE] "
            f"{username} removed "
            f"{target_user} from "
            f"{group_name}"
        )

        return f"MEMBER_REMOVED|" f"{group_name}|" f"{target_user}"

    except Exception as e:

        print("[REMOVE MEMBER ERROR]", e)

        return "ERROR|Could not remove member"


# =========================================================


# LEAVE GROUP


# =========================================================


def handle_leave_group(username, group_name):

    try:

        group_name = group_name.strip()

        group = database.get_group(group_name)

        if not group:

            return "ERROR|Group does not exist"

        # -------------------------------------------------

        # OWNER

        # -------------------------------------------------

        owner = None

        if isinstance(group, (tuple, list)):

            if len(group) >= 3:

                owner = str(group[2])

        if owner == username:

            return (
                "ERROR|Group owner cannot leave. "
                "Delete the group or transfer ownership."
            )

        members = database.get_group_members(group_name)

        if username not in members:

            return "ERROR|You are not a member"

        success = database.leave_group(group_name, username)

        if not success:

            return "ERROR|Could not leave group"

        print(f"[GROUP LEAVE] " f"{username} -> {group_name}")

        return f"LEFT|{group_name}"

    except Exception as e:

        print("[LEAVE GROUP ERROR]", e)

        return "ERROR|Could not leave group"


# =========================================================


# GROUP HISTORY


# =========================================================


def handle_group_history(username, group_name):

    try:

        group_name = group_name.strip()

        group = database.get_group(group_name)

        if not group:

            return "ERROR|Group does not exist"

        members = database.get_group_members(group_name)

        if username not in members:

            return "ERROR|You are not a member"

        messages = database.get_group_messages(group_name)

        records = []

        for record in messages:

            try:

                sender = record[0]

                message = record[1]

                timestamp = record[2]

                records.append(f"{timestamp} | " f"{sender} | " f"{message}")

            except Exception:

                continue

        history = ";;".join(records)

        return f"GROUP_HISTORY|" f"{group_name}|" f"{history}"

    except Exception as e:

        print("[GROUP HISTORY ERROR]", e)

        return "ERROR|Could not get group history"


# =========================================================


# PUBLIC KEY


# =========================================================


def handle_public_key(username, command):

    try:

        parts = command.split("|", 2)

        if len(parts) != 3:

            return "ERROR|Invalid public key format"

        key_username = parts[1].strip()

        public_key = parts[2]

        if key_username != username:

            return "ERROR|Username mismatch"

        database.update_public_key(username, public_key)

        with keys_lock:

            public_keys[username] = public_key

        print(f"[KEY REGISTERED] " f"{username}")

        return f"KEY_SUCCESS|" f"Public key registered"

    except Exception as e:

        print("[PUBLIC KEY ERROR]", e)

        return "ERROR|Could not register public key"


# =========================================================


# PUBLIC KEY REQUEST


# =========================================================


def handle_key_request(username, target):

    try:

        target = target.strip()

        public_key = database.get_public_key(target)

        if not public_key:

            return "ERROR|Public key not found"

        return f"PUBLIC_KEY|" f"{target}|" f"{public_key}"

    except Exception as e:

        print("[KEY REQUEST ERROR]", e)

        return "ERROR|Could not get public key"


# =========================================================


# CLIENT HANDLER


# =========================================================


def handle_client(client, address):

    username = None

    buffer = ""

    try:

        print(f"[NEW CONNECTION] {address}")

        username, buffer = authenticate(client)

        if not username:

            try:

                client.close()

            except Exception:

                pass

            return

        send_user_list()

        send_group_list(client)

        send_pending_messages(username, client)

        # =================================================

        # MAIN LOOP

        # =================================================

        while True:

            command, buffer = receive_line(client, buffer)

            if command is None:

                break

            if not command:

                continue

            print(f"[COMMAND] " f"{username}: " f"{command}")

            # =================================================

            # USERS

            # =================================================

            if command == "/users":

                send_user_list()

            # =================================================

            # GROUPS

            # =================================================

            elif command == "/groups":

                send_group_list(client)

            # =================================================

            # CREATE GROUP

            # =================================================

            elif command.startswith("/create "):

                group_name = command[len("/create ") :]

                result = handle_create_group(username, group_name)

                send_message(client, result)

                if result.startswith("GROUP_CREATED|"):

                    send_group_list(client)

            # =================================================

            # JOIN GROUP

            # =================================================

            elif command.startswith("/join "):

                group_name = command[len("/join ") :]

                result = handle_join_group(username, group_name)

                send_message(client, result)

                if result.startswith("JOINED|"):

                    send_group_list(client)

            # =================================================

            # GROUP MEMBERS

            # =================================================

            elif command.startswith("/members "):

                group_name = command[len("/members ") :]

                result = handle_group_members(username, group_name)

                send_message(client, result)

            # =================================================

            # ADD MEMBER

            # =================================================

            elif command.startswith("/addmember "):

                content = command[len("/addmember ") :]

                parts = content.split(" ", 1)

                if len(parts) != 2:

                    send_message(client, "ERROR|Usage: " "/addmember group user")

                    continue

                group_name = parts[0]

                target_user = parts[1]

                result = handle_add_member(username, group_name, target_user)

                send_message(client, result)

                if result.startswith("MEMBER_ADDED|"):

                    group_members = database.get_group_members(group_name)

                    with clients_lock:

                        current_clients = dict(clients)

                    for member in group_members:

                        if member in current_clients:

                            send_message(
                                current_clients[member],
                                f"GROUP_UPDATED|" f"{group_name}",
                            )

                    # Send the newly-added member the complete group state immediately.

                    if target_user in current_clients:

                        members_result = handle_group_members(target_user, group_name)

                        if members_result.startswith("MEMBERS|"):

                            send_message(current_clients[target_user], members_result)

                        history_result = handle_group_history(target_user, group_name)

                        if history_result.startswith("GROUP_HISTORY|"):

                            send_message(current_clients[target_user], history_result)

                        send_group_list(current_clients[target_user])

                        send_message(
                            current_clients[target_user],
                            f"MEMBER_ADDED|{group_name}|{target_user}",
                        )

            # =================================================

            # REMOVE MEMBER

            # =================================================

            elif command.startswith("/removemember "):

                content = command[len("/removemember ") :]

                parts = content.rsplit(" ", 1)

                if len(parts) != 2:

                    send_message(client, "ERROR|Usage: " "/removemember group user")

                    continue

                group_name = parts[0]

                target_user = parts[1]

                result = handle_remove_member(username, group_name, target_user)

                send_message(client, result)

                if result.startswith("MEMBER_REMOVED|"):

                    group_members = database.get_group_members(group_name)

                    with clients_lock:

                        current_clients = dict(clients)

                    for member in group_members:

                        if member in current_clients:

                            send_message(
                                current_clients[member],
                                f"GROUP_UPDATED|" f"{group_name}",
                            )

                    if target_user in current_clients:

                        send_message(
                            current_clients[target_user],
                            f"MEMBER_REMOVED|" f"{group_name}|" f"{target_user}",
                        )

            # =================================================

            # LEAVE GROUP

            # =================================================

            elif command.startswith("/leave "):

                group_name = command[len("/leave ") :]

                result = handle_leave_group(username, group_name)

                send_message(client, result)

                if result.startswith("LEFT|"):

                    send_group_list(client)

            # =================================================

            # GROUP MESSAGE

            # =================================================

            elif command.startswith("/groupmsg|"):

                result = handle_group_message(username, command)

                send_message(client, result)

            elif command.startswith("/groupmsg "):

                content = command[len("/groupmsg ") :]

                parts = content.rsplit(" ", 1)

                if len(parts) != 2:

                    send_message(client, "ERROR|Usage: " "/groupmsg group message")

                    continue

                group_name = parts[0]

                message = parts[1]

                result = handle_group_message(
                    username, f"/groupmsg|" f"{group_name}|" f"{message}"
                )

                send_message(client, result)

            # =================================================

            # GROUP HISTORY

            # =================================================

            elif command.startswith("/grouphistory "):

                group_name = command[len("/grouphistory ") :]

                result = handle_group_history(username, group_name)

                send_message(client, result)

            # =================================================

            # PRIVATE MESSAGE

            # =================================================

            elif command.startswith("/encrypted|"):

                result = handle_private_message(username, command)

                send_message(client, result)

            # =================================================

            # ACK

            # =================================================

            elif command.startswith("/ack|"):

                try:

                    message_id = int(command.split("|", 1)[1])

                    database.update_message_status(message_id, "read")

                except Exception as e:

                    print("[ACK ERROR]", e)

            # =================================================

            # HISTORY

            # =================================================

            elif command.startswith("/history "):

                target = command[len("/history ") :].strip()

                history = database.get_messages_between_users(username, target)

                records = []

                for row in history:

                    try:

                        timestamp = row[0]

                        sender = row[1]

                        receiver = row[2]

                        encrypted = row[3]

                        records.append(
                            f"{timestamp} | "
                            f"{sender} -> "
                            f"{receiver} | "
                            f"{encrypted}"
                        )

                    except Exception:

                        continue

                send_message(client, "HISTORY|" + ";;".join(records))

            # =================================================

            # PUBLIC KEY

            # =================================================

            elif command.startswith("PUBLIC_KEY|"):

                result = handle_public_key(username, command)

                send_message(client, result)

            # =================================================

            # KEY REQUEST

            # =================================================

            elif command.startswith("/key "):

                target = command[len("/key ") :]

                result = handle_key_request(username, target)

                send_message(client, result)

            # =================================================

            # EXIT

            # =================================================

            elif command == "/exit":

                break

            # =================================================

            # UNKNOWN

            # =================================================

            else:

                send_message(client, "ERROR|Unknown command")

    except ConnectionResetError:

        print(f"[CONNECTION RESET] " f"{username}")

    except ConnectionAbortedError:

        print(f"[CONNECTION ABORTED] " f"{username}")

    except Exception as e:

        print(f"[CLIENT ERROR] " f"{username}: " f"{e}")

    finally:

        if username:

            with clients_lock:

                if clients.get(username) is client:

                    clients.pop(username, None)

            print(f"[DISCONNECTED] " f"{username}")

            send_user_list()

        try:

            client.close()

        except Exception:

            pass


# =========================================================


# START SERVER


# =========================================================


def start_server():

    global server

    global running

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server.bind((HOST, PORT))

    server.listen(50)

    print("======================================")

    print("       SECURE CHAT TCP SERVER")

    print("======================================")

    print(f"Listening on " f"{HOST}:{PORT}")

    print("Server started...")

    while running:

        try:

            client, address = server.accept()

            thread = threading.Thread(
                target=handle_client, args=(client, address), daemon=True
            )

            thread.start()

        except OSError:

            break

        except Exception as e:

            print("[SERVER ERROR]", e)

    try:

        server.close()

    except Exception:

        pass


# =========================================================


# MAIN


# =========================================================


if __name__ == "__main__":

    start_server()
