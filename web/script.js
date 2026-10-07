// ============================================================
// SECURECHAT - script.js
// ============================================================

let socket = null;

let currentUser = null;
let currentChatUser = null;
let currentGroup = null;
let currentMode = null;

let onlineUsers = [];
let groups = [];
let groupMembers = {};

let authHandlersBound = false;
let chatHandlersBound = false;


// ============================================================
// HELPERS
// ============================================================

function $(id) {
    return document.getElementById(id);
}

function escapeHtml(value) {
    const div = document.createElement("div");
    div.textContent = value == null ? "" : String(value);
    return div.innerHTML;
}

function sameUser(a, b) {
    if (a == null || b == null) return false;
    return String(a).trim().toLowerCase() === String(b).trim().toLowerCase();
}

function guard(fn, wait = 400) {
    let last = 0;
    return function (...args) {
        const now = Date.now();
        if (now - last < wait) return;
        last = now;
        return fn.apply(this, args);
    };
}

function showToast(message, type = "success") {
    const toast = $("toast");
    const text = $("toastMessage");
    const icon = $("toastIcon");

    if (!toast) {
        console.log(`[${type}] ${message}`);
        return;
    }

    if (text) {
        text.textContent = message;
    }

    if (icon) {
        icon.textContent = type === "error" ? "!" : "✓";
    }

    toast.classList.add("show");

    setTimeout(() => {
        toast.classList.remove("show");
    }, 2500);
}

function updateNetworkStatus(status) {
    const element = $("networkStatus");

    if (element) {
        element.textContent = status;
    }
}

function clearMessage(id) {
    const element = $(id);

    if (element) {
        element.textContent = "";
        element.className = "auth-message";
    }
}

function setMessage(id, message, type = "error") {
    const element = $(id);

    if (!element) return;

    element.textContent = message;
    element.className = "auth-message";

    if (type === "success") {
        element.classList.add("success");
    } else {
        element.classList.add("error");
    }
}

function extractErrorMessage(data, fallback = "An error occurred.") {
    if (typeof data === "string" && data) return data;

    if (data && typeof data === "object") {
        return data.message || data.error || fallback;
    }

    return fallback;
}

function getGroupFromData(data) {
    return (
        (data && (data.group || data.groupname || data.name)) ||
        ""
    );
}

function getMemberName(member) {
    if (typeof member === "string") {
        return member;
    }

    if (member && typeof member === "object") {
        return (
            member.username ||
            member.user ||
            member.name ||
            member.member ||
            ""
        );
    }

    return "";
}

function normalizeNames(list) {
    if (!Array.isArray(list)) return [];

    return list
        .map(getMemberName)
        .filter(name => !!name);
}

function parseTimestamp(timestamp) {
    if (!timestamp) return null;

    if (timestamp instanceof Date) {
        return isNaN(timestamp.getTime()) ? null : timestamp;
    }

    let value = timestamp;

    if (typeof value === "number") {
        // Seconds vs milliseconds
        if (value < 1e12) value = value * 1000;
        const fromNumber = new Date(value);
        return isNaN(fromNumber.getTime()) ? null : fromNumber;
    }

    value = String(value).trim();

    // "2026-10-07 12:30:45" -> "2026-10-07T12:30:45"
    if (/^\d{4}-\d{2}-\d{2} \d/.test(value)) {
        value = value.replace(" ", "T");
    }

    const parsed = new Date(value);

    return isNaN(parsed.getTime()) ? null : parsed;
}

function ensureSocketLibrary() {
    if (typeof io === "undefined") {
        console.error("Socket.IO client library (io) is not loaded.");
        showToast("Socket.IO library failed to load", "error");
        return false;
    }

    return true;
}

// Single place where the Socket.IO connection is created.
function createSocket() {

    if (socket) {
        return socket;
    }

    if (!ensureSocketLibrary()) {
        return null;
    }

    socket = io(window.location.origin, {
        transports: ["websocket"],
        reconnection: true,
        reconnectionAttempts: 10,
        timeout: 10000
    });

    return socket;
}


// ============================================================
// LOGIN / REGISTER TABS
// ============================================================

function showLogin() {
    $("loginForm")?.classList.remove("hidden");
    $("registerForm")?.classList.add("hidden");

    $("loginTab")?.classList.add("active");
    $("registerTab")?.classList.remove("active");

    clearMessage("registerMessage");
}

function showRegister() {
    $("registerForm")?.classList.remove("hidden");
    $("loginForm")?.classList.add("hidden");

    $("registerTab")?.classList.add("active");
    $("loginTab")?.classList.remove("active");

    clearMessage("loginMessage");
}


// ============================================================
// AUTH SOCKET
// ============================================================

function connectAuthSocket() {

    const s = createSocket();

    if (!s) {
        return null;
    }

    if (authHandlersBound) {
        return s;
    }

    authHandlersBound = true;

    s.on("connect", () => {
        console.log("Auth socket connected:", s.id);
    });

    s.on("connect_error", error => {
        console.error("Auth socket connect error:", error);
    });

    s.on("register_success", data => {

        setMessage(
            "registerMessage",
            data?.message || "Registration successful!",
            "success"
        );

        setTimeout(() => {
            showLogin();
        }, 1000);
    });

    s.on("register_error", data => {

        setMessage(
            "registerMessage",
            data?.message || "Registration failed.",
            "error"
        );
    });

    s.on("login_success", data => {

        currentUser = data?.username;

        if (!currentUser) {
            setMessage(
                "loginMessage",
                "Login failed: no username returned.",
                "error"
            );
            return;
        }

        localStorage.setItem(
            "securechat_username",
            currentUser
        );

        window.location.href = "/chat";
    });

    s.on("login_error", data => {

        setMessage(
            "loginMessage",
            data?.message || "Invalid username or password.",
            "error"
        );
    });

    return s;
}


// ============================================================
// REGISTER
// ============================================================

function registerUser() {

    const username =
        $("registerUsername")?.value.trim();

    const password =
        $("registerPassword")?.value;

    if (!username || !password) {

        setMessage(
            "registerMessage",
            "Please enter username and password.",
            "error"
        );

        return;
    }

    const s = connectAuthSocket();

    if (!s) return;

    s.emit("register", {
        username: username,
        password: password
    });
}


// ============================================================
// LOGIN
// ============================================================

function login() {

    const username =
        $("loginUsername")?.value.trim();

    const password =
        $("loginPassword")?.value;

    if (!username || !password) {

        setMessage(
            "loginMessage",
            "Please enter username and password.",
            "error"
        );

        return;
    }

    const s = connectAuthSocket();

    if (!s) return;

    s.emit("login", {
        username: username,
        password: password
    });
}


// ============================================================
// CHAT INITIALIZATION
// ============================================================

function initializeChat() {

    currentUser =
        localStorage.getItem("securechat_username");

    if (!currentUser) {
        window.location.href = "/";
        return;
    }

    if ($("currentUsername")) {
        $("currentUsername").textContent =
            currentUser;
    }

    if ($("myAvatar")) {
        $("myAvatar").textContent =
            currentUser.charAt(0).toUpperCase();
    }

    connectChatSocket();
}


// ============================================================
// CHAT SOCKET
// ============================================================

function connectChatSocket() {

    const s = createSocket();

    if (!s) {
        return null;
    }

    // Handlers are registered exactly once per socket.
    if (chatHandlersBound) {
        return s;
    }

    chatHandlersBound = true;


    // ========================================================
    // CONNECTION
    // ========================================================

    s.on("connect", () => {

        console.log(
            "Chat socket connected:",
            s.id
        );

        updateNetworkStatus("Connected");

        // Runs on every (re)connect so the session is re-attached.
        s.emit("attach", {
            username: currentUser
        });

        s.emit("get_users");
        s.emit("get_groups");
    });

    s.on("disconnect", reason => {

        updateNetworkStatus("Disconnected");

        console.log(
            "Chat socket disconnected:",
            reason
        );
    });

    s.on("connect_error", error => {

        updateNetworkStatus("Connection error");

        console.error(
            "Chat socket connect error:",
            error
        );
    });

    s.on("attach_success", data => {

        console.log(
            "ATTACH SUCCESS:",
            data
        );

        updateNetworkStatus("Connected");

        // Refresh once the server confirms our session.
        s.emit("get_users");
        s.emit("get_groups");

        if (currentGroup) {
            loadGroupMembers(currentGroup);
        }
    });

    s.on("key_success", data => {

        console.log(
            "KEY SUCCESS:",
            data
        );

        if (data?.message) {
            showToast(data.message);
        }
    });


    // ========================================================
    // USERS
    // ========================================================

    s.on("users", data => {

        const list =
            Array.isArray(data)
                ? data
                : Array.isArray(data?.users)
                    ? data.users
                    : [];

        onlineUsers = normalizeNames(list);

        renderUsers();

        populateAddMemberSelect();
    });


    // ========================================================
    // GROUPS
    // ========================================================

    s.on("groups", data => {

        groups =
            Array.isArray(data)
                ? data
                : Array.isArray(data?.groups)
                    ? data.groups
                    : [];

        if ($("groupCount")) {
            $("groupCount").textContent =
                groups.length;
        }

        renderGroups();
    });


    // ========================================================
    // PRIVATE MESSAGE
    // ========================================================

    s.on("message", data => {

        if (!data) return;

        const sender =
            data.sender || "Unknown";

        const message =
            data.message || "";

        if (!message) return;

        // Ignore echoes of our own messages (already displayed).
        if (sameUser(sender, currentUser)) {
            return;
        }

        if (
            currentMode === "private" &&
            sameUser(currentChatUser, sender)
        ) {

            addMessage(
                sender,
                message,
                false,
                data.timestamp
            );

        } else {

            showToast(
                `New message from ${sender}`
            );
        }
    });


    // ========================================================
    // PRIVATE HISTORY
    // ========================================================

    s.on("history", data => {

        console.log(
            "HISTORY RECEIVED:",
            data
        );

        showPrivateHistory(data);
    });


    // ========================================================
    // GROUP MESSAGE
    // ========================================================

    s.on("group_message", data => {

        console.log(
            "GROUP MESSAGE RECEIVED:",
            data
        );

        if (!data) return;

        const group =
            getGroupFromData(data);

        const sender =
            data.sender ||
            "Unknown";

        const message =
            data.message ||
            "";

        if (!message) return;

        /*
         * Only display a group message in the currently
         * opened group. Messages from other groups still
         * generate a notification.
         */

        if (
            currentMode === "group" &&
            currentGroup === group
        ) {

            /*
             * Do not display our own message twice.
             * We already display it immediately when sending.
             */
            if (!sameUser(sender, currentUser)) {

                addMessage(
                    sender,
                    message,
                    false,
                    data.timestamp
                );
            }

        } else if (!sameUser(sender, currentUser)) {

            showToast(
                `New message in ${group}`
            );
        }
    });


    // ========================================================
    // GROUP HISTORY
    // ========================================================

    s.on("group_history", data => {

        console.log(
            "GROUP HISTORY RECEIVED:",
            data
        );

        showGroupHistory(data);
    });


    // ========================================================
    // GROUP CREATED
    // ========================================================

    s.on("group_created", data => {

        console.log(
            "GROUP CREATED:",
            data
        );

        const group =
            getGroupFromData(data);

        if (group) {
            showToast(
                `Group "${group}" created`
            );
        }

        loadGroups();
    });


    // ========================================================
    // GROUP JOINED
    // ========================================================

    s.on("group_joined", data => {

        console.log(
            "GROUP JOINED:",
            data
        );

        const group =
            getGroupFromData(data);

        if (group) {
            showToast(
                `Joined ${group}`
            );
        }

        loadGroups();
    });


    // ========================================================
    // GENERIC JOINED EVENT
    // ========================================================

    s.on("joined", data => {

        console.log(
            "JOINED:",
            data
        );

        loadGroups();
    });


    // ========================================================
    // GROUP LEFT
    // ========================================================

    s.on("group_left", data => {

        console.log(
            "GROUP LEFT:",
            data
        );

        handleLeftGroup(
            getGroupFromData(data)
        );
    });


    // ========================================================
    // GENERIC LEFT
    // ========================================================

    s.on("left", data => {

        console.log(
            "LEFT GROUP:",
            data
        );

        handleLeftGroup(
            getGroupFromData(data)
        );
    });


    // ========================================================
    // MEMBERS
    // ========================================================

    s.on("members", data => {

        console.log(
            "MEMBERS RECEIVED:",
            data
        );

        handleMembersData(data);
    });


    // ========================================================
    // GROUP UPDATED
    // ========================================================

    s.on("group_updated", data => {

        console.log(
            "GROUP UPDATED:",
            data
        );

        const group =
            getGroupFromData(data);

        loadGroups();

        // If the server included the member list, apply it.
        if (Array.isArray(data?.members)) {

            handleMembersData({
                group: group || currentGroup,
                members: data.members
            });

            return;
        }

        if (
            currentGroup &&
            (!group || group === currentGroup)
        ) {
            loadGroupMembers(currentGroup);
        }
    });


    // ========================================================
    // MEMBER ADDED
    // ========================================================

    s.on("member_added", data => {

        console.log(
            "MEMBER ADDED:",
            data
        );

        const group =
            getGroupFromData(data);

        const username =
            data?.username ||
            data?.member ||
            "";

        if (username && sameUser(username, currentUser)) {

            showToast(
                `You were added to ${group || "a group"}`
            );

        } else if (username) {

            showToast(
                `${username} added to ${group}`
            );

        } else {

            showToast(
                `Member added to ${group}`
            );
        }

        loadGroups();

        if (
            currentGroup &&
            (!group || currentGroup === group)
        ) {

            loadGroupMembers(currentGroup);
        }
    });


    // ========================================================
    // MEMBER REMOVED
    // ========================================================

    s.on("member_removed", data => {

        console.log(
            "MEMBER REMOVED:",
            data
        );

        const group =
            getGroupFromData(data);

        const username =
            data?.username ||
            data?.member ||
            "";

        if (username) {

            showToast(
                `${username} removed from ${group}`
            );
        }

        /*
         * If THIS user was removed from the group,
         * immediately close the group.
         */

        if (
            sameUser(username, currentUser) &&
            currentGroup === group
        ) {

            currentGroup = null;
            currentMode = null;

            delete groupMembers[group];

            clearChatScreen();
            closeGroupInfo();

        } else if (
            currentGroup &&
            (!group || currentGroup === group)
        ) {

            loadGroupMembers(currentGroup);
        }

        loadGroups();
    });


    // ========================================================
    // ACKNOWLEDGEMENTS
    // ========================================================

    s.on("sent", data => {

        console.log(
            "SENT:",
            data
        );
    });

    s.on("ack", data => {

        console.log(
            "ACK:",
            data
        );
    });


    // ========================================================
    // SERVER ERRORS / NOTIFICATIONS
    // ========================================================

    s.on("error", data => {

        console.error(
            "SERVER ERROR:",
            data
        );

        showToast(
            extractErrorMessage(data),
            "error"
        );
    });

    s.on("server_error", data => {

        console.error(
            "SERVER_ERROR:",
            data
        );

        showToast(
            extractErrorMessage(data),
            "error"
        );
    });

    s.on("error_message", data => {

        console.error(
            "ERROR_MESSAGE:",
            data
        );

        showToast(
            extractErrorMessage(data),
            "error"
        );
    });

    s.on("server", data => {

        console.log(
            "SERVER:",
            data
        );

        if (data?.message) {

            showToast(
                data.message
            );
        }
    });

    s.on("server_message", data => {

        console.log(
            "SERVER_MESSAGE:",
            data
        );

        const text =
            extractErrorMessage(data, "");

        if (text) {

            showToast(
                text
            );
        }
    });


    return s;
}


// ============================================================
// LEFT GROUP HANDLER
// ============================================================

function handleLeftGroup(group) {

    if (group) {
        delete groupMembers[group];
    }

    if (
        currentGroup &&
        (!group || currentGroup === group)
    ) {

        currentGroup = null;
        currentMode = null;

        clearChatScreen();
        closeGroupInfo();
    }

    loadGroups();
}


// ============================================================
// USERS UI
// ============================================================

function renderUsers() {

    const container =
        $("usersList");

    if (!container) return;

    container.innerHTML = "";

    const users =
        onlineUsers.filter(
            user => !sameUser(user, currentUser)
        );

    if ($("onlineCount")) {

        $("onlineCount").textContent =
            users.length;
    }

    if ($("networkClients")) {

        $("networkClients").textContent =
            onlineUsers.length;
    }

    // Online / offline status of the open private chat
    if (
        currentMode === "private" &&
        currentChatUser &&
        $("chatSubtitle")
    ) {

        const isOnline =
            onlineUsers.some(
                user => sameUser(user, currentChatUser)
            );

        $("chatSubtitle").textContent =
            isOnline
                ? "Private conversation · Online"
                : "Private conversation · Offline";
    }

    if (users.length === 0) {

        container.innerHTML = `
            <div class="empty-list">
                No other users online
            </div>
        `;

        return;
    }

    users.forEach(user => {

        const button =
            document.createElement("button");

        button.type = "button";

        button.className =
            "user-item";

        if (
            currentMode === "private" &&
            currentChatUser === user
        ) {

            button.classList.add(
                "selected"
            );
        }

        button.innerHTML = `
            <span class="user-dot"></span>
            <span>${escapeHtml(user)}</span>
        `;

        button.onclick = () => {

            openPrivateChat(user);
        };

        container.appendChild(button);
    });
}


// ============================================================
// PRIVATE CHAT
// ============================================================

function openPrivateChat(username) {

    if (!username) return;

    currentChatUser = username;
    currentGroup = null;
    currentMode = "private";

    if ($("chatTitle")) {
        $("chatTitle").textContent =
            username;
    }

    if ($("chatSubtitle")) {
        $("chatSubtitle").textContent =
            "Private conversation";
    }

    $("groupInfoBtn")
        ?.classList.add("hidden");

    $("welcomeScreen")
        ?.classList.add("hidden");

    $("messagesContainer")
        ?.classList.remove("hidden");

    $("messageArea")
        ?.classList.remove("hidden");

    if ($("messages")) {
        $("messages").innerHTML = "";
    }

    renderUsers();
    renderGroups();

    loadPrivateHistory(username);
}


function loadPrivateHistory(username) {

    if (!socket || !socket.connected) {
        return;
    }

    /*
     * The web_server.py bridge translates this into
     * the TCP /history command.
     */

    socket.emit(
        "history",
        {
            username: username
        }
    );
}


function getHistoryItems(data) {

    if (Array.isArray(data)) {
        return data;
    }

    if (Array.isArray(data?.history)) {
        return data.history;
    }

    if (Array.isArray(data?.messages)) {
        return data.messages;
    }

    return [];
}


function showPrivateHistory(data) {

    // Only render history into an open private conversation.
    if (currentMode !== "private") {
        return;
    }

    // Ignore history for a different conversation if the server says which.
    const peer =
        data && !Array.isArray(data)
            ? (data.username || data.with || data.user || "")
            : "";

    if (
        peer &&
        currentChatUser &&
        !sameUser(peer, currentChatUser) &&
        !sameUser(peer, currentUser)
    ) {
        return;
    }

    const messages =
        $("messages");

    if (!messages) return;

    messages.innerHTML = "";

    getHistoryItems(data).forEach(item => {

        let sender;
        let message;
        let timestamp;

        if (Array.isArray(item)) {

            // [timestamp, sender, message]
            timestamp = item[0];
            sender = item[1];
            message = item[2];

        } else if (item && typeof item === "object") {

            sender = item.sender || item.from || item.username || "Unknown";
            message = item.message != null ? item.message : item.text;
            timestamp = item.timestamp || item.time || item.created_at;

        } else {

            return;
        }

        if (message == null || message === "") return;

        addMessage(
            sender,
            message,
            sameUser(sender, currentUser),
            timestamp
        );
    });
}


// ============================================================
// SEND MESSAGE
// ============================================================

function sendMessage() {

    const input =
        $("messageInput");

    if (!input) return;

    const message =
        input.value.trim();

    if (!message) return;

    if (!socket || !socket.connected) {

        showToast(
            "Not connected to server",
            "error"
        );

        return;
    }


    // --------------------------------------------------------
    // PRIVATE MESSAGE
    // --------------------------------------------------------

    if (
        currentMode === "private" &&
        currentChatUser
    ) {

        socket.emit(
            "chat_message",
            {
                receiver: currentChatUser,
                message: message
            }
        );

        addMessage(
            currentUser,
            message,
            true,
            new Date().toISOString()
        );

        input.value = "";

        return;
    }


    // --------------------------------------------------------
    // GROUP MESSAGE
    // --------------------------------------------------------

    if (
        currentMode === "group" &&
        currentGroup
    ) {

        console.log(
            "SENDING GROUP MESSAGE:",
            currentGroup,
            message
        );

        /*
         * The message is sent as a single string, untouched.
         * It is NEVER split on spaces. web_server.py builds:
         *
         * /groupmsg|groupname|message
         *
         * and sends it to server.py.
         */

        socket.emit(
            "group_message",
            {
                group: currentGroup,
                groupname: currentGroup,
                message: message
            }
        );

        /*
         * Show our own message immediately.
         * When the server broadcasts it back,
         * the group_message handler ignores our duplicate.
         */

        addMessage(
            currentUser,
            message,
            true,
            new Date().toISOString()
        );

        input.value = "";

        return;
    }


    showToast(
        "Select a user or group first",
        "error"
    );
}


function handleMessageKey(event) {

    if (event.key === "Enter") {

        event.preventDefault();

        sendMessage();
    }
}


// ============================================================
// ADD MESSAGE
// ============================================================

function addMessage(
    sender,
    message,
    mine = false,
    timestamp = null
) {

    const container =
        $("messages");

    if (!container) return;

    const row =
        document.createElement("div");

    row.className =
        `message-row ${mine ? "mine" : ""}`;

    const bubble =
        document.createElement("div");

    bubble.className =
        "message-bubble";

    const time =
        parseTimestamp(timestamp) || new Date();

    bubble.innerHTML = `
        <div class="message-sender">
            ${escapeHtml(sender)}
        </div>

        <div class="message-text">
            ${escapeHtml(message)}
        </div>

        <div class="message-time">
            ${time.toLocaleTimeString([], {
                hour: "2-digit",
                minute: "2-digit"
            })}
        </div>
    `;

    row.appendChild(bubble);

    container.appendChild(row);

    const messagesContainer =
        $("messagesContainer");

    if (messagesContainer) {

        messagesContainer.scrollTop =
            messagesContainer.scrollHeight;
    }

    container.scrollTop =
        container.scrollHeight;
}


// ============================================================
// CLEAR CHAT
// ============================================================

function clearChatScreen() {

    if ($("messages")) {
        $("messages").innerHTML = "";
    }

    $("welcomeScreen")
        ?.classList.remove("hidden");

    $("messagesContainer")
        ?.classList.add("hidden");

    $("messageArea")
        ?.classList.add("hidden");

    if ($("chatTitle")) {
        $("chatTitle").textContent =
            "SecureChat";
    }

    if ($("chatSubtitle")) {
        $("chatSubtitle").textContent =
            "Select a conversation";
    }

    $("groupInfoBtn")
        ?.classList.add("hidden");

    renderGroups();
    renderUsers();
}


// ============================================================
// SIDEBAR
// ============================================================

function showUsers() {

    $("usersPanel")
        ?.classList.remove("hidden");

    $("groupsPanel")
        ?.classList.add("hidden");

    updateSidebarTabs("users");

    renderUsers();
}


function showGroups() {

    $("groupsPanel")
        ?.classList.remove("hidden");

    $("usersPanel")
        ?.classList.add("hidden");

    updateSidebarTabs("groups");

    loadGroups();
}


function updateSidebarTabs(active) {

    document
        .querySelectorAll(".sidebar-item")
        .forEach(item => {

            item.classList.remove("active");
        });

    if (active === "users") {

        document
            .querySelector(
                '.sidebar-item[data-tab="users"]'
            )
            ?.classList.add("active");
    }

    if (active === "groups") {

        document
            .querySelector(
                '.sidebar-item[data-tab="groups"]'
            )
            ?.classList.add("active");
    }
}


// ============================================================
// GROUPS
// ============================================================

function loadGroups() {

    if (!socket || !socket.connected) {
        return;
    }

    socket.emit("get_groups");
}


function getGroupName(group) {

    if (typeof group === "string") {
        return group;
    }

    if (group && typeof group === "object") {
        return (
            group.name ||
            group.groupname ||
            group.group ||
            ""
        );
    }

    return "";
}


function renderGroups() {

    const container =
        $("groupsList");

    if (!container) return;

    container.innerHTML = "";

    if (groups.length === 0) {

        container.innerHTML = `
            <div class="empty-list">
                No groups available
            </div>
        `;

        return;
    }

    groups.forEach(group => {

        const groupName =
            getGroupName(group);

        if (!groupName) return;

        const button =
            document.createElement("button");

        button.type = "button";

        button.className =
            "group-item";

        if (
            currentMode === "group" &&
            currentGroup === groupName
        ) {

            button.classList.add(
                "selected"
            );
        }

        button.innerHTML = `
            <span>👥</span>
            <span>${escapeHtml(groupName)}</span>
        `;

        button.onclick = () => {

            openGroup(groupName);
        };

        container.appendChild(button);
    });
}


// ============================================================
// OPEN GROUP
// ============================================================

function openGroup(group) {

    if (!group) return;

    currentGroup = group;
    currentChatUser = null;
    currentMode = "group";

    if ($("chatTitle")) {
        $("chatTitle").textContent =
            group;
    }

    if ($("chatSubtitle")) {
        $("chatSubtitle").textContent =
            "Group conversation";
    }

    $("groupInfoBtn")
        ?.classList.remove("hidden");

    $("welcomeScreen")
        ?.classList.add("hidden");

    $("messagesContainer")
        ?.classList.remove("hidden");

    $("messageArea")
        ?.classList.remove("hidden");

    if ($("messages")) {
        $("messages").innerHTML = "";
    }

    renderGroups();
    renderUsers();

    // Show cached members right away while fresh data loads.
    if (groupMembers[group]) {
        renderGroupMembers(groupMembers[group]);
        populateAddMemberSelect(groupMembers[group]);
    }

    if (socket && socket.connected) {

        socket.emit(
            "group_history",
            {
                group: group,
                groupname: group
            }
        );

        loadGroupMembers(group);
    }
}


// ============================================================
// GROUP HISTORY
// ============================================================

function showGroupHistory(data) {

    // Only render history into an open group conversation.
    if (currentMode !== "group" || !currentGroup) {
        return;
    }

    // Ignore history that belongs to a different group.
    const group =
        data && !Array.isArray(data)
            ? getGroupFromData(data)
            : "";

    if (group && group !== currentGroup) {
        return;
    }

    const messages =
        $("messages");

    if (!messages) return;

    messages.innerHTML = "";

    getHistoryItems(data).forEach(item => {

        let sender;
        let message;
        let timestamp;

        if (Array.isArray(item)) {

            // Backend field order: timestamp, sender, message
            timestamp = item[0];
            sender = item[1];
            message = item[2];

        } else if (item && typeof item === "object") {

            sender = item.sender || item.username || item.from || "Unknown";
            message = item.message != null ? item.message : item.text;
            timestamp = item.timestamp || item.time || item.created_at;

        } else {

            return;
        }

        if (message == null || message === "") return;

        addMessage(
            sender,
            message,
            sameUser(sender, currentUser),
            timestamp
        );
    });
}


// ============================================================
// CREATE GROUP
// ============================================================

function openCreateGroup() {

    const modal =
        $("createGroupModal");

    if (modal) {
        modal.classList.remove("hidden");
    }

    const input =
        $("groupNameInput");

    if (input) {

        input.value = "";
        input.focus();
    }
}


function closeCreateGroup() {

    $("createGroupModal")
        ?.classList.add("hidden");
}


function createGroup() {

    const input =
        $("groupNameInput");

    if (!input) return;

    const group =
        input.value.trim();

    if (!group) {

        showToast(
            "Enter a group name",
            "error"
        );

        return;
    }

    if (!socket || !socket.connected) {

        showToast(
            "Not connected to server",
            "error"
        );

        return;
    }

    socket.emit(
        "create_group",
        {
            groupname: group
        }
    );

    closeCreateGroup();
}


// ============================================================
// JOIN GROUP
// ============================================================

function joinGroup(group) {

    if (!socket || !socket.connected) {
        return;
    }

    if (!group) return;

    socket.emit(
        "join_group",
        {
            groupname: group
        }
    );
}


// ============================================================
// GROUP INFO
// ============================================================

function openGroupInfo() {

    if (
        !currentGroup ||
        currentMode !== "group"
    ) {

        showToast(
            "Select a group first",
            "error"
        );

        return;
    }

    $("groupInfoModal")
        ?.classList.remove("hidden");

    if ($("infoGroupName")) {

        $("infoGroupName").textContent =
            currentGroup;
    }

    if (groupMembers[currentGroup]) {
        renderGroupMembers(groupMembers[currentGroup]);
        populateAddMemberSelect(groupMembers[currentGroup]);
    }

    loadGroupMembers(
        currentGroup
    );
}


function closeGroupInfo() {

    $("groupInfoModal")
        ?.classList.add("hidden");
}


// ============================================================
// GROUP MEMBERS
// ============================================================

function loadGroupMembers(group) {

    if (
        !socket ||
        !socket.connected ||
        !group
    ) {
        return;
    }

    socket.emit(
        "get_members",
        {
            group: group,
            groupname: group
        }
    );
}


function handleMembersData(data) {

    console.log(
        "MEMBERS DATA:",
        data
    );

    const group =
        getGroupFromData(data) ||
        currentGroup;

    const members =
        normalizeNames(
            Array.isArray(data)
                ? data
                : data?.members
        );

    // groupMembers[groupName] = ["user1", "user2", ...]
    if (group) {

        groupMembers[group] =
            members;
    }

    // Only touch the visible UI if this is the open group.
    if (group && group !== currentGroup) {
        return;
    }

    renderGroupMembers(
        members
    );

    populateAddMemberSelect(
        members
    );

    const label =
        `${members.length} member${members.length === 1 ? "" : "s"}`;

    if (
        currentMode === "group" &&
        $("chatSubtitle")
    ) {

        $("chatSubtitle").textContent =
            label;
    }

    if ($("infoGroupMeta")) {

        $("infoGroupMeta").textContent =
            label;
    }
}


function renderGroupMembers(members) {

    const container =
        $("groupMembersList");

    if (!container) return;

    container.innerHTML = "";

    const names =
        normalizeNames(members);

    if (names.length === 0) {

        container.innerHTML = `
            <div class="empty-list">
                No members found
            </div>
        `;

        return;
    }

    names.forEach(username => {

        const item =
            document.createElement("div");

        item.className =
            "member-item";

        const avatar =
            document.createElement("div");

        avatar.className =
            "member-avatar";

        avatar.textContent =
            username
                .charAt(0)
                .toUpperCase();

        const info =
            document.createElement("div");

        info.className =
            "member-info";

        const name =
            document.createElement("strong");

        name.textContent =
            username;

        info.appendChild(name);

        if (sameUser(username, currentUser)) {

            const you =
                document.createElement("span");

            you.className =
                "member-you";

            you.textContent =
                "You";

            info.appendChild(you);
        }

        item.appendChild(avatar);
        item.appendChild(info);

        // Remove-member control (not shown for ourselves;
        // use "leave group" for that).
        if (!sameUser(username, currentUser)) {

            const removeButton =
                document.createElement("button");

            removeButton.type = "button";

            removeButton.className =
                "member-remove";

            removeButton.textContent =
                "Remove";

            removeButton.onclick = () => {

                removeGroupMember(username);
            };

            item.appendChild(removeButton);
        }

        container.appendChild(item);
    });

    if ($("infoGroupMeta")) {

        $("infoGroupMeta").textContent =
            `${names.length} member${names.length === 1 ? "" : "s"}`;
    }
}


// ============================================================
// ADD MEMBER SELECT
// ============================================================

function populateAddMemberSelect(
    existingMembers = null
) {

    const select =
        $("addMemberSelect");

    if (!select) return;

    const previousValue =
        select.value;

    select.innerHTML = "";

    const defaultOption =
        document.createElement("option");

    defaultOption.value = "";

    defaultOption.textContent =
        "Select a user";

    select.appendChild(
        defaultOption
    );

    const members =
        existingMembers ||
        groupMembers[currentGroup] ||
        [];

    const memberNames =
        normalizeNames(members);

    onlineUsers.forEach(user => {

        if (!user) return;

        if (sameUser(user, currentUser)) {
            return;
        }

        if (
            memberNames.some(
                name => sameUser(name, user)
            )
        ) {
            return;
        }

        const option =
            document.createElement("option");

        option.value = user;

        option.textContent = user;

        select.appendChild(option);
    });

    // Keep the previous selection if it is still available.
    if (
        previousValue &&
        Array.from(select.options).some(
            option => option.value === previousValue
        )
    ) {
        select.value = previousValue;
    }
}


// ============================================================
// ADD MEMBER
// ============================================================

function addSelectedMember() {

    const select =
        $("addMemberSelect");

    if (!select) return;

    const username =
        select.value;

    if (!username) {

        showToast(
            "Select a user first",
            "error"
        );

        return;
    }

    if (!currentGroup) {

        showToast(
            "No group selected",
            "error"
        );

        return;
    }

    if (
        !socket ||
        !socket.connected
    ) {

        showToast(
            "Not connected to server",
            "error"
        );

        return;
    }

    console.log(
        "ADDING MEMBER:",
        username,
        "TO:",
        currentGroup
    );

    socket.emit(
        "add_member",
        {
            group: currentGroup,
            groupname: currentGroup,
            username: username
        }
    );

    select.value = "";
}


// ============================================================
// REMOVE MEMBER
// ============================================================

function removeGroupMember(
    username
) {

    if (!currentGroup) {

        showToast(
            "No group selected",
            "error"
        );

        return;
    }

    if (
        !socket ||
        !socket.connected
    ) {

        showToast(
            "Not connected to server",
            "error"
        );

        return;
    }

    if (!username) return;

    socket.emit(
        "remove_member",
        {
            group: currentGroup,
            groupname: currentGroup,
            username: username
        }
    );
}


// ============================================================
// LEAVE GROUP
// ============================================================

function leaveGroup() {

    if (!currentGroup) {

        showToast(
            "No group selected",
            "error"
        );

        return;
    }

    if (
        !socket ||
        !socket.connected
    ) {

        showToast(
            "Not connected to server",
            "error"
        );

        return;
    }

    const group =
        currentGroup;

    socket.emit(
        "leave_group",
        {
            group: group,
            groupname: group
        }
    );

    delete groupMembers[group];

    currentGroup = null;
    currentMode = null;

    clearChatScreen();
    closeGroupInfo();
}


// ============================================================
// REFRESH DATA
// ============================================================

function refreshData() {

    if (
        !socket ||
        !socket.connected
    ) {
        return;
    }

    socket.emit("get_users");
    socket.emit("get_groups");

    if (currentGroup) {
        loadGroupMembers(
            currentGroup
        );
    }
}


// ============================================================
// LOGOUT
// ============================================================

function logout() {

    localStorage.removeItem(
        "securechat_username"
    );

    if (socket) {

        try {
            socket.emit("logout");
        } catch (error) {
            console.error(error);
        }

        socket.disconnect();
        socket = null;
    }

    authHandlersBound = false;
    chatHandlersBound = false;

    currentUser = null;
    currentChatUser = null;
    currentGroup = null;
    currentMode = null;

    window.location.href = "/";
}


// ============================================================
// GUARDED ACTIONS
// (protects against double-firing if a button has both an
//  inline onclick in the HTML and an event listener here)
// ============================================================

const guardedLogin = guard(login);
const guardedRegister = guard(registerUser);
const guardedCreateGroup = guard(createGroup);
const guardedAddMember = guard(addSelectedMember);
const guardedLeaveGroup = guard(leaveGroup);
const guardedLogout = guard(logout);


// ============================================================
// EVENT LISTENERS
// ============================================================

document.addEventListener(
    "DOMContentLoaded",
    () => {

        /*
         * IMPORTANT:
         * Only initialize chat on /chat, and only the
         * auth socket elsewhere. Exactly one socket is
         * created per page.
         */

        const path =
            window.location.pathname;

        const isChatPage =
            path === "/chat" ||
            path === "/chat/";

        if (isChatPage) {

            initializeChat();

        } else {

            connectAuthSocket();
        }


        // ----------------------------------------------------
        // LOGIN
        // ----------------------------------------------------

        $("loginButton")
            ?.addEventListener(
                "click",
                guardedLogin
            );


        // ----------------------------------------------------
        // REGISTER
        // ----------------------------------------------------

        $("registerButton")
            ?.addEventListener(
                "click",
                guardedRegister
            );


        // ----------------------------------------------------
        // LOGIN TAB
        // ----------------------------------------------------

        $("loginTab")
            ?.addEventListener(
                "click",
                showLogin
            );


        // ----------------------------------------------------
        // REGISTER TAB
        // ----------------------------------------------------

        $("registerTab")
            ?.addEventListener(
                "click",
                showRegister
            );


        // ----------------------------------------------------
        // SEND MESSAGE
        // ----------------------------------------------------

        $("sendButton")
            ?.addEventListener(
                "click",
                sendMessage
            );


        // ----------------------------------------------------
        // ENTER MESSAGE
        // ----------------------------------------------------

        $("messageInput")
            ?.addEventListener(
                "keydown",
                handleMessageKey
            );


        // ----------------------------------------------------
        // CREATE GROUP
        // ----------------------------------------------------

        $("createGroupButton")
            ?.addEventListener(
                "click",
                guardedCreateGroup
            );


        // ----------------------------------------------------
        // ADD MEMBER
        // ----------------------------------------------------

        $("addMemberButton")
            ?.addEventListener(
                "click",
                guardedAddMember
            );


        // ----------------------------------------------------
        // LEAVE GROUP
        // ----------------------------------------------------

        $("leaveGroupButton")
            ?.addEventListener(
                "click",
                guardedLeaveGroup
            );


        // ----------------------------------------------------
        // CLOSE GROUP INFO
        // ----------------------------------------------------

        $("closeGroupInfo")
            ?.addEventListener(
                "click",
                closeGroupInfo
            );


        // ----------------------------------------------------
        // GROUP INFO BUTTON
        // ----------------------------------------------------

        $("groupInfoBtn")
            ?.addEventListener(
                "click",
                openGroupInfo
            );


        // ----------------------------------------------------
        // LOGOUT
        // ----------------------------------------------------

        $("logoutButton")
            ?.addEventListener(
                "click",
                guardedLogout
            );


        // ----------------------------------------------------
        // REFRESH
        // ----------------------------------------------------

        $("refreshButton")
            ?.addEventListener(
                "click",
                refreshData
            );
    }
);


// ============================================================
// MAKE FUNCTIONS AVAILABLE TO HTML
// ============================================================

window.login = guardedLogin;
window.registerUser = guardedRegister;

window.showLogin = showLogin;
window.showRegister = showRegister;

window.sendMessage = sendMessage;
window.handleMessageKey = handleMessageKey;

window.showUsers = showUsers;
window.showGroups = showGroups;

window.openPrivateChat = openPrivateChat;
window.openGroup = openGroup;

window.createGroup = guardedCreateGroup;
window.openCreateGroup = openCreateGroup;
window.closeCreateGroup = closeCreateGroup;

window.joinGroup = joinGroup;

window.openGroupInfo = openGroupInfo;
window.closeGroupInfo = closeGroupInfo;

window.addSelectedMember = guardedAddMember;

window.removeGroupMember = removeGroupMember;

window.leaveGroup = guardedLeaveGroup;

window.logout = guardedLogout;

window.refreshData = refreshData;