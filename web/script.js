// ============================================================
// SECURECHAT  –  script.js
// Fully wired to web_server.py Socket.IO events.
// ============================================================

'use strict';

// ── State ────────────────────────────────────────────────────
let socket = null;

let currentUser    = null;   // logged-in username
let currentChatUser = null;  // open private-chat peer
let currentGroup   = null;   // open group name
let currentMode    = null;   // "private" | "group" | null

let onlineUsers = [];   // currently connected users (from /users)
let allUsers    = [];   // all registered users      (from /allusers)
let groups      = [];   // groups this user belongs to

let groupMembers = {};  // groupName -> string[]
let groupAdmins  = {};  // groupName -> adminUsername

// Prevent duplicate socket handler registration
let authHandlersBound = false;
let chatHandlersBound = false;

const USERNAME_KEY = 'securechat_username';
const TOKEN_KEY    = 'securechat_token';


// ============================================================
// HELPERS
// ============================================================

function $(id) { return document.getElementById(id); }

/** Safely escape HTML to prevent XSS */
function escapeHtml(value) {
    const d = document.createElement('div');
    d.textContent = value == null ? '' : String(value);
    return d.innerHTML;
}

/** Case-insensitive username comparison */
function sameUser(a, b) {
    if (a == null || b == null) return false;
    return String(a).trim().toLowerCase() === String(b).trim().toLowerCase();
}

/** Debounce a button action to avoid double-fire */
function guard(fn, wait = 400) {
    let last = 0;
    return function (...args) {
        const now = Date.now();
        if (now - last < wait) return;
        last = now;
        return fn.apply(this, args);
    };
}

/** Get the string name from a group object or string */
function getGroupName(group) {
    if (typeof group === 'string') return group;
    if (group && typeof group === 'object')
        return group.name || group.groupname || group.group || '';
    return '';
}

/** Get group name from an event data object */
function getGroupFromData(data) {
    return (data && (data.group || data.groupname || data.name)) || '';
}

/** Normalize a member to a string name */
function getMemberName(member) {
    if (typeof member === 'string') return member;
    if (member && typeof member === 'object')
        return member.username || member.user || member.name || member.member || '';
    return '';
}

function normalizeNames(list) {
    if (!Array.isArray(list)) return [];
    return list.map(getMemberName).filter(Boolean);
}

/** Parse ISO / SQLite timestamp strings into a Date object */
function parseTimestamp(ts) {
    if (!ts) return null;
    if (ts instanceof Date) return isNaN(ts.getTime()) ? null : ts;
    if (typeof ts === 'number') {
        const d = new Date(ts < 1e12 ? ts * 1000 : ts);
        return isNaN(d.getTime()) ? null : d;
    }
    let s = String(ts).trim();
    if (/^\d{4}-\d{2}-\d{2} \d/.test(s)) s = s.replace(' ', 'T');
    const d = new Date(s);
    return isNaN(d.getTime()) ? null : d;
}

function extractErrorMessage(data, fallback = 'An error occurred.') {
    if (typeof data === 'string' && data) return data;
    if (data && typeof data === 'object')
        return data.message || data.error || fallback;
    return fallback;
}

function clearSession() {
    localStorage.removeItem(USERNAME_KEY);
    localStorage.removeItem(TOKEN_KEY);
}

function returnToLogin(message) {
    if (message) showToast(message, 'error');
    clearSession();
    setTimeout(() => { window.location.href = '/'; }, 1500);
}


// ============================================================
// TOAST
// ============================================================

let _toastTimer = null;

function showToast(message, type = 'success') {
    const toast = $('toast');
    const text  = $('toastMessage');
    const icon  = $('toastIcon');

    if (!toast) { console.log(`[${type}]`, message); return; }

    if (text) text.textContent = message;
    if (icon) icon.textContent = type === 'error' ? '✕' : '✓';

    // reset classes
    toast.className = 'toast show';
    if (type === 'error') toast.classList.add('error');

    clearTimeout(_toastTimer);
    _toastTimer = setTimeout(() => toast.classList.remove('show'), 3000);
}


// ============================================================
// NETWORK STATUS
// ============================================================

function setNetworkStatus(label, connected) {
    const el = $('networkStatus');
    if (!el) return;
    el.textContent = label;
    el.className = connected ? 'connected' : 'disconnected';
}


// ============================================================
// AUTH MESSAGE HELPERS (login/register page)
// ============================================================

function clearMessage(id) {
    const el = $(id);
    if (el) { el.textContent = ''; el.className = 'auth-message'; }
}

function setMessage(id, message, type = 'error') {
    const el = $(id);
    if (!el) return;
    el.textContent = message;
    el.className   = `auth-message ${type === 'success' ? 'success' : 'error'}`;
}


// ============================================================
// LOGIN / REGISTER TAB SWITCHING
// ============================================================

function showLogin() {
    $('loginForm')   ?.classList.remove('hidden');
    $('registerForm')?.classList.add('hidden');
    $('loginTab')    ?.classList.add('active');
    $('registerTab') ?.classList.remove('active');
    clearMessage('registerMessage');
    $('loginUsername')?.focus();
}

function showRegister() {
    $('registerForm')?.classList.remove('hidden');
    $('loginForm')   ?.classList.add('hidden');
    $('registerTab') ?.classList.add('active');
    $('loginTab')    ?.classList.remove('active');
    clearMessage('loginMessage');
    $('registerUsername')?.focus();
}


// ============================================================
// SOCKET CREATION – exactly one socket per page
// ============================================================

function createSocket() {
    if (socket) return socket;

    if (typeof io === 'undefined') {
        showToast('Socket.IO library failed to load.', 'error');
        console.error('[SecureChat] io is undefined – CDN load failed?');
        return null;
    }

    socket = io(window.location.origin, {
        transports: ['websocket'],
        reconnection: true,
        reconnectionAttempts: 20,
        reconnectionDelay: 1000,
        timeout: 12000,
    });

    return socket;
}


// ============================================================
// AUTH SOCKET  (index.html only)
// ============================================================

function connectAuthSocket() {
    const s = createSocket();
    if (!s) return null;
    if (authHandlersBound) return s;
    authHandlersBound = true;

    s.on('connect', () => {
        console.log('[Auth] connected', s.id);
    });

    s.on('connect_error', err => {
        console.error('[Auth] connect error', err);
        setMessage('loginMessage', 'Cannot reach server. Is it running?', 'error');
    });

    // ── Register ──────────────────────────────────────────
    s.on('register_success', data => {
        setMessage('registerMessage', data?.message || 'Registration successful!', 'success');
        setTimeout(showLogin, 1200);
    });

    s.on('register_error', data => {
        setMessage('registerMessage', extractErrorMessage(data, 'Registration failed.'), 'error');
    });

    // ── Login ──────────────────────────────────────────────
    s.on('login_success', data => {
        currentUser = data?.username;
        if (!currentUser) {
            setMessage('loginMessage', 'Login failed: no username returned.', 'error');
            return;
        }
        localStorage.setItem(USERNAME_KEY, currentUser);
        localStorage.setItem(TOKEN_KEY, data.token || '');
        // navigate to chat; socket is left open so the GRACE_SECONDS timer
        // in the server doesn't fire before attach succeeds.
        window.location.href = '/chat';
    });

    s.on('login_error', data => {
        setMessage('loginMessage', extractErrorMessage(data, 'Invalid username or password.'), 'error');
        const btn = $('loginButton');
        if (btn) { btn.disabled = false; btn.textContent = 'Sign In'; }
    });

    return s;
}


// ============================================================
// AUTH ACTIONS
// ============================================================

function registerUser() {
    const username = $('registerUsername')?.value.trim();
    const password = $('registerPassword')?.value;

    if (!username || !password) {
        setMessage('registerMessage', 'Please fill in username and password.', 'error');
        return;
    }

    clearMessage('registerMessage');
    const s = connectAuthSocket();
    if (!s) return;

    s.emit('register', { username, password });
}

function login() {
    const username = $('loginUsername')?.value.trim();
    const password = $('loginPassword')?.value;

    if (!username || !password) {
        setMessage('loginMessage', 'Please fill in username and password.', 'error');
        return;
    }

    clearMessage('loginMessage');

    const btn = $('loginButton');
    if (btn) { btn.disabled = true; btn.textContent = 'Signing in…'; }

    const s = connectAuthSocket();
    if (!s) {
        if (btn) { btn.disabled = false; btn.textContent = 'Sign In'; }
        return;
    }

    s.emit('login', { username, password });
}


// ============================================================
// CHAT INITIALIZATION  (chat.html only)
// ============================================================

function initializeChat() {
    currentUser = localStorage.getItem(USERNAME_KEY);
    const token = localStorage.getItem(TOKEN_KEY);

    if (!currentUser || !token) {
        clearSession();
        window.location.href = '/';
        return;
    }

    // Update sidebar header
    const avatar = $('myAvatar');
    if (avatar) avatar.textContent = currentUser.charAt(0).toUpperCase();
    const nameEl = $('currentUsername');
    if (nameEl) nameEl.textContent = currentUser;

    connectChatSocket();
}


// ============================================================
// CHAT SOCKET  (chat.html only)
// ============================================================

function connectChatSocket() {
    const s = createSocket();
    if (!s) return null;
    if (chatHandlersBound) return s;
    chatHandlersBound = true;


    // ── Connection lifecycle ───────────────────────────────
    s.on('connect', () => {
        console.log('[Chat] connected', s.id);
        setNetworkStatus('Connected', true);

        // Re-attach on every (re)connect so the session survives page refresh.
        s.emit('attach', {
            username: currentUser,
            token:    localStorage.getItem(TOKEN_KEY),
        });
    });

    s.on('disconnect', reason => {
        console.warn('[Chat] disconnected', reason);
        setNetworkStatus('Disconnected', false);
    });

    s.on('connect_error', err => {
        console.error('[Chat] connect error', err);
        setNetworkStatus('Connection error', false);
    });

    s.on('reconnect_attempt', n => {
        setNetworkStatus(`Reconnecting (${n})…`, false);
    });

    // ── Attach ────────────────────────────────────────────
    s.on('attach_success', data => {
        console.log('[Chat] attach_success', data);
        setNetworkStatus('Connected', true);

        s.emit('get_users');
        s.emit('get_groups');
        s.emit('get_all_users');

        if (currentGroup) loadGroupMembers(currentGroup);
    });

    s.on('attach_error', data => {
        console.error('[Chat] attach_error', data);
        returnToLogin(extractErrorMessage(data, 'Session expired. Please log in again.'));
    });

    s.on('session_closed', data => {
        console.error('[Chat] session_closed', data);
        returnToLogin(extractErrorMessage(data, 'Connection to the chat server was lost.'));
    });

    s.on('server_shutdown', () => {
        returnToLogin('The chat server was shut down.');
    });

    s.on('key_success', data => {
        console.log('[Chat] key_success', data);
    });


    // ── Online Users  (from /users command) ───────────────
    // Payload:  { users: ["alice", "bob", ...] }
    s.on('users', data => {
        const list = Array.isArray(data) ? data
                   : Array.isArray(data?.users) ? data.users : [];
        onlineUsers = normalizeNames(list);
        renderUsers();
        populateAddMemberSelect();
        updateNetworkClients();
    });

    // ── All Registered Users (from /allusers) ─────────────
    // Payload: { users: [...] }
    s.on('all_users', data => {
        const list = Array.isArray(data) ? data
                   : Array.isArray(data?.users) ? data.users : [];
        allUsers = normalizeNames(list);
        renderUsers();
        populateAddMemberSelect();
    });


    // ── Groups this user belongs to ───────────────────────
    // Payload: { groups: ["team", "general", ...] }
    s.on('groups', data => {
        groups = Array.isArray(data) ? data
               : Array.isArray(data?.groups) ? data.groups : [];

        const count = $('groupCount');
        if (count) count.textContent = groups.length;

        // If the open group was removed from our list, close it.
        if (
            currentMode === 'group' &&
            currentGroup &&
            !groups.some(g => getGroupName(g) === currentGroup)
        ) {
            currentGroup = null;
            currentMode  = null;
            clearChatScreen();
            closeGroupInfo();
        }

        renderGroups();
    });


    // ── Private Message ───────────────────────────────────
    // Payload: { sender, message_id, message, timestamp }
    s.on('message', data => {
        if (!data) return;
        const sender  = data.sender  || 'Unknown';
        const message = data.message || '';
        if (!message) return;

        // Ignore own echoes (we add the bubble optimistically on send).
        if (sameUser(sender, currentUser)) return;

        if (currentMode === 'private' && sameUser(currentChatUser, sender)) {
            addMessage(sender, message, false, data.timestamp);
        } else {
            showToast(`💬 New message from ${sender}`);
        }
    });

    // ── Private History ───────────────────────────────────
    // Payload: { with: "peer", history: [{sender,receiver,message,timestamp},...] }
    s.on('history', data => {
        console.log('[Chat] history received', data);
        showPrivateHistory(data);
    });


    // ── Group Message ─────────────────────────────────────
    // Payload: { group, sender, message, timestamp }
    s.on('group_message', data => {
        if (!data) return;
        const group   = getGroupFromData(data);
        const sender  = data.sender  || 'Unknown';
        const message = data.message || '';
        if (!message) return;

        if (currentMode === 'group' && currentGroup === group) {
            // Own messages are shown optimistically on send.
            if (!sameUser(sender, currentUser)) {
                addMessage(sender, message, false, data.timestamp);
            }
        } else if (!sameUser(sender, currentUser)) {
            showToast(`👥 New message in ${group}`);
        }
    });

    // ── Group History ─────────────────────────────────────
    // Payload: { group, history: [{timestamp,sender,message},...] }
    s.on('group_history', data => {
        console.log('[Chat] group_history received', data);
        showGroupHistory(data);
    });


    // ── Group Lifecycle ───────────────────────────────────
    s.on('group_created', data => {
        const group = getGroupFromData(data);
        if (group) showToast(`Group "${group}" created`);
        loadGroups();
    });

    s.on('joined',      () => loadGroups());
    s.on('group_joined',() => loadGroups());

    s.on('left',       data => handleLeftGroup(getGroupFromData(data)));
    s.on('group_left', data => handleLeftGroup(getGroupFromData(data)));

    s.on('group_updated', data => {
        const group = getGroupFromData(data);
        loadGroups();
        if (Array.isArray(data?.members)) {
            handleMembersData({
                group:   group || currentGroup,
                admin:   data.admin,
                members: data.members,
            });
            return;
        }
        if (currentGroup && (!group || group === currentGroup)) {
            loadGroupMembers(currentGroup);
        }
    });


    // ── Members ───────────────────────────────────────────
    // Payload: { group, admin, members: [string,...] }
    s.on('members', data => {
        console.log('[Chat] members received', data);
        handleMembersData(data);
    });

    s.on('member_added', data => {
        const group    = getGroupFromData(data);
        const username = data?.username || data?.member || '';
        if (sameUser(username, currentUser)) {
            showToast(`You were added to ${group || 'a group'}`);
        } else if (username) {
            showToast(`${username} added to ${group}`);
        }
        loadGroups();
        if (currentGroup && (!group || currentGroup === group)) {
            loadGroupMembers(currentGroup);
        }
    });

    s.on('member_removed', data => {
        const group    = getGroupFromData(data);
        const username = data?.username || data?.member || '';
        if (sameUser(username, currentUser)) {
            showToast(`You were removed from ${group}`, 'error');
        } else if (username) {
            showToast(`${username} removed from ${group}`);
        }
        if (sameUser(username, currentUser) && currentGroup === group) {
            currentGroup = null;
            currentMode  = null;
            delete groupMembers[group];
            delete groupAdmins[group];
            clearChatScreen();
            closeGroupInfo();
        } else if (currentGroup && (!group || currentGroup === group)) {
            loadGroupMembers(currentGroup);
        }
        loadGroups();
    });


    // ── Acknowledgements ──────────────────────────────────
    s.on('sent', () => { /* message delivered to server */ });
    s.on('ack',  () => { /* server ACK received */ });


    // ── Errors & Notifications ────────────────────────────
    s.on('error',         data => showToast(extractErrorMessage(data), 'error'));
    s.on('server_error',  data => showToast(extractErrorMessage(data), 'error'));
    s.on('error_message', data => showToast(extractErrorMessage(data), 'error'));

    s.on('server', data => {
        if (data?.message) showToast(data.message);
    });
    s.on('server_message', data => {
        const t = extractErrorMessage(data, '');
        if (t) showToast(t);
    });

    return s;
}


// ============================================================
// LEFT GROUP HANDLER
// ============================================================

function handleLeftGroup(group) {
    if (group) {
        delete groupMembers[group];
        delete groupAdmins[group];
    }
    if (currentGroup && (!group || currentGroup === group)) {
        currentGroup = null;
        currentMode  = null;
        clearChatScreen();
        closeGroupInfo();
    }
    loadGroups();
}


// ============================================================
// USERS UI
// ============================================================

function updateNetworkClients() {
    const el = $('networkClients');
    if (el) el.textContent = onlineUsers.length;
}

function renderUsers() {
    const container = $('usersList');
    if (!container) return;

    // Only show users who are currently online (excluding yourself).
    const online = onlineUsers.filter(u => !sameUser(u, currentUser));

    const countEl = $('onlineCount');
    if (countEl) countEl.textContent = online.length;

    updateNetworkClients();

    // Update subtitle for open private chat
    if (currentMode === 'private' && currentChatUser) {
        const subtitle = $('chatSubtitle');
        const isOnline = onlineUsers.some(u => sameUser(u, currentChatUser));
        if (subtitle) {
            subtitle.textContent = isOnline
                ? 'Private · 🟢 Online'
                : 'Private · ⚫ Offline';
        }
    }

    container.innerHTML = '';

    if (online.length === 0) {
        container.innerHTML = '<div class="empty-list">No other users online</div>';
        return;
    }

    online.forEach(user => {
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'user-item';
        if (currentMode === 'private' && sameUser(currentChatUser, user))
            btn.classList.add('selected');

        const initial = user.charAt(0).toUpperCase();
        btn.innerHTML = `
            <div class="user-avatar-sm">${escapeHtml(initial)}</div>
            <span class="user-dot"></span>
            <span>${escapeHtml(user)}</span>`;
        btn.onclick = () => openPrivateChat(user);
        container.appendChild(btn);
    });
}


// ============================================================
// GROUPS UI
// ============================================================

function renderGroups() {
    const container = $('groupsList');
    if (!container) return;

    container.innerHTML = '';

    if (groups.length === 0) {
        container.innerHTML = '<div class="empty-list">No groups yet. Create one!</div>';
        return;
    }

    groups.forEach(g => {
        const name = getGroupName(g);
        if (!name) return;

        const btn = document.createElement('button');
        btn.type      = 'button';
        btn.className = 'group-item';
        if (currentMode === 'group' && currentGroup === name)
            btn.classList.add('selected');

        btn.innerHTML = `
            <div class="group-icon">👥</div>
            <span>${escapeHtml(name)}</span>`;
        btn.onclick = () => openGroup(name);
        container.appendChild(btn);
    });
}

function loadGroups() {
    if (socket && socket.connected) socket.emit('get_groups');
}


// ============================================================
// OPEN PRIVATE CHAT
// ============================================================

function openPrivateChat(username) {
    if (!username) return;

    currentChatUser = username;
    currentGroup    = null;
    currentMode     = 'private';

    // Header
    const title    = $('chatTitle');
    const subtitle = $('chatSubtitle');
    const avatarEl = $('chatAvatarEl');

    if (title)    title.textContent    = username;
    if (subtitle) subtitle.textContent = 'Private · loading…';
    if (avatarEl) {
        avatarEl.textContent = username.charAt(0).toUpperCase();
        avatarEl.className   = 'chat-avatar';
    }

    $('groupInfoBtn')       ?.classList.add('hidden');
    $('welcomeScreen')      ?.classList.add('hidden');
    $('messagesContainer')  ?.classList.remove('hidden');
    $('messageArea')        ?.classList.remove('hidden');

    const msgs = $('messages');
    if (msgs) msgs.innerHTML = '<div class="empty-list">Loading history…</div>';

    renderUsers();
    renderGroups();
    loadPrivateHistory(username);
}

function loadPrivateHistory(username) {
    if (!socket || !socket.connected) return;
    // web_server.py translates this to the TCP /history command.
    socket.emit('get_history', { username });
}


// ============================================================
// SHOW PRIVATE HISTORY
// ============================================================

function getHistoryItems(data) {
    if (Array.isArray(data))           return data;
    if (Array.isArray(data?.history))  return data.history;
    if (Array.isArray(data?.messages)) return data.messages;
    return [];
}

function showPrivateHistory(data) {
    if (currentMode !== 'private') return;

    // Only render if the history matches the currently open conversation.
    const peer = (!Array.isArray(data))
        ? (data?.with || data?.username || data?.user || '')
        : '';

    if (peer && currentChatUser &&
        !sameUser(peer, currentChatUser) &&
        !sameUser(peer, currentUser)) return;

    const msgs = $('messages');
    if (!msgs) return;
    msgs.innerHTML = '';

    const items = getHistoryItems(data);

    if (items.length === 0) {
        msgs.innerHTML = '<div class="empty-list">No messages yet. Say hello!</div>';
        return;
    }

    // Group messages by date for date dividers.
    let lastDate = '';

    items.forEach(item => {
        let sender, message, timestamp;

        if (Array.isArray(item)) {
            [timestamp, sender, message] = item;
        } else if (item && typeof item === 'object') {
            sender    = item.sender || item.from || item.username || 'Unknown';
            message   = item.message != null ? item.message : item.text;
            timestamp = item.timestamp || item.time || item.created_at;
        } else { return; }

        if (message == null || message === '') return;

        const dateStr = formatDateDivider(timestamp);
        if (dateStr && dateStr !== lastDate) {
            appendDateDivider(msgs, dateStr);
            lastDate = dateStr;
        }

        addMessage(sender, message, sameUser(sender, currentUser), timestamp);
    });
}


// ============================================================
// OPEN GROUP
// ============================================================

function openGroup(group) {
    if (!group) return;

    currentGroup    = group;
    currentChatUser = null;
    currentMode     = 'group';

    const title    = $('chatTitle');
    const subtitle = $('chatSubtitle');
    const avatarEl = $('chatAvatarEl');

    if (title)    title.textContent    = group;
    if (subtitle) subtitle.textContent = 'Group chat · loading…';
    if (avatarEl) {
        avatarEl.textContent = '#';
        avatarEl.className   = 'chat-avatar group-av';
    }

    $('groupInfoBtn')     ?.classList.remove('hidden');
    $('welcomeScreen')    ?.classList.add('hidden');
    $('messagesContainer')?.classList.remove('hidden');
    $('messageArea')      ?.classList.remove('hidden');

    const msgs = $('messages');
    if (msgs) msgs.innerHTML = '<div class="empty-list">Loading history…</div>';

    renderGroups();
    renderUsers();

    // Show cached members immediately while fresh data loads.
    if (groupMembers[group]) {
        renderGroupMembers(groupMembers[group]);
        populateAddMemberSelect(groupMembers[group]);
        applyGroupPermissions();
    }

    if (socket && socket.connected) {
        socket.emit('get_group_history', { group, groupname: group });
        loadGroupMembers(group);
    }
}


// ============================================================
// SHOW GROUP HISTORY
// ============================================================

function showGroupHistory(data) {
    if (currentMode !== 'group' || !currentGroup) return;

    const group = (!Array.isArray(data)) ? getGroupFromData(data) : '';
    if (group && group !== currentGroup) return;

    const msgs = $('messages');
    if (!msgs) return;
    msgs.innerHTML = '';

    const items = getHistoryItems(data);

    if (items.length === 0) {
        msgs.innerHTML = '<div class="empty-list">No messages yet. Be the first!</div>';
        return;
    }

    let lastDate = '';

    items.forEach(item => {
        let sender, message, timestamp;

        if (Array.isArray(item)) {
            [timestamp, sender, message] = item;
        } else if (item && typeof item === 'object') {
            sender    = item.sender || item.username || item.from || 'Unknown';
            message   = item.message != null ? item.message : item.text;
            timestamp = item.timestamp || item.time || item.created_at;
        } else { return; }

        if (message == null || message === '') return;

        const dateStr = formatDateDivider(timestamp);
        if (dateStr && dateStr !== lastDate) {
            appendDateDivider(msgs, dateStr);
            lastDate = dateStr;
        }

        addMessage(sender, message, sameUser(sender, currentUser), timestamp);
    });
}


// ============================================================
// SEND MESSAGE
// ============================================================

function sendMessage() {
    const input   = $('messageInput');
    if (!input) return;

    const message = input.value.trim();
    if (!message) return;

    if (!socket || !socket.connected) {
        showToast('Not connected to server', 'error');
        return;
    }

    if (currentMode === 'private' && currentChatUser) {
        // web_server.py handler: chat_message -> /encrypted|receiver|payload
        socket.emit('chat_message', {
            receiver: currentChatUser,
            message,
        });
        addMessage(currentUser, message, true, new Date().toISOString());
        input.value = '';
        return;
    }

    if (currentMode === 'group' && currentGroup) {
        // web_server.py handler: group_message -> /groupmsg|group|text
        socket.emit('group_message', {
            group:     currentGroup,
            groupname: currentGroup,
            message,
        });
        addMessage(currentUser, message, true, new Date().toISOString());
        input.value = '';
        return;
    }

    showToast('Select a user or group first', 'error');
}

function handleMessageKey(event) {
    if (event.key === 'Enter') {
        event.preventDefault();
        sendMessage();
    }
}


// ============================================================
// ADD MESSAGE BUBBLE
// ============================================================

function addMessage(sender, message, mine = false, timestamp = null) {
    const container = $('messages');
    if (!container) return;

    // Remove the placeholder if present.
    const placeholder = container.querySelector('.empty-list');
    if (placeholder) placeholder.remove();

    const row = document.createElement('div');
    row.className = `message-row${mine ? ' mine' : ''}`;

    // Small avatar for incoming messages
    if (!mine) {
        const av = document.createElement('div');
        av.className   = 'msg-avatar';
        av.textContent = sender.charAt(0).toUpperCase();
        row.appendChild(av);
    }

    const bubble = document.createElement('div');
    bubble.className = 'message-bubble';

    const time = parseTimestamp(timestamp) || new Date();

    bubble.innerHTML = `
        <div class="message-sender">${escapeHtml(sender)}</div>
        <div class="message-text">${escapeHtml(message)}</div>
        <div class="message-time">${time.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</div>`;

    row.appendChild(bubble);
    container.appendChild(row);

    // Scroll to bottom
    const mc = $('messagesContainer');
    if (mc) mc.scrollTop = mc.scrollHeight;
}


// ============================================================
// DATE DIVIDER HELPERS
// ============================================================

function formatDateDivider(timestamp) {
    const d = parseTimestamp(timestamp);
    if (!d) return '';
    const today     = new Date();
    const yesterday = new Date(today);
    yesterday.setDate(today.getDate() - 1);

    if (d.toDateString() === today.toDateString())     return 'Today';
    if (d.toDateString() === yesterday.toDateString()) return 'Yesterday';
    return d.toLocaleDateString([], { weekday: 'long', month: 'short', day: 'numeric' });
}

function appendDateDivider(container, text) {
    const div = document.createElement('div');
    div.className = 'date-divider';
    div.innerHTML = `<span>${escapeHtml(text)}</span>`;
    container.appendChild(div);
}


// ============================================================
// CLEAR CHAT SCREEN
// ============================================================

function clearChatScreen() {
    const msgs = $('messages');
    if (msgs) msgs.innerHTML = '';

    $('welcomeScreen')    ?.classList.remove('hidden');
    $('messagesContainer')?.classList.add('hidden');
    $('messageArea')      ?.classList.add('hidden');

    const title    = $('chatTitle');
    const subtitle = $('chatSubtitle');
    const avatarEl = $('chatAvatarEl');

    if (title)    title.textContent    = 'SecureChat';
    if (subtitle) subtitle.textContent = 'Select a conversation';
    if (avatarEl) { avatarEl.textContent = '💬'; avatarEl.className = 'chat-avatar'; }

    $('groupInfoBtn')?.classList.add('hidden');

    renderGroups();
    renderUsers();
}


// ============================================================
// SIDEBAR PANEL SWITCHING
// ============================================================

function showUsers() {
    $('usersPanel') ?.classList.remove('hidden');
    $('groupsPanel')?.classList.add('hidden');
    _updateSidebarTabs('users');
    renderUsers();
}

function showGroups() {
    $('groupsPanel')?.classList.remove('hidden');
    $('usersPanel') ?.classList.add('hidden');
    _updateSidebarTabs('groups');
    loadGroups();
}

function _updateSidebarTabs(active) {
    document.querySelectorAll('.sidebar-item').forEach(el => el.classList.remove('active'));
    document.querySelector(`.sidebar-item[data-tab="${active}"]`)?.classList.add('active');
}


// ============================================================
// CREATE GROUP
// ============================================================

function openCreateGroup() {
    $('createGroupModal')?.classList.remove('hidden');
    const input = $('groupNameInput');
    if (input) { input.value = ''; input.focus(); }
}

function closeCreateGroup() {
    $('createGroupModal')?.classList.add('hidden');
}

function createGroup() {
    const input = $('groupNameInput');
    if (!input) return;

    const group = input.value.trim();
    if (!group) { showToast('Enter a group name', 'error'); return; }
    if (!socket || !socket.connected) { showToast('Not connected', 'error'); return; }

    // web_server.py: create_group -> /create groupname
    socket.emit('create_group', { groupname: group });
    closeCreateGroup();
}


// ============================================================
// JOIN GROUP  (admin adds members; kept for completeness)
// ============================================================

function joinGroup(group) {
    if (!socket || !socket.connected || !group) return;
    socket.emit('join_group', { groupname: group });
}


// ============================================================
// GROUP INFO MODAL
// ============================================================

function isGroupAdmin(group) {
    return !!group && sameUser(groupAdmins[group], currentUser);
}

/** Show/hide admin-only controls – only UI hint; backend enforces. */
function applyGroupPermissions() {
    const admin = isGroupAdmin(currentGroup);
    $('addMemberSection')?.classList.toggle('hidden', !admin);
    $('leaveSection')    ?.classList.toggle('hidden', admin);
}

function openGroupInfo() {
    if (!currentGroup || currentMode !== 'group') {
        showToast('Select a group first', 'error');
        return;
    }

    $('groupInfoModal')?.classList.remove('hidden');

    const nameEl = $('infoGroupName');
    if (nameEl) nameEl.textContent = currentGroup;

    if (groupMembers[currentGroup]) {
        renderGroupMembers(groupMembers[currentGroup]);
        populateAddMemberSelect(groupMembers[currentGroup]);
    }

    applyGroupPermissions();
    loadGroupMembers(currentGroup);
}

function closeGroupInfo() {
    $('groupInfoModal')?.classList.add('hidden');
}


// ============================================================
// GROUP MEMBERS
// ============================================================

function loadGroupMembers(group) {
    if (!socket || !socket.connected || !group) return;
    // web_server.py: get_members -> /members groupname
    socket.emit('get_members', { group, groupname: group });
}

function handleMembersData(data) {
    const group   = getGroupFromData(data) || currentGroup;
    const members = normalizeNames(Array.isArray(data) ? data : data?.members);

    if (group) {
        groupMembers[group] = members;
        if (data?.admin) groupAdmins[group] = data.admin;
    }

    // Only touch the visible UI if this is the open group.
    if (group && group !== currentGroup) return;

    renderGroupMembers(members);
    populateAddMemberSelect(members);
    applyGroupPermissions();

    const count    = members.length;
    const subtitle = $('chatSubtitle');
    if (currentMode === 'group' && subtitle) {
        subtitle.textContent = `${count} member${count === 1 ? '' : 's'}`;
    }
    _updateGroupMeta(count);
}

function _updateGroupMeta(count) {
    const el = $('infoGroupMeta');
    if (!el) return;
    const admin = groupAdmins[currentGroup];
    let text = `${count} member${count === 1 ? '' : 's'}`;
    if (admin) text += ` · Admin: ${admin}`;
    el.textContent = text;
}

function renderGroupMembers(members) {
    const container = $('groupMembersList');
    if (!container) return;

    container.innerHTML = '';
    const names = normalizeNames(members);

    if (names.length === 0) {
        container.innerHTML = '<div class="empty-list">No members found</div>';
        return;
    }

    const adminName      = groupAdmins[currentGroup];
    const viewerIsAdmin  = isGroupAdmin(currentGroup);

    names.forEach(username => {
        const item   = document.createElement('div');
        item.className = 'member-item';

        const av = document.createElement('div');
        av.className   = 'member-avatar';
        av.textContent = username.charAt(0).toUpperCase();

        const info = document.createElement('div');
        info.className = 'member-info';

        const nameNode = document.createElement('strong');
        nameNode.textContent = username;
        info.appendChild(nameNode);

        if (sameUser(username, adminName)) {
            const badge = document.createElement('span');
            badge.className   = 'member-admin';
            badge.textContent = 'Admin';
            info.appendChild(badge);
        }

        if (sameUser(username, currentUser)) {
            const you = document.createElement('span');
            you.className   = 'member-you';
            you.textContent = 'You';
            info.appendChild(you);
        }

        item.appendChild(av);
        item.appendChild(info);

        // Remove button: admin only, not for self or admin
        if (viewerIsAdmin && !sameUser(username, adminName) && !sameUser(username, currentUser)) {
            const removeBtn = document.createElement('button');
            removeBtn.type      = 'button';
            removeBtn.className = 'member-remove';
            removeBtn.textContent = 'Remove';
            removeBtn.onclick = () => removeGroupMember(username);
            item.appendChild(removeBtn);
        }

        container.appendChild(item);
    });

    _updateGroupMeta(names.length);
}


// ============================================================
// ADD MEMBER SELECT
// ============================================================

function populateAddMemberSelect(existingMembers = null) {
    const select = $('addMemberSelect');
    if (!select) return;

    const prev = select.value;
    select.innerHTML = '<option value="">Select a user…</option>';

    const memberNames = normalizeNames(existingMembers || groupMembers[currentGroup] || []);
    // Prefer all registered users if known, fall back to online-only.
    const candidates  = allUsers.length > 0 ? allUsers : onlineUsers;

    candidates.forEach(user => {
        if (!user) return;
        if (sameUser(user, currentUser)) return;
        if (memberNames.some(m => sameUser(m, user))) return;

        const opt = document.createElement('option');
        opt.value = user;
        opt.textContent = user;
        select.appendChild(opt);
    });

    // Restore previous selection if still valid
    if (prev && Array.from(select.options).some(o => o.value === prev))
        select.value = prev;
}


// ============================================================
// ADD MEMBER
// ============================================================

function addSelectedMember() {
    const select = $('addMemberSelect');
    if (!select) return;

    const username = select.value;
    if (!username) { showToast('Select a user first', 'error'); return; }
    if (!currentGroup) { showToast('No group selected', 'error'); return; }
    if (!isGroupAdmin(currentGroup)) {
        showToast('Only the group admin can add members', 'error'); return;
    }
    if (!socket || !socket.connected) { showToast('Not connected', 'error'); return; }

    // web_server.py: add_member -> /addmember groupname username
    socket.emit('add_member', {
        group:    currentGroup,
        groupname:currentGroup,
        username,
    });

    select.value = '';
}


// ============================================================
// REMOVE MEMBER
// ============================================================

function removeGroupMember(username) {
    if (!currentGroup) { showToast('No group selected', 'error'); return; }
    if (!isGroupAdmin(currentGroup)) {
        showToast('Only the group admin can remove members', 'error'); return;
    }
    if (!socket || !socket.connected) { showToast('Not connected', 'error'); return; }
    if (!username) return;

    // web_server.py: remove_member -> /removemember groupname username
    socket.emit('remove_member', {
        group:    currentGroup,
        groupname:currentGroup,
        username,
    });
}


// ============================================================
// LEAVE GROUP
// ============================================================

function leaveGroup() {
    if (!currentGroup) { showToast('No group selected', 'error'); return; }
    if (isGroupAdmin(currentGroup)) {
        showToast('The group admin cannot leave the group', 'error'); return;
    }
    if (!socket || !socket.connected) { showToast('Not connected', 'error'); return; }

    // web_server.py: leave_group -> /leave groupname
    socket.emit('leave_group', { group: currentGroup, groupname: currentGroup });
}


// ============================================================
// REFRESH DATA
// ============================================================

function refreshData() {
    if (!socket || !socket.connected) { showToast('Not connected', 'error'); return; }

    const btn = $('refreshButton');
    if (btn) btn.classList.add('spin');
    setTimeout(() => btn?.classList.remove('spin'), 600);

    socket.emit('get_users');
    socket.emit('get_groups');
    socket.emit('get_all_users');
    if (currentGroup) loadGroupMembers(currentGroup);
    if (currentMode === 'private' && currentChatUser) loadPrivateHistory(currentChatUser);
    if (currentMode === 'group'   && currentGroup)    {
        socket.emit('get_group_history', { group: currentGroup, groupname: currentGroup });
    }
}


// ============================================================
// LOGOUT
// ============================================================

function logout() {
    clearSession();

    if (socket) {
        try { socket.emit('logout'); } catch (_) { /* ignore */ }
        socket.disconnect();
        socket = null;
    }

    authHandlersBound = false;
    chatHandlersBound = false;
    currentUser = currentChatUser = currentGroup = currentMode = null;

    window.location.href = '/';
}


// ============================================================
// GUARDED (debounced) VERSIONS
// ============================================================

const guardedLogin       = guard(login);
const guardedRegister    = guard(registerUser);
const guardedCreateGroup = guard(createGroup);
const guardedAddMember   = guard(addSelectedMember);
const guardedLeaveGroup  = guard(leaveGroup);
const guardedLogout      = guard(logout);


// ============================================================
// DOM READY
// ============================================================

document.addEventListener('DOMContentLoaded', () => {
    const isChatPage = window.location.pathname.startsWith('/chat');

    if (isChatPage) {
        initializeChat();
    } else {
        connectAuthSocket();
        // Focus the username field on load
        setTimeout(() => $('loginUsername')?.focus(), 100);
    }

    // Wire up elements that may exist on either page
    $('loginButton')    ?.addEventListener('click', guardedLogin);
    $('registerButton') ?.addEventListener('click', guardedRegister);
    $('loginTab')       ?.addEventListener('click', showLogin);
    $('registerTab')    ?.addEventListener('click', showRegister);

    $('sendButton')     ?.addEventListener('click', sendMessage);
    $('messageInput')   ?.addEventListener('keydown', handleMessageKey);

    $('createGroupButton')?.addEventListener('click', guardedCreateGroup);
    $('addMemberButton')  ?.addEventListener('click', guardedAddMember);
    $('leaveGroupButton') ?.addEventListener('click', guardedLeaveGroup);

    $('closeGroupInfo')   ?.addEventListener('click', closeGroupInfo);
    $('groupInfoBtn')     ?.addEventListener('click', openGroupInfo);

    $('logoutButton')     ?.addEventListener('click', guardedLogout);
    $('refreshButton')    ?.addEventListener('click', refreshData);

    // Close modals when clicking the backdrop
    document.querySelectorAll('.modal').forEach(modal => {
        modal.addEventListener('click', e => {
            if (e.target === modal) {
                modal.classList.add('hidden');
            }
        });
    });
});


// ============================================================
// EXPOSE TO INLINE HTML HANDLERS
// ============================================================

window.login        = guardedLogin;
window.registerUser = guardedRegister;

window.showLogin    = showLogin;
window.showRegister = showRegister;

window.sendMessage      = sendMessage;
window.handleMessageKey = handleMessageKey;

window.showUsers  = showUsers;
window.showGroups = showGroups;

window.openPrivateChat = openPrivateChat;
window.openGroup       = openGroup;

window.openCreateGroup  = openCreateGroup;
window.closeCreateGroup = closeCreateGroup;
window.createGroup      = guardedCreateGroup;

window.joinGroup = joinGroup;

window.openGroupInfo  = openGroupInfo;
window.closeGroupInfo = closeGroupInfo;

window.addSelectedMember  = guardedAddMember;
window.removeGroupMember  = removeGroupMember;

window.leaveGroup = guardedLeaveGroup;
window.logout     = guardedLogout;
window.refreshData = refreshData;