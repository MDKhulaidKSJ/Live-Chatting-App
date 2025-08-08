/**
 * عالمی معیار کی چیٹ ایپ - مین اسکرپٹ (app.js)
 * مصنف: (محمد خلید قاسمی کاسگنجوی)
 * ورژن: 1.0.0
 * تفصیل: ایک جدید، ماڈیولر، اور فیچر سے بھرپور چیٹ ایپلیکیشن کے لیے جاوا اسکرپٹ منطق۔
 */

// سخت موڈ کا استعمال تاکہ عام غلطیوں سے بچا جا سکے۔
'use strict';

// Firebase SDKs اور DOMPurify کو امپورٹ کریں۔
import { initializeApp } from "https://www.gstatic.com/firebasejs/11.6.1/firebase-app.js";
import { getAuth, signInWithCustomToken, onAuthStateChanged } from "https://www.gstatic.com/firebasejs/11.6.1/firebase-auth.js";
import { getFirestore, collection, addDoc, query, orderBy, onSnapshot, serverTimestamp, doc, updateDoc, getDoc } from "https://www.gstatic.com/firebasejs/11.6.1/firebase-firestore.js";
import DOMPurify from 'https://cdn.jsdelivr.net/npm/dompurify@2.3.6/dist/purify.es.min.js';

// گلوبل Firebase کنفیگریشن ویری ایبلز (Netlify Environment Variables سے)
// نوٹ: FIREBASE_CONFIG اور FIREBASE_SERVICE_ACCOUNT Netlify میں سیٹ کیے گئے ہیں۔
const appId = typeof __app_id !== 'undefined' ? __app_id : 'default-app-id';
const firebaseConfig = typeof FIREBASE_CONFIG !== 'undefined' ? JSON.parse(FIREBASE_CONFIG) : {};

// Firebase سروس انسٹینسز
let db;
let auth;

/**
 * --- 1. یوٹیلیٹی فنکشنز ---
 * یہ مددگار فنکشنز ہیں جو پوری ایپلیکیشن میں استعمال ہوں گے۔
 */
const utils = {
    /**
     * ایک فنکشن کی کال کو کچھ تاخیر کے ساتھ انجام دیتا ہے (Debouncing)۔
     * کارکردگی کو بہتر بنانے کے لیے استعمال ہوتا ہے، جیسے ٹائپنگ انڈیکیٹر۔
     * @param {Function} func - چلایا جانے والا فنکشن۔
     * @param {number} delay - ملی سیکنڈ میں تاخیر۔
     * @returns {Function} ڈیباؤنس شدہ فنکشن۔
     */
    debounce(func, delay = 300) {
        let timeoutId;
        return (...args) => {
            clearTimeout(timeoutId);
            timeoutId = setTimeout(() => {
                func.apply(this, args);
            }, delay);
        };
    },

    /**
     * ٹائم اسٹیمپ کو صارف دوست فارمیٹ میں تبدیل کرتا ہے۔
     * @param {Date|firebase.firestore.Timestamp} timestamp - تاریخ یا فائر سٹور ٹائم اسٹیمپ آبجیکٹ۔
     * @returns {string} فارمیٹ شدہ وقت۔
     */
    formatTimestamp(timestamp) {
        let date;
        if (timestamp && typeof timestamp.toDate === 'function') {
            date = timestamp.toDate();
        } else if (timestamp instanceof Date) {
            date = timestamp;
        } else {
            return '';
        }
        return date.toLocaleTimeString('ur-PK', { hour: 'numeric', minute: '2-digit', hour12: true });
    },

    /**
     * کسٹم ٹوسٹ نوٹیفیکیشن دکھاتا ہے۔
     * @param {string} message - دکھانے کے لیے پیغام۔
     * @param {'success'|'error'|'info'} type - پیغام کی قسم (سٹائلنگ کے لیے)۔
     */
    showToast(message, type = 'info') {
        const toastContainer = document.getElementById('toast-container');
        if (!toastContainer) {
            console.warn('Toast container نہیں ملا۔ پیغام: ' + message);
            return;
        }

        const toast = document.createElement('div');
        toast.className = `toast toast--${type}`;
        toast.innerHTML = `<p>${sanitizeInput(message)}</p>`; // پیغام کو سینیٹائز کریں
        toastContainer.appendChild(toast);

        // کچھ دیر بعد ٹوسٹ کو ہٹا دیں۔
        setTimeout(() => {
            toast.classList.add('fade-out');
            toast.addEventListener('animationend', () => toast.remove());
        }, 3000); // 3 سیکنڈ بعد فیڈ آؤٹ کریں۔
    }
};

/**
 * XSS حملوں کو روکنے کے لیے ایک سٹرنگ کو سینیٹائز کرتا ہے۔
 * @param {string} dirtyString - سینیٹائز کرنے کے لیے سٹرنگ۔
 * @returns {string} سینیٹائز شدہ سٹرنگ۔
 */
function sanitizeInput(dirtyString) {
    return DOMPurify.sanitize(dirtyString, { USE_PROFILES: { html: true } });
}

/**
 * --- 2. اسٹیٹ مینیجر ---
 * یہ کلاس ایپلیکیشن کی تمام حالتوں (state) کو ایک جگہ پر منظم کرتی ہے۔
 */
class StateManager {
    constructor() {
        this.currentUser = null;
        this.activeChatId = null;
        this.chats = new Map(); // چیٹ آئی ڈی کے لحاظ سے چیٹس کو منظم کرنا
        this.onlineUsers = new Map(); // آن لائن صارفین کی فہرست
        this.typingUsers = new Map(); // ٹائپ کرنے والے صارفین کی فہرست
    }

    setCurrentUser(user) { this.currentUser = user; }
    setActiveChat(chatId) { this.activeChatId = chatId; }
    addChat(chat) { this.chats.set(chat.id, chat); }
    getChat(chatId) { return this.chats.get(chatId); }

    addMessage(chatId, message) {
        if (this.chats.has(chatId)) {
            const chat = this.chats.get(chatId);
            if (!chat.messages) chat.messages = [];
            chat.messages.push(message);
        }
    }

    setOnlineUsers(usersArray) {
        this.onlineUsers.clear();
        usersArray.forEach(user => this.onlineUsers.set(user.id, user));
    }

    setTypingStatus(chatId, userId, isTyping) {
        if (!this.typingUsers.has(chatId)) {
            this.typingUsers.set(chatId, new Map());
        }
        const chatTypingUsers = this.typingUsers.get(chatId);
        if (isTyping) {
            chatTypingUsers.set(userId, true);
        } else {
            chatTypingUsers.delete(userId);
        }
    }

    getTypingUsersForChat(chatId) {
        return this.typingUsers.get(chatId) || new Map();
    }
}

/**
 * --- 3. فائر بیس سروس (ڈیٹا لیئر) ---
 * یہ کلاس فائر بیس کے ساتھ تمام مواصلات کو سنبھالتی ہے۔
 */
class FirebaseService {
    constructor(dbInstance, authInstance) {
        this.db = dbInstance;
        this.auth = authInstance;
    }

    /**
     * کسٹم ٹوکن کے ذریعے صارف کی تصدیق کرتا ہے۔
     * @returns {Promise<Object>} صارف کا آبجیکٹ (id, name)۔
     */
    async authenticateUser() {
        try {
            // Netlify Function کو کال کریں جو کسٹم ٹوکن بنائے گا
            const tokenResponse = await fetch('/.netlify/functions/create-custom-token');
            if (!tokenResponse.ok) {
                throw new Error(`HTTP error! status: ${tokenResponse.status}`);
            }
            const { token } = await tokenResponse.json();
            
            const userCredential = await signInWithCustomToken(this.auth, token);
            const user = userCredential.user;
            // ایک سادہ صارف نام بنائیں
            const userName = `User-${user.uid.substring(0, 8)}`;
            
            // آن لائن صارفین کی فہرست میں صارف کو شامل/اپ ڈیٹ کریں۔
            const onlineUsersRef = doc(this.db, `artifacts/${appId}/public/data/onlineUsers`, user.uid);
            await setDoc(onlineUsersRef, {
                id: user.uid,
                name: userName,
                lastSeen: serverTimestamp(),
                status: 'online',
                avatar: `https://i.pravatar.cc/150?u=${user.uid}` // پلیس ہولڈر اوتار
            }, { merge: true }); // اگر موجود ہو تو اپ ڈیٹ کریں، ورنہ بنائیں

            return { id: user.uid, name: userName, avatar: `https://i.pravatar.cc/150?u=${user.uid}` };
        } catch (error) {
            console.error("تصدیق میں خرابی:", error);
            throw new Error('صارف کی تصدیق میں ناکام رہا۔');
        }
    }

    /**
     * چیٹ کی فہرست کو ریئل ٹائم میں سنتا ہے۔
     * @param {string} userId - موجودہ صارف کی ID۔
     * @param {Function} onChatsUpdate - جب چیٹس اپ ڈیٹ ہوں تو کال بیک فنکشن۔
     * @returns {Function} ان سبسکرائب فنکشن۔
     */
    listenToChatList(userId, onChatsUpdate) {
        // یہ ایک سادہ مثال ہے، حقیقی ایپ میں چیٹ کی فہرست صارف کے تعلقات پر مبنی ہوگی۔
        const chatsCollectionRef = collection(this.db, `artifacts/${appId}/public/data/chats`);
        const q = query(chatsCollectionRef, orderBy('lastMessageTimestamp', 'desc'));

        return onSnapshot(q, (snapshot) => {
            const chats = snapshot.docs.map(doc => {
                const data = doc.data();
                return {
                    id: doc.id,
                    ...data,
                    lastMessageTimestamp: data.lastMessageTimestamp ? data.lastMessageTimestamp.toDate() : null,
                    // یہاں صارفین کی معلومات کو شامل کرنے کے لیے مزید لاجک آئے گا
                    users: [{ id: 'user_mock', name: data.name || 'نامعلوم چیٹ', avatar: data.avatar || 'https://placehold.co/100x100/aabbcc/ffffff?text=C' }]
                };
            });
            onChatsUpdate(chats);
        }, (error) => {
            console.error("چیٹ کی فہرست سننے میں خرابی:", error);
            utils.showToast('چیٹ کی فہرست لوڈ کرنے میں ناکام رہا۔', 'error');
        });
    }

    /**
     * کسی خاص چیٹ کے پیغامات کو ریئل ٹائم میں سنتا ہے۔
     * @param {string} chatId - چیٹ کی ID۔
     * @param {Function} onNewMessage - جب نیا پیغام آئے تو کال بیک فنکشن۔
     * @returns {Function} ان سبسکرائب فنکشن۔
     */
    listenToMessages(chatId, onNewMessage) {
        const messagesCollectionRef = collection(this.db, `artifacts/${appId}/public/data/messages`);
        const q = query(messagesCollectionRef, orderBy('timestamp'));
        
        return onSnapshot(q, (snapshot) => {
            snapshot.docChanges().forEach((change) => {
                if (change.type === 'added') {
                    onNewMessage(change.doc.data());
                }
            });
        }, (error) => {
            console.error("پیغامات سننے میں خرابی:", error);
            utils.showToast('پیغامات لوڈ کرنے میں ناکام رہا۔', 'error');
        });
    }

    /**
     * ایک نیا پیغام بھیجتا ہے۔
     * @param {string} chatId - چیٹ کی ID۔
     * @param {Object} messageData - پیغام کا ڈیٹا۔
     * @returns {Promise<void>}
     */
    async sendMessage(chatId, messageData) {
        try {
            const messagesCollectionRef = collection(this.db, `artifacts/${appId}/public/data/messages`);
            const docRef = await addDoc(messagesCollectionRef, {
                ...messageData,
                chatId: chatId, // پیغام کو چیٹ سے منسلک کریں
                timestamp: serverTimestamp()
            });
            // چیٹ کی آخری پیغام کی ٹائم سٹیمپ اپ ڈیٹ کریں۔
            const chatRef = doc(this.db, `artifacts/${appId}/public/data/chats`, chatId);
            await updateDoc(chatRef, {
                lastMessage: messageData.messageText,
                lastMessageTimestamp: serverTimestamp()
            });
            return docRef;
        } catch (error) {
            console.error("پیغام بھیجنے میں خرابی:", error);
            throw new Error('پیغام بھیجنے میں ناکام رہا۔');
        }
    }
    
    /**
     * فائل کو Firebase Storage پر اپ لوڈ کرتا ہے۔ (فی الحال نقلی)
     * @param {File} file - اپ لوڈ کرنے کے لیے فائل۔
     * @returns {Promise<Object>} فائل کا URL اور نام۔
     */
    async uploadFile(file) {
        // یہاں Firebase Storage کا استعمال کرتے ہوئے حقیقی فائل اپ لوڈ کریں۔
        // یہ صرف ایک نقلی امپلیمنٹیشن ہے۔
        return new Promise(resolve => {
            utils.showToast(`فائل اپ لوڈ ہو رہی ہے: ${file.name}`, 'info');
            setTimeout(() => {
                resolve({ 
                    url: 'https://images.unsplash.com/photo-1558655146-d09347e92766?w=400', // نقلی URL
                    name: file.name,
                    type: file.type 
                });
            }, 2000);
        });
    }

    /**
     * آن لائن صارفین کی فہرست کو ریئل ٹائم میں سنتا ہے۔
     * @param {Function} onUsersUpdate - جب صارفین کی فہرست اپ ڈیٹ ہو تو کال بیک فنکشن۔
     * @returns {Function} ان سبسکرائب فنکشن۔
     */
    listenToOnlineUsers(onUsersUpdate) {
        const onlineUsersCollectionRef = collection(this.db, `artifacts/${appId}/public/data/onlineUsers`);
        const q = query(onlineUsersCollectionRef, orderBy('lastSeen', 'desc'));

        return onSnapshot(q, (snapshot) => {
            const users = snapshot.docs.map(doc => doc.data());
            onUsersUpdate(users);
        }, (error) => {
            console.error("آن لائن صارفین سننے میں خرابی:", error);
            utils.showToast('آن لائن صارفین لوڈ کرنے میں ناکام رہا۔', 'error');
        });
    }

    /**
     * صارف کے ٹائپنگ اسٹیٹس کو اپ ڈیٹ کرتا ہے۔
     * @param {string} chatId - چیٹ کی ID۔
     * @param {string} userId - صارف کی ID۔
     * @param {boolean} isTyping - ٹائپ کر رہا ہے یا نہیں۔
     */
    async updateTypingStatus(chatId, userId, isTyping) {
        const typingStatusRef = doc(this.db, `artifacts/${appId}/public/data/typingStatus`, chatId);
        try {
            const docSnap = await getDoc(typingStatusRef);
            let typers = docSnap.exists() ? docSnap.data().typers || {} : {};

            if (isTyping) {
                typers[userId] = true;
            } else {
                delete typers[userId];
            }
            await setDoc(typingStatusRef, { typers: typers }, { merge: true });
        } catch (error) {
            console.error("ٹائپنگ اسٹیٹس اپ ڈیٹ کرنے میں خرابی:", error);
        }
    }

    /**
     * ٹائپنگ اسٹیٹس کو ریئل ٹائم میں سنتا ہے۔
     * @param {string} chatId - چیٹ کی ID۔
     * @param {Function} onTypingUpdate - جب ٹائپنگ اسٹیٹس اپ ڈیٹ ہو تو کال بیک فنکشن۔
     * @returns {Function} ان سبسکرائب فنکشن۔
     */
    listenToTypingStatus(chatId, onTypingUpdate) {
        const typingStatusRef = doc(this.db, `artifacts/${appId}/public/data/typingStatus`, chatId);
        return onSnapshot(typingStatusRef, (docSnap) => {
            const data = docSnap.data();
            onTypingUpdate(data ? data.typers : {});
        }, (error) => {
            console.error("ٹائپنگ اسٹیٹس سننے میں خرابی:", error);
        });
    }
}

/**
 * --- 4. UI کنٹرولر (ویو لیئر) ---
 * یہ کلاس تمام DOM مینیپولیشن اور UI اپ ڈیٹس کو سنبھالتی ہے۔
 */
class UIController {
    constructor() {
        this.cacheDOMElements();
        this.theme = localStorage.getItem('chat-theme') || 'light';
        this.applyTheme();
    }

    cacheDOMElements() {
        // تمام ضروری DOM عناصر کو کیش کیا جاتا ہے۔
        this.chatApp = document.getElementById('chat-app');
        this.sidebar = document.getElementById('sidebar');
        this.chatList = document.getElementById('chat-list');
        this.chatMessagesDisplay = document.getElementById('chat-messages-display');
        this.messageForm = document.getElementById('message-form');
        this.messageInput = document.getElementById('message-input');
        this.sendButton = document.getElementById('send-message-btn');
        this.settingsModal = document.getElementById('settings-modal');
        this.themeSwitcher = document.getElementById('theme-switcher');
        this.fileInput = document.getElementById('file-input');
        this.filePreview = document.getElementById('file-preview');
        this.filePreviewName = document.getElementById('file-preview-name');
        this.removeFilePreviewBtn = document.getElementById('remove-file-preview');
        this.typingIndicator = document.getElementById('typing-indicator');
        this.typingUsername = document.getElementById('typing-username');
        this.toastContainer = document.getElementById('toast-container'); // ٹوسٹ کنٹینر

        // نئے UI عناصر
        this.sidebarToggleButton = document.getElementById('sidebar-toggle-button');
        this.settingsToggleButton = document.getElementById('settings-toggle');
        this.settingsCloseButton = document.getElementById('settings-close-btn');
        this.attachFileButton = document.getElementById('attach-file-btn');
        this.emojiButton = document.getElementById('emoji-btn');
        this.chatHeaderAvatar = document.getElementById('chat-header-avatar');
        this.chatHeaderName = document.getElementById('chat-header-name');
        this.chatHeaderStatus = document.getElementById('chat-header-status');
        this.onlineUsersList = document.getElementById('users-online-list'); // آن لائن صارفین کی فہرست
    }

    /**
     * چیٹ کی فہرست کو UI میں رینڈر کرتا ہے۔
     * @param {Array<Object>} chats - چیٹ آبجیکٹس کی فہرست۔
     * @param {string} activeChatId - فعال چیٹ کی ID۔
     */
    renderChatList(chats, activeChatId) {
        this.chatList.innerHTML = ''; // پرانی فہرست کو صاف کریں۔
        if (chats.length === 0) {
            this.chatList.innerHTML = '<li class="chat-list__item" style="justify-content:center; cursor:default; border-bottom:none;"><p style="color:var(--text-light);">کوئی چیٹ نہیں ملی۔</p></li>';
            return;
        }

        chats.forEach(chat => {
            const user = chat.users[0]; // فرض کریں کہ یہ 1-on-1 چیٹ ہے
            const isActive = chat.id === activeChatId ? 'chat-list__item--active' : '';
            const lastMessageTime = chat.lastMessageTimestamp ? utils.formatTimestamp(chat.lastMessageTimestamp) : '';

            const chatItem = `
                <li class="chat-list__item ${isActive}" data-chat-id="${chat.id}" tabindex="0">
                    <img src="${sanitizeInput(user.avatar)}" alt="${sanitizeInput(user.name)} کا پروفائل امیج" class="chat-list__avatar" onerror="this.onerror=null;this.src='https://placehold.co/100x100/aabbcc/ffffff?text=User';">
                    <div class="chat-list__details">
                        <h3 class="chat-list__name">${sanitizeInput(user.name)}</h3>
                        <p class="chat-list__last-message">${sanitizeInput(chat.lastMessage || 'کوئی پیغام نہیں')}</p>
                    </div>
                    <div class="chat-list__meta">
                        <time class="chat-list__timestamp" datetime="${chat.lastMessageTimestamp ? chat.lastMessageTimestamp.toISOString() : ''}">${lastMessageTime}</time>
                        ${chat.unreadCount > 0 ? `<span class="chat-list__unread-count" aria-label="${chat.unreadCount} غیر پڑھے ہوئے پیغامات">${chat.unreadCount}</span>` : ''}
                    </div>
                </li>`;
            this.chatList.insertAdjacentHTML('beforeend', chatItem);
        });
    }

    /**
     * ایک پیغام کو چیٹ ڈسپلے میں رینڈر کرتا ہے۔
     * @param {Object} message - پیغام کا آبجیکٹ۔
     * @param {Object} currentUser - موجودہ صارف کا آبجیکٹ۔
     */
    renderMessage(message, currentUser) {
        const isOutgoing = message.senderId === currentUser.id;
        const messageClass = isOutgoing ? 'message--outgoing' : 'message--incoming';
        const senderName = isOutgoing ? 'آپ' : message.senderName;
        const timestamp = message.timestamp ? utils.formatTimestamp(message.timestamp) : '';
        const messageContent = message.messageText ? sanitizeInput(message.messageText) : '';
        const fileAttachmentHTML = message.fileUrl ? `<img src="${sanitizeInput(message.fileUrl.url)}" alt="${sanitizeInput(message.fileUrl.name)}" class="message__image-attachment">` : '';

        const messageHTML = `
            <article class="message ${messageClass}" data-message-id="${message.id}" aria-labelledby="msg-${message.id}-sender">
                ${!isOutgoing ? `<img src="https://i.pravatar.cc/150?u=${message.senderId}" alt="${sanitizeInput(senderName)} کا پروفائل امیج" class="message__avatar" onerror="this.onerror=null;this.src='https://placehold.co/100x100/aabbcc/ffffff?text=User';">` : ''}
                <div class="message__body">
                    <div class="message__header">
                        <span class="message__sender-name" id="msg-${message.id}-sender">${sanitizeInput(senderName)}</span>
                        <time class="message__timestamp" datetime="${message.timestamp ? message.timestamp.toDate().toISOString() : ''}">${timestamp}</time>
                    </div>
                    <div class="message__content">
                        ${messageContent ? `<p>${messageContent}</p>` : ''}
                        ${fileAttachmentHTML}
                    </div>
                    ${isOutgoing ? `<div class="message__footer"><span class="message__status" aria-label="پہنچ گیا"><svg width="16" height="16"><use href="#icon-check"></use></svg></span></div>` : ''}
                </div>
            </article>`;
        
        this.chatMessagesDisplay.insertAdjacentHTML('beforeend', messageHTML);
        this.scrollToBottom();
    }

    /**
     * آن لائن صارفین کی فہرست کو UI میں رینڈر کرتا ہے۔
     * @param {Array<Object>} users - آن لائن صارفین کی فہرست۔
     * @param {string} currentUserId - موجودہ صارف کی ID۔
     */
    renderOnlineUsers(users, currentUserId) {
        this.onlineUsersList.innerHTML = '';
        users.forEach(user => {
            if (user.id === currentUserId) return; // موجودہ صارف کو فہرست سے ہٹائیں
            const userItem = `
                <li role="listitem" class="ltr-text">
                    <img src="${sanitizeInput(user.avatar)}" alt="${sanitizeInput(user.name)} کا پروفائل امیج" style="width:24px; height:24px; border-radius:50%; margin-left:8px;" onerror="this.onerror=null;this.src='https://placehold.co/24x24/aabbcc/ffffff?text=U';">
                    ${sanitizeInput(user.name)}
                    <span style="width:8px; height:8px; border-radius:50%; background-color:var(--success-color); margin-right:8px;"></span>
                </li>`;
            this.onlineUsersList.insertAdjacentHTML('beforeend', userItem);
        });
    }

    /**
     * چیٹ ہیڈر کی معلومات کو اپ ڈیٹ کرتا ہے۔
     * @param {Object} chatInfo - چیٹ کی معلومات (نام، اوتار، اسٹیٹس)۔
     */
    updateChatHeader(chatInfo) {
        this.chatHeaderAvatar.src = sanitizeInput(chatInfo.avatar || 'https://placehold.co/100x100/aabbcc/ffffff?text=User');
        this.chatHeaderAvatar.alt = sanitizeInput(chatInfo.name + ' کا پروفائل امیج');
        this.chatHeaderName.textContent = sanitizeInput(chatInfo.name);
        this.chatHeaderStatus.textContent = sanitizeInput(chatInfo.status || 'آف لائن');
        this.chatHeaderStatus.className = `chat-header__status chat-header__status--${chatInfo.status || 'offline'}`;
    }

    /**
     * ماڈل کو دکھاتا یا چھپاتا ہے۔
     * @param {string} modalId - ماڈل کی ID۔
     * @param {boolean} show - دکھانے کے لیے صحیح، چھپانے کے لیے غلط۔
     */
    toggleModal(modalId, show) {
        const modal = document.getElementById(modalId);
        if(modal) {
            modal.hidden = !show;
            if (show) {
                modal.focus(); // ماڈل پر فوکس کریں
                // اگر ماڈل میں کوئی کلوز بٹن ہے تو اس پر فوکس کریں
                const closeBtn = modal.querySelector('.modal__close-btn');
                if (closeBtn) closeBtn.focus();
            }
        }
    }

    /**
     * تھیم کو لاگو کرتا ہے۔
     */
    applyTheme() {
        document.documentElement.setAttribute('data-theme', this.theme);
        if(this.themeSwitcher) this.themeSwitcher.value = this.theme;
        localStorage.setItem('chat-theme', this.theme);
    }
    
    /**
     * تھیم سیٹ کرتا ہے۔
     * @param {string} themeName - تھیم کا نام ('light' یا 'dark')۔
     */
    setTheme(themeName) {
        this.theme = themeName;
        this.applyTheme();
    }
    
    /**
     * ان پٹ فیلڈ کو صاف کرتا ہے اور فائل کے پیش نظارہ کو چھپاتا ہے۔
     */
    clearInput() {
        this.messageInput.innerHTML = '';
        this.filePreview.hidden = true;
    }
    
    /**
     * فائل کے پیش نظارہ کو دکھاتا ہے۔
     * @param {string} fileName - فائل کا نام۔
     */
    showFilePreview(fileName) {
        this.filePreviewName.textContent = sanitizeInput(fileName);
        this.filePreview.hidden = false;
    }

    /**
     * ٹائپنگ انڈیکیٹر کو اپ ڈیٹ کرتا ہے۔
     * @param {Map<string, boolean>} typingUsersMap - ٹائپ کرنے والے صارفین کی Map۔
     * @param {Object} currentUser - موجودہ صارف۔
     */
    updateTypingIndicator(typingUsersMap, currentUser) {
        const typers = Array.from(typingUsersMap.keys()).filter(id => id !== currentUser.id);
        if (typers.length === 0) {
            this.typingIndicator.hidden = true;
            return;
        }
        
        // یہاں آپ کو صارفین کے ID سے ان کے نام حاصل کرنے کے لیے ایک لاجک کی ضرورت ہوگی۔
        // فی الحال، صرف ID دکھائیں۔
        const names = typers.map(id => `User-${id.substring(0,4)}`).join(', ');
        this.typingUsername.textContent = names;
        this.typingIndicator.hidden = false;
    }

    /**
     * چیٹ ڈسپلے کو سب سے نیچے تک اسکرول کرتا ہے۔
     */
    scrollToBottom() {
        this.chatMessagesDisplay.scrollTop = this.chatMessagesDisplay.scrollHeight;
    }
}

/**
 * --- 5. مین ایپلیکیشن (آرکسٹریٹر) ---
 * یہ کلاس تمام ماڈیولز کو ایک ساتھ جوڑتی ہے اور ایپلیکیشن کی منطق کو چلاتی ہے۔
 */
class App {
    constructor() {
        this.state = new StateManager();
        this.ui = new UIController();
        // Firebase سروس کو db اور auth انسٹینسز کے ساتھ انیشلائز کریں۔
        this.firebaseService = new FirebaseService(db, auth);
        this.selectedFile = null; // منتخب کردہ فائل کو ذخیرہ کرنے کے لیے

        this.debouncedTypingStatusUpdate = utils.debounce(this.updateTypingStatusInFirebase.bind(this), 1000);
    }

    /**
     * ایپلیکیشن کو شروع کرتا ہے۔
     */
    async init() {
        console.log("ایپلیکیشن شروع ہو رہی ہے...");
        this.bindEvents();
        // UI کو ابتدائی طور پر چھپائیں جب تک صارف تصدیق نہ ہو جائے۔
        this.ui.chatApp.style.display = 'none'; 
        document.getElementById('loading-indicator').style.display = 'block';

        // Firebase Authentication کا کام initializeFirebaseAndApp میں ہوتا ہے۔
        // یہ فنکشن onAuthStateChanged کال بیک کے ذریعے handleChatSetup کو ٹریگر کرے گا۔
    }

    /**
     * تمام UI ایونٹ لسنرز کو بائنڈ کرتا ہے۔
     */
    bindEvents() {
        this.ui.messageForm.addEventListener('submit', this.handleMessageSend.bind(this));
        
        if(this.ui.themeSwitcher) {
            this.ui.themeSwitcher.addEventListener('change', (e) => this.ui.setTheme(e.target.value));
        }

        this.ui.settingsToggleButton.addEventListener('click', () => this.ui.toggleModal('settings-modal', true));
        this.ui.settingsCloseButton.addEventListener('click', () => this.ui.toggleModal('settings-modal', false));
        
        this.ui.attachFileButton.addEventListener('click', () => this.ui.fileInput.click());
        this.ui.fileInput.addEventListener('change', this.handleFileSelection.bind(this));
        this.ui.removeFilePreviewBtn.addEventListener('click', this.handleFileRemoval.bind(this));
        
        this.ui.emojiButton.addEventListener('click', () => utils.showToast('ایموجی پکر (جلد آ رہا ہے!)', 'info'));
        
        // سائیڈبار ٹوگل بٹن
        this.ui.sidebarToggleButton.addEventListener('click', () => {
            this.ui.sidebar.classList.toggle('chat-app__sidebar--open');
            // موبائل پر چیٹ ایریا کو بھی ٹوگل کریں
            if (window.innerWidth <= 992) {
                this.ui.chatApp.classList.toggle('chat-app--list-view');
                this.ui.chatApp.classList.toggle('chat-app--thread-view');
            }
        });

        // ٹائپنگ اسٹیٹس اپ ڈیٹ
        this.ui.messageInput.addEventListener('input', this.handleTyping.bind(this));
    }

    /**
     * صارف کی تصدیق کے بعد چیٹ سیٹ اپ کرتا ہے۔
     * @param {Object} user - تصدیق شدہ صارف کا آبجیکٹ۔
     */
    handleChatSetup(user) {
        this.state.setCurrentUser(user);
        
        // آن لائن صارفین کی فہرست سنیں۔
        this.firebaseService.listenToOnlineUsers((onlineUsers) => {
            this.state.setOnlineUsers(onlineUsers);
            this.ui.renderOnlineUsers(Array.from(this.state.onlineUsers.values()), this.state.currentUser.id);
        });

        // چیٹ کی فہرست حاصل کریں اور سنیں۔
        this.firebaseService.listenToChatList(user.id, (chats) => {
            chats.forEach(chat => this.state.addChat(chat));
            // فی الحال، پہلی چیٹ کو فعال چیٹ کے طور پر سیٹ کریں۔
            if (chats.length > 0 && !this.state.activeChatId) {
                this.setActiveChat(chats[0].id);
            }
            this.ui.renderChatList(Array.from(this.state.chats.values()), this.state.activeChatId);
        });
        
        // UI کو ظاہر کریں
        document.getElementById('loading-indicator').style.display = 'none';
        this.ui.chatApp.style.display = 'grid'; // Grid لے آؤٹ ظاہر کریں
        utils.showToast(`چیٹ میں خوش آمدید، ${this.state.currentUser.name}!`, 'success');
        this.ui.messageInput.focus();
    }

    /**
     * فعال چیٹ سیٹ کرتا ہے اور پیغامات سننا شروع کرتا ہے۔
     * @param {string} chatId - فعال چیٹ کی ID۔
     */
    setActiveChat(chatId) {
        if (this.state.activeChatId === chatId) return;

        // اگر پہلے سے کوئی لسنر ہے تو اسے ان سبسکرائب کریں۔
        if (this.messageUnsubscribe) this.messageUnsubscribe();
        if (this.typingUnsubscribe) this.typingUnsubscribe();

        this.state.setActiveChat(chatId);
        const activeChatInfo = this.state.getChat(chatId);
        if (activeChatInfo) {
            // چیٹ ہیڈر کو اپ ڈیٹ کریں۔
            this.ui.updateChatHeader({
                name: activeChatInfo.users[0].name,
                avatar: activeChatInfo.users[0].avatar,
                status: 'online' // یا حقیقی اسٹیٹس لوڈ کریں
            });
            // چیٹ پیغامات ڈسپلے کو صاف کریں۔
            this.ui.chatMessagesDisplay.innerHTML = '';
            // پیغامات سننا شروع کریں۔
            this.messageUnsubscribe = this.firebaseService.listenToMessages(chatId, (message) => {
                this.state.addMessage(chatId, message);
                this.ui.renderMessage(message, this.state.currentUser);
            });
            // ٹائپنگ اسٹیٹس سننا شروع کریں۔
            this.typingUnsubscribe = this.firebaseService.listenToTypingStatus(chatId, (typers) => {
                const typingUsersMap = new Map(Object.entries(typers));
                this.ui.updateTypingIndicator(typingUsersMap, this.state.currentUser);
            });
        }
    }

    /**
     * پیغام بھیجنے کو ہینڈل کرتا ہے۔
     * @param {Event} e - سبمٹ ایونٹ۔
     */
    async handleMessageSend(e) {
        e.preventDefault();
        const content = this.ui.messageInput.innerText.trim();
        if (!content && !this.selectedFile) return;
        if (!this.state.currentUser || !this.state.activeChatId) {
            utils.showToast('چیٹ منتخب کریں یا لاگ ان کریں۔', 'info');
            return;
        }
        
        this.ui.sendButton.disabled = true;

        try {
            let fileAttachment = null;
            if (this.selectedFile) {
                fileAttachment = await this.firebaseService.uploadFile(this.selectedFile);
            }

            const messageData = {
                senderId: this.state.currentUser.id,
                senderName: this.state.currentUser.name,
                messageText: content,
                fileUrl: fileAttachment, // فائل کا URL شامل کریں
            };

            await this.firebaseService.sendMessage(this.state.activeChatId, messageData);
            this.ui.clearInput();
            this.selectedFile = null; // فائل کو صاف کریں
            utils.showToast('پیغام بھیجا گیا!', 'success');
            // ٹائپنگ اسٹیٹس کو بھی ری سیٹ کریں
            await this.firebaseService.updateTypingStatus(this.state.activeChatId, this.state.currentUser.id, false);
        } catch (error) {
            utils.showToast(error.message || 'پیغام بھیجنے میں ناکام رہا۔', 'error');
        } finally {
            this.ui.sendButton.disabled = false;
        }
    }
    
    /**
     * فائل کے انتخاب کو ہینڈل کرتا ہے۔
     * @param {Event} e - چینج ایونٹ۔
     */
    handleFileSelection(e) {
        const files = e.target.files;
        if (files.length > 0) {
            this.selectedFile = files[0];
            this.ui.showFilePreview(this.selectedFile.name);
            this.ui.messageInput.focus(); // ان پٹ پر فوکس رکھیں
        }
    }

    /**
     * فائل کے پیش نظارہ کو ہٹاتا ہے۔
     */
    handleFileRemoval() {
        this.selectedFile = null;
        this.ui.fileInput.value = ''; // فائل ان پٹ کو بھی صاف کریں
        this.ui.clearInput();
    }
    
    /**
     * صارف کے ٹائپ کرنے پر ٹائپنگ اسٹیٹس کو ہینڈل کرتا ہے۔
     */
    handleTyping() {
        if (!this.state.currentUser || !this.state.activeChatId) return;
        // ٹائپنگ اسٹیٹس کو Firebase میں اپ ڈیٹ کریں۔
        this.firebaseService.updateTypingStatus(this.state.activeChatId, this.state.currentUser.id, true);
        // ڈیباؤنسڈ فنکشن کو ٹریگر کریں تاکہ ٹائپنگ رکنے پر اسٹیٹس کو ری سیٹ کیا جا سکے۔
        this.debouncedTypingStatusUpdate();
    }
    
    /**
     * جب ٹائپنگ رک جائے تو Firebase میں ٹائپنگ اسٹیٹس کو اپ ڈیٹ کرتا ہے۔
     */
    async updateTypingStatusInFirebase() {
        if (!this.state.currentUser || !this.state.activeChatId) return;
        await this.firebaseService.updateTypingStatus(this.state.activeChatId, this.state.currentUser.id, false);
    }
}

// Firebase اور App کو انیشلائز کریں۔
async function initializeFirebaseAndApp() {
    try {
        const app = initializeApp(firebaseConfig);
        db = getFirestore(app);
        auth = getAuth(app);
        
        const mainApp = new App(); // App کلاس کا انسٹینس بنائیں
        mainApp.init(); // App کو انیشلائز کریں

        onAuthStateChanged(auth, async (user) => {
            if (user) {
                // اگر صارف موجود ہے تو چیٹ سیٹ اپ کریں
                mainApp.handleChatSetup({ id: user.uid, name: `User-${user.uid.substring(0,8)}` });
            } else {
                console.log('کوئی صارف سائن ان نہیں ہوا۔ کسٹم ٹوکن کے ساتھ سائن ان ہو رہا ہے...');
                try {
                    const tokenResponse = await fetch('/.netlify/functions/create-custom-token');
                    if (!tokenResponse.ok) {
                        throw new Error(`HTTP error! status: ${tokenResponse.status}`);
                    }
                    const { token } = await tokenResponse.json();
                    await signInWithCustomToken(auth, token);
                } catch (signInError) {
                    console.error("Custom token کے ساتھ سائن ان کرنے میں ناکام:", signInError);
                    document.getElementById('loading-indicator').innerHTML = '<p>چیٹ لوڈ نہیں ہو سکی۔ سائن ان میں خرابی۔</p>';
                    utils.showToast('چیٹ میں سائن ان کرنے میں ناکام رہا۔', 'error');
                }
            }
        });
    } catch (error) {
        console.error("Firebase شروع کرنے یا تصدیق کے دوران خرابی:", error);
        document.getElementById('loading-indicator').innerHTML = '<p>چیٹ لوڈ نہیں ہو سکی۔ براہ کرم دوبارہ کوشش کریں۔</p>';
        utils.showToast('چیٹ ایپلیکیشن شروع کرنے میں ناکام رہا۔', 'error');
    }
}

// جب DOM مکمل طور پر لوڈ ہو جائے تو ایپلیکیشن شروع کریں۔
document.addEventListener('DOMContentLoaded', initializeFirebaseAndApp);

