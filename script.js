// script.js

// Firebase SDKs کو امپورٹ کریں
// یہ اسکرپٹ Firebase کے لیے ضروری ماڈیولز کو CDN سے لوڈ کرتا ہے۔
import { initializeApp } from "https://www.gstatic.com/firebasejs/11.6.1/firebase-app.js";
import { getAuth, signInWithCustomToken, onAuthStateChanged } from "https://www.gstatic.com/firebasejs/11.6.1/firebase-auth.js";
import { getFirestore, collection, addDoc, query, orderBy, onSnapshot, serverTimestamp } from "https://www.gstatic.com/firebasejs/11.6.1/firebase-firestore.js";
// DOMPurify کو امپورٹ کریں تاکہ XSS حملوں سے بچنے کے لیے صارف کے ان پٹ کو سینیٹائز کیا جا سکے۔
import DOMPurify from 'https://cdn.jsdelivr.net/npm/dompurify@2.3.6/dist/purify.es.min.js';

// گلوبل Firebase کنفیگریشن ویری ایبلز (ماحول کی طرف سے فراہم کردہ)
// یہ ویری ایبلز آپ کے Netlify ماحول سے خود بخود دستیاب ہوتے ہیں۔
const appId = typeof __app_id !== 'undefined' ? __app_id : 'default-app-id';
const firebaseConfig = typeof __firebase_config !== 'undefined' ? JSON.parse(__firebase_config) : {};

// Firebase سروس انسٹینسز
let db; // Firestore ڈیٹا بیس انسٹینس
let auth; // Authentication سروس انسٹینس
let currentUserId = null; // موجودہ لاگ ان شدہ صارف کی ID
let currentUserName = null; // موجودہ لاگ ان شدہ صارف کا نام (ڈسپلے کے لیے)

// DOM عناصر کے حوالہ جات حاصل کریں
// یہ وہ HTML عناصر ہیں جن کے ساتھ JavaScript تعامل کرے گا۔
const chatMessagesDisplay = document.getElementById('chat-messages-display');
const messageInput = document.getElementById('message-input');
const messageForm = document.getElementById('message-form');
const sendButton = document.getElementById('send-message-button'); // بھیجنے کے بٹن کا حوالہ
const userIdDisplay = document.getElementById('user-id');
const loadingIndicator = document.getElementById('loading-indicator');
const inputArea = document.querySelector('footer'); // فوٹر کو منتخب کریں جس میں ان پٹ اور بٹن شامل ہیں

// پیغام بھیجنے کے دوران لوڈنگ اسٹیٹ کے لیے ایک ویری ایبل
let isSendingMessage = false;

/**
 * چیٹ ڈسپلے ایریا کو سب سے نیچے تک اسکرول کرتا ہے۔
 * اس سے یہ یقینی ہوتا ہے کہ تازہ ترین پیغامات ہمیشہ نظر آتے ہیں۔
 */
function scrollToBottom() {
    chatMessagesDisplay.scrollTop = chatMessagesDisplay.scrollHeight;
}

/**
 * XSS حملوں کو روکنے کے لیے ایک سٹرنگ کو سینیٹائز کرتا ہے۔
 * مضبوط سینیٹائزیشن کے لیے DOMPurify کا استعمال کرتا ہے۔
 * @param {string} dirtyString - سینیٹائز کرنے کے لیے سٹرنگ۔
 * @returns {string} سینیٹائز شدہ سٹرنگ۔
 */
function sanitizeInput(dirtyString) {
    // DOMPurify.sanitize ایک صاف سٹرنگ واپس کرتا ہے۔
    return DOMPurify.sanitize(dirtyString, { USE_PROFILES: { html: true } });
}

/**
 * چیٹ پیغام کے لیے ایک HTML عنصر بناتا اور واپس کرتا ہے۔
 * پیغام کے آنے والے یا جانے والے ہونے کی بنیاد پر مناسب سٹائلنگ لاگو کرتا ہے۔
 * @param {string} senderName - بھیجنے والے کا نام۔
 * @param {string} messageText - پیغام کا مواد۔
 * @param {boolean} isOutgoing - اگر پیغام موجودہ صارف کی طرف سے ہے تو صحیح۔
 * @returns {HTMLElement} بنایا گیا پیغام عنصر۔
 */
function createMessageElement(senderName, messageText, isOutgoing) {
    const messageSection = document.createElement('section');
    messageSection.className = `message ${isOutgoing ? 'outgoing-message' : 'incoming-message'}`;

    const messageDiv = document.createElement('div');
    const senderNameSpan = document.createElement('strong');
    senderNameSpan.className = 'sender-name ltr-text';
    senderNameSpan.textContent = `${sanitizeInput(senderName)}:`;

    const messageContentP = document.createElement('p');
    messageContentP.className = 'message-content';
    messageContentP.innerHTML = sanitizeInput(messageText);

    messageDiv.appendChild(senderNameSpan);
    messageDiv.appendChild(messageContentP);
    messageSection.appendChild(messageDiv);

    return messageSection;
}

/**
 * Firestore سے پیغامات کے لیے ایک ریئل ٹائم لسنر سیٹ کرتا ہے۔
 */
function setupRealtimeListener() {
    if (!db) {
        console.error("Firestore شروع نہیں ہوا ہے۔ ریئل ٹائم لسنر سیٹ نہیں کیا جا سکتا۔");
        return;
    }

    const messagesCollectionRef = collection(db, `artifacts/${appId}/public/data/messages`);
    const q = query(messagesCollectionRef, orderBy('timestamp'));

    const unsubscribe = onSnapshot(q, (snapshot) => {
        snapshot.docChanges().forEach((change) => {
            if (change.type === 'added') {
                const messageData = change.doc.data();
                const isOutgoing = messageData.senderId === currentUserId;
                const displayedSenderName = isOutgoing ? 'آپ' : messageData.senderName;
                const messageElement = createMessageElement(displayedSenderName, messageData.messageText, isOutgoing);
                chatMessagesDisplay.appendChild(messageElement);
                scrollToBottom();
            }
        });
    }, (error) => {
        console.error("پیغامات سننے میں خرابی:", error);
    });

    return unsubscribe;
}

/**
 * ایک نئے پیغام کی جمع آوری کو ہینڈل کرتا ہے۔
 */
async function handleMessageSubmit(event) {
    event.preventDefault();

    if (isSendingMessage) {
        return;
    }

    const messageText = messageInput.value.trim();

    if (messageText === '' || !currentUserId || !currentUserName) {
        return;
    }

    isSendingMessage = true;
    sendButton.disabled = true;

    try {
        const messagesCollectionRef = collection(db, `artifacts/${appId}/public/data/messages`);
        await addDoc(messagesCollectionRef, {
            senderId: currentUserId,
            senderName: currentUserName,
            messageText: messageText,
            timestamp: serverTimestamp()
        });

        messageInput.value = '';
    } catch (error) {
        console.error("پیغام بھیجنے میں خرابی:", error);
    } finally {
        isSendingMessage = false;
        sendButton.disabled = false;
        messageInput.focus();
    }
}

/**
 * Firebase سروسز کو شروع کرتا ہے اور صارف کی تصدیق کو ہینڈل کرتا ہے۔
 */
async function initializeFirebase() {
    try {
        inputArea.style.display = 'none';
        loadingIndicator.style.display = 'block';

        const app = initializeApp(firebaseConfig);
        db = getFirestore(app);
        auth = getAuth(app);

        onAuthStateChanged(auth, async (user) => {
            if (user) {
                currentUserId = user.uid;
                currentUserName = `User-${currentUserId.substring(0, 8)}`;
                userIdDisplay.textContent = currentUserId;
                console.log('صارف تصدیق شدہ:', currentUserId);

                setupRealtimeListener();

                loadingIndicator.style.display = 'none';
                inputArea.style.display = 'flex';
                messageInput.focus();
            } else {
                console.log('کوئی صارف سائن ان نہیں ہوا۔ کسٹم ٹوکن کے ساتھ سائن ان ہو رہا ہے...');
                try {
                    // Netlify Function کو کال کریں جو کسٹم ٹوکن بنائے گا
                    const tokenResponse = await fetch('/.netlify/functions/create-custom-token');
                    if (!tokenResponse.ok) {
                        throw new Error('Failed to get custom token');
                    }
                    const { token } = await tokenResponse.json();
                    
                    // کسٹم ٹوکن کا استعمال کرتے ہوئے سائن ان کریں
                    await signInWithCustomToken(auth, token);
                } catch (signInError) {
                    console.error("Custom token کے ساتھ سائن ان کرنے میں ناکام:", signInError);
                    loadingIndicator.textContent = 'چیٹ لوڈ نہیں ہو سکی۔ سائن ان میں خرابی۔';
                    inputArea.style.display = 'none';
                }
            }
        });

    } catch (error) {
        console.error("Firebase شروع کرنے یا تصدیق کے دوران خرابی:", error);
        loadingIndicator.textContent = 'چیٹ لوڈ نہیں ہو سکی۔ براہ کرم دوبارہ کوشش کریں۔';
        inputArea.style.display = 'none';
    }
}

// ایونٹ لسنرز
messageForm.addEventListener('submit', handleMessageSubmit);

// جب ونڈو مکمل طور پر لوڈ ہو جائے تو Firebase کو شروع کریں۔
window.onload = initializeFirebase;