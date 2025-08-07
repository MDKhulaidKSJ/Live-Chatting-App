// Firebase Admin SDK کو امپورٹ کریں
const { initializeApp, cert } = require('firebase-admin/app');
const { getAuth } = require('firebase-admin/auth');

// Netlify Environment Variables سے Firebase Admin SDK کی خفیہ معلومات حاصل کریں
// یہ آپ نے Firebase console سے JSON فائل میں حاصل کی تھی
const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);

// Firebase Admin SDK کو انیشلائز کریں
initializeApp({
  credential: cert(serviceAccount)
});

exports.handler = async (event, context) => {
  try {
    // ایک گمنام صارف ID بنائیں (یہ آپ کی مرضی کے مطابق ہو سکتی ہے)
    const uid = 'user-' + Math.random().toString(36).substring(2, 15);
    
    // Custom Token بنائیں
    const customToken = await getAuth().createCustomToken(uid);

    return {
      statusCode: 200,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ token: customToken }),
    };
  } catch (error) {
    console.error('Error creating custom token:', error);
    return {
      statusCode: 500,
      body: JSON.stringify({ error: 'Failed to create custom token' }),
    };
  }
};
