// server.js (or app.js)
require('dotenv').config(); // Load environment variables from .env file
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const axios = require('axios'); // For making HTTP requests to Paystack API
const crypto = require('crypto');
const admin = require('firebase-admin');

// --- Firebase Admin Initialization ---
// IMPORTANT: Create this file from your Firebase project settings
const serviceAccount = require('./serviceAccountKey.json');

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
}
const firestoreDb = admin.firestore();

const app = express();
const PORT = process.env.PORT || 5000;
const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY;
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5173';
const BACKEND_URL = process.env.BACKEND_URL || `http://localhost:${PORT}`; // For production, set this in your hosting environment

// Middleware
// Add your live frontend URL to the whitelist for production
const whitelist = ['http://localhost:5173', FRONTEND_URL];
const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    if (whitelist.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  }
};
app.use(cors(corsOptions));
app.use(bodyParser.json()); // To parse JSON request bodies

// --- API Endpoints ---

// 1. Endpoint to initialize a Paystack transaction
app.post('/api/paystack/initialize', async (req, res) => {
  const { amount, email, orderId, userId, cartItems, shippingInfo } = req.body; // Data sent from your React frontend

  if (!amount || !email || !orderId || !userId || !cartItems || !shippingInfo) {
    console.error('Missing required payment details:', { amount, email, orderId, userId, cartItems, shippingInfo });
    return res.status(400).json({ message: 'Missing required payment details. Ensure cart and shipping info are included.' });
  }

  try {
    // Convert amount to kobo (Paystack expects amount in smallest currency unit)
    const amountInKobo = Math.round(parseFloat(amount) * 100);

    const paystackResponse = await axios.post(
      'https://api.paystack.co/transaction/initialize',
      {
        email: email,
        amount: amountInKobo,
        currency: 'GHS', // Example: Ghanaian Cedis. Adjust as needed (e.g., NGN for Naira)
        callback_url: `${BACKEND_URL}/api/paystack/verify`, // Your backend's verification endpoint
        metadata: {
          order_id: orderId,
          user_id: userId,
          // Pass cart and shipping info in metadata so we can retrieve it in the verification step
          cart_items: JSON.stringify(cartItems),
          shipping_info: JSON.stringify(shippingInfo),
        },
      },
      {
        headers: {
          Authorization: `Bearer ${PAYSTACK_SECRET_KEY}`,
          'Content-Type': 'application/json',
        },
      }
    );

    // Send Paystack's authorization_url back to the frontend
    res.status(200).json({
      message: 'Payment initialization successful',
      data: paystackResponse.data.data, // Contains authorization_url, reference, etc.
    });

  } catch (error) {
    console.error('Error initializing Paystack transaction:', error.response ? error.response.data : error.message);
    res.status(500).json({
      message: 'Failed to initialize payment',
      error: error.response ? error.response.data : error.message,
    });
  }
});

// 3. Endpoint for Paystack Webhooks
// This is more reliable for order fulfillment than the callback_url.
app.post('/api/paystack/webhook', async (req, res) => {
  // IMPORTANT: Validate the webhook signature to ensure the request is from Paystack
  const hash = crypto.createHmac('sha512', PAYSTACK_SECRET_KEY).update(JSON.stringify(req.body)).digest('hex');
  if (hash !== req.headers['x-paystack-signature']) {
    console.warn('Webhook received with invalid signature.');
    return res.sendStatus(401); // Unauthorized
  }

  const event = req.body;

  // Check for the 'charge.success' event
  if (event.event === 'charge.success') {
    console.log('Webhook: Received successful charge event.');
    const transactionData = event.data;

    // --- Fulfill the order ---
    const { order_id, user_id, cart_items, shipping_info } = transactionData.metadata;
    const app_id = process.env.FIREBASE_PROJECT_ID;

    if (!order_id || !user_id || !cart_items || !shipping_info || !app_id) {
      console.error('Webhook Error: Missing required metadata from Paystack.', transactionData.metadata);
      // Still send 200 OK to Paystack so it doesn't keep retrying, but log the error for investigation.
      return res.sendStatus(200);
    }

    const orderRef = firestoreDb.collection(`artifacts/${app_id}/users/${user_id}/orders`).doc(order_id);

    // Check if order already exists to prevent duplicate processing
    const docSnap = await orderRef.get();
    if (docSnap.exists) {
      console.log(`Webhook: Order ${order_id} has already been processed. Skipping.`);
      return res.sendStatus(200);
    }

    try {
      // 1. Create the order document in Firestore
      await orderRef.set({
        items: JSON.parse(cart_items),
        shippingInfo: JSON.parse(shipping_info),
        totalPrice: transactionData.amount / 100,
        paymentStatus: 'paid',
        paystackReference: transactionData.reference,
        orderDate: admin.firestore.FieldValue.serverTimestamp(),
        status: 'processing'
      });
      console.log(`Webhook: Order ${order_id} created successfully for user ${user_id}.`);

      // 2. Clear the user's cart in Firestore
      const cartRef = firestoreDb.collection(`artifacts/${app_id}/users/${user_id}/cart`).doc('currentCart');
      await cartRef.set({ items: [] });
      console.log(`Webhook: Cart cleared for user ${user_id}.`);
    } catch (error) {
      console.error(`Webhook: Error processing order ${order_id}:`, error);
    }
  }

  // Acknowledge receipt of the event
  res.sendStatus(200);
});

// 2. Endpoint to verify a Paystack transaction (This is your callback_url)
// Paystack redirects the user here OR sends a webhook here.
// For simplicity, this example uses the redirect method for verification.
app.get('/api/paystack/verify', async (req, res) => {
  const { trxref, reference } = req.query; // Paystack sends transaction reference in query params

  if (!trxref && !reference) {
    console.error('Transaction reference missing in verification callback.');
    return res.status(400).json({ message: 'Transaction reference missing.' });
  }

  const transactionReference = trxref || reference;

  try {
    const paystackResponse = await axios.get(
      `https://api.paystack.co/transaction/verify/${transactionReference}`,
      {
        headers: {
          Authorization: `Bearer ${PAYSTACK_SECRET_KEY}`,
          'Content-Type': 'application/json',
        },
      }
    );

    const transactionData = paystackResponse.data.data;

    if (transactionData.status === 'success') {
      // Payment was successful!
      // The primary order fulfillment is now handled by the webhook.
      // This redirect is for the user's immediate experience.
      console.log(`Callback: Redirecting user for successful transaction ${transactionReference}.`);


      // Redirect the user back to your React frontend's success page
      // You might pass success/error status via query params
      res.redirect(`${FRONTEND_URL}/checkout-success?status=success&reference=${transactionReference}`);

    } else {
      // Payment failed or was not successful
      console.error('Paystack transaction not successful:', transactionData.gateway_response);
      res.redirect(`${FRONTEND_URL}/checkout-failure?status=failed&message=${encodeURIComponent(transactionData.gateway_response)}`);
    }

  } catch (error) {
    console.error('Error verifying Paystack transaction:', error.response ? error.response.data : error.message);
    res.redirect(`${FRONTEND_URL}/checkout-failure?status=error&message=Verification%20failed`);
  }
});


// Basic route for testing server status
app.get('/', (req, res) => {
  res.send('Paystack Backend is running!');
});

// Start the server
app.listen(PORT, () => {
  console.log(`Paystack Backend listening at http://localhost:${PORT}`);
});
// src/firebaseConfig.js
// For Firebase JS SDK v7.20.0 and later, measurementId is optional