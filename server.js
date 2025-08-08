// server.js (or app.js)
require('dotenv').config(); // Load environment variables from .env file
const express = require('express');
const cors = require('cors');
const axios = require('axios'); // For making HTTP requests to Paystack API
const crypto = require('crypto');
const nodemailer = require('nodemailer');
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

// --- Nodemailer Transporter Setup ---
// Use environment variables for email credentials
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: parseInt(process.env.EMAIL_PORT || '587', 10),
  secure: parseInt(process.env.EMAIL_PORT || '587', 10) === 465, // true for 465, false for other ports
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

const app = express();
const PORT = process.env.PORT || 5000;
const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY;
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5173';
const BACKEND_URL = process.env.BACKEND_URL || `http://localhost:${PORT}`; // For production, set this in your hosting environment

// Middleware
// --- CORS Configuration ---
const primaryFrontendUrl = process.env.FRONTEND_URL;
const firebaseProjectId = process.env.FIREBASE_PROJECT_ID;

// Build a more robust whitelist using a Set to handle unique URLs
const whitelist = new Set(['http://localhost:5173']); // Add local dev environment

if (primaryFrontendUrl) {
  whitelist.add(primaryFrontendUrl); // Add primary live URL from env
}

// If a Firebase project ID is provided, also add the secondary Firebase domain
if (firebaseProjectId) {
  whitelist.add(`https://${firebaseProjectId}.firebaseapp.com`);
}

const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (like Postman, mobile apps, or server-to-server)
    // or if the origin is in our whitelist.
    if (!origin || whitelist.has(origin)) {
      callback(null, true);
    } else {
      console.error(`CORS Error: The request from origin '${origin}' was blocked. Whitelist contains: ${[...whitelist].join(', ')}`);
      callback(new Error('Not allowed by CORS'));
    }
  }
};
app.use(cors(corsOptions));
// We need the raw body for webhook verification, and the parsed body for other routes.
// The 'verify' option of express.json allows us to capture the raw body before it's parsed.
app.use(express.json({
  verify: (req, res, buf) => {
    // Save the raw body to a new property on the request object
    req.rawBody = buf.toString();
  }
}));

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
  // Use the rawBody for the HMAC signature verification, which we captured in the express.json() middleware
  const hash = crypto.createHmac('sha512', PAYSTACK_SECRET_KEY).update(req.rawBody).digest('hex');
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

      // 3. Send order confirmation email
      const orderDataForEmail = {
        orderId: order_id,
        customerEmail: transactionData.customer.email,
        customerName: JSON.parse(shipping_info).name,
        items: JSON.parse(cart_items),
        totalPrice: transactionData.amount / 100,
        shippingInfo: JSON.parse(shipping_info),
      };
      await sendOrderConfirmationEmail(orderDataForEmail);

    } catch (error) {
      console.error(`Webhook: Error processing order ${order_id}:`, error);
      // Even if email fails, we send 200 so Paystack doesn't retry. The order is already saved.
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

// --- Email Sending Function ---
async function sendOrderConfirmationEmail(order) {
  const itemsHtml = order.items.map(item => `
    <tr>
      <td style="padding: 8px; border-bottom: 1px solid #ddd;">${item.name} (x${item.quantity})</td>
      <td style="padding: 8px; border-bottom: 1px solid #ddd; text-align: right;">GHC ${(item.price * item.quantity).toFixed(2)}</td>
    </tr>
  `).join('');

  const mailOptions = {
    from: `"Awuzat Import" <${process.env.EMAIL_USER}>`,
    to: order.customerEmail,
    subject: `Your Order Confirmation (ID: ${order.orderId.substring(0, 8)})`,
    html: `
      <div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
        <h2 style="color: #0d47a1;">Thank you for your order, ${order.customerName}!</h2>
        <p>We've received your order and will process it shortly. Here are the details:</p>
        <h3>Order ID: ${order.orderId}</h3>
        <table style="width: 100%; border-collapse: collapse;">
          <thead>
            <tr>
              <th style="padding: 8px; border-bottom: 2px solid #ddd; text-align: left;">Item</th>
              <th style="padding: 8px; border-bottom: 2px solid #ddd; text-align: right;">Price</th>
            </tr>
          </thead>
          <tbody>
            ${itemsHtml}
          </tbody>
          <tfoot>
            <tr>
              <td style="padding: 8px; font-weight: bold; text-align: right;">Total:</td>
              <td style="padding: 8px; font-weight: bold; text-align: right;">GHC ${order.totalPrice.toFixed(2)}</td>
            </tr>
          </tfoot>
        </table>
        <h3 style="margin-top: 20px;">Shipping to:</h3>
        <p>
          ${order.shippingInfo.name}<br>
          ${order.shippingInfo.address}<br>
          ${order.shippingInfo.city}, ${order.shippingInfo.zip}
        </p>
        <p>Thank you for shopping with us!</p>
      </div>
    `,
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log(`Confirmation email sent successfully to ${order.customerEmail}`);
  } catch (error) {
    console.error(`Error sending confirmation email to ${order.customerEmail}:`, error);
    // Note: Do not block the main process for email failure. Log it for follow-up.
  }
}

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