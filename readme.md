# SecureShop E-Commerce Payment System

A complete e-commerce payment system with Razorpay integration featuring product catalog, shopping cart, checkout flow, and secure payment processing.

## Features

* Product catalog with 3 subscription plans
* Shopping cart with add/remove functionality
* Billing information form with validation
* Razorpay payment integration
* Payment verification with signature validation
* Order confirmation page
* Fraud detection system
* Rate limiting protection
* Input validation and sanitization
* Security logging

## Requirements

```bash
npm install
```

Dependencies:
* Node.js 14 or higher
* Express.js
* Razorpay SDK
* CORS
* Helmet (security headers)
* express-rate-limit
* validator
* dotenv

## Configuration

Create a `.env` file in the `backend/` directory:

```env
RAZORPAY_KEY_ID=your_razorpay_key_id
RAZORPAY_KEY_SECRET=your_razorpay_key_secret
RAZORPAY_WEBHOOK_SECRET=your_webhook_secret
PORT=3000
FRONTEND_URL=http://localhost:5500
```

Get your Razorpay keys from https://razorpay.com dashboard.

## Usage

```bash
# Navigate to backend directory
cd backend

# Install dependencies
npm install

# Start the backend server
npm start

# Open the frontend
# Open frontend/shop-products.html in your browser
```

The server will start on `http://localhost:3000`

## Testing

Use Razorpay test cards:
* Success: `4111 1111 1111 1111`
* Failure: `4000 0000 0000 0002`
* 3D Secure: `5555 5555 5555 4444`

Use any future expiry date and any CVV.

## Project Structure

```
secureshop/
├── backend/
│   ├── .env.template      # Environment variables template
│   ├── package.json       # Dependencies configuration
│   └── server.js          # Express backend with payment APIs
├── frontend/
│   ├── shop-products.html # Product catalog and shopping cart
│   ├── checkout.html      # Billing details form
│   ├── payment.html       # Payment processing with Razorpay
│   └── success.html       # Order confirmation page

```

## Output

The system provides:
* Order ID and Payment ID
* Payment confirmation with transaction details
* Email notifications (configured in Razorpay dashboard)
* Security logs in console
* Fraud risk scores for transactions
