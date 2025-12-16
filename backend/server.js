const express = require('express');
const Razorpay = require('razorpay');
const crypto = require('crypto');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const validator = require('validator');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Security Middleware
app.use(helmet());
app.use(cors({
    origin: process.env.FRONTEND_URL || 'http://localhost:5500',
    credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Rate Limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again later.'
});

const paymentLimiter = rateLimit({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 10, // Limit payment attempts
    message: 'Too many payment attempts, please try again later.'
});

app.use('/api/', limiter);

// Initialize Razorpay
const razorpay = new Razorpay({
    key_id: process.env.RAZORPAY_KEY_ID || 'rzp_test_1DP5mmOlF5G5ag',
    key_secret: process.env.RAZORPAY_KEY_SECRET || 'YOUR_SECRET_KEY_HERE'
});

// In-memory storage (use database in production)
const orders = new Map();
const payments = new Map();
const fraudScores = new Map();

// Security: Input Validation
function validateOrderInput(data) {
    const errors = [];

    if (!data.amount || typeof data.amount !== 'number' || data.amount < 100) {
        errors.push('Invalid amount. Minimum ₹1 required.');
    }

    if (data.amount > 10000000) { // Max ₹1,00,000
        errors.push('Amount exceeds maximum limit of ₹1,00,000');
    }

    if (!data.currency || data.currency !== 'INR') {
        errors.push('Invalid currency');
    }

    return errors;
}

function validateEmail(email) {
    return validator.isEmail(email);
}

function validatePhone(phone) {
    // Indian phone number validation
    const cleanPhone = phone.replace(/\D/g, '');
    return /^[6-9]\d{9}$/.test(cleanPhone);
}

// Security: Fraud Detection
function calculateFraudScore(data) {
    let score = 0;
    const factors = [];

    // Check for suspicious email patterns
    const suspiciousKeywords = ['test', 'fake', 'fraud', 'dummy'];
    const email = data.notes?.customer_email?.toLowerCase() || '';
    
    if (suspiciousKeywords.some(keyword => email.includes(keyword))) {
        score += 20;
        factors.push('Suspicious email pattern');
    }

    // Check for disposable email domains
    const disposableDomains = ['tempmail.com', 'throwaway.email', '10minutemail'];
    if (disposableDomains.some(domain => email.includes(domain))) {
        score += 30;
        factors.push('Disposable email detected');
    }

    // Check for high transaction amounts
    if (data.amount > 5000000) { // > ₹50,000
        score += 15;
        factors.push('High transaction amount');
    }

    // Check for repeated phone patterns
    const phone = data.notes?.customer_phone?.replace(/\D/g, '') || '';
    if (/(\d)\1{7,}/.test(phone)) {
        score += 25;
        factors.push('Suspicious phone pattern');
    }

    // Time-based checks (late night transactions)
    const hour = new Date().getHours();
    if (hour >= 2 && hour <= 5) {
        score += 10;
        factors.push('Unusual transaction time');
    }

    return { score: Math.min(score, 100), factors };
}

// Security: Signature Verification
function verifyRazorpaySignature(orderId, paymentId, signature) {
    const expectedSignature = crypto
        .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET || 'YOUR_SECRET_KEY_HERE')
        .update(`${orderId}|${paymentId}`)
        .digest('hex');

    return crypto.timingSafeEqual(
        Buffer.from(expectedSignature),
        Buffer.from(signature)
    );
}

// Security Logging
function logSecurityEvent(event, details) {
    console.log(`[SECURITY] ${new Date().toISOString()} - ${event}`, details);
}

// Health Check
app.get('/health', (req, res) => {
    res.json({
        status: 'ok',
        timestamp: new Date().toISOString(),
        service: 'SecureShop Payment Gateway'
    });
});

// Create Order
app.post('/api/create-order', paymentLimiter, async (req, res) => {
    try {
        const { amount, currency, receipt, notes } = req.body;

        // Input validation
        const validationErrors = validateOrderInput(req.body);
        if (validationErrors.length > 0) {
            logSecurityEvent('VALIDATION_FAILED', { errors: validationErrors });
            return res.status(400).json({
                success: false,
                error: validationErrors.join(', ')
            });
        }

        // Validate email and phone if provided
        if (notes?.customer_email && !validateEmail(notes.customer_email)) {
            return res.status(400).json({
                success: false,
                error: 'Invalid email address'
            });
        }

        if (notes?.customer_phone && !validatePhone(notes.customer_phone)) {
            return res.status(400).json({
                success: false,
                error: 'Invalid phone number'
            });
        }

        // Fraud detection
        const fraudCheck = calculateFraudScore(req.body);
        
        if (fraudCheck.score >= 75) {
            logSecurityEvent('HIGH_RISK_TRANSACTION_BLOCKED', {
                score: fraudCheck.score,
                factors: fraudCheck.factors
            });
            
            return res.status(403).json({
                success: false,
                error: 'Transaction blocked for security reasons. Please contact support.'
            });
        }

        // Create order with Razorpay
        const options = {
            amount: amount,
            currency: currency || 'INR',
            receipt: receipt || `receipt_${Date.now()}`,
            notes: notes || {}
        };

        const order = await razorpay.orders.create(options);

        // Store order details
        orders.set(order.id, {
            ...order,
            fraud_score: fraudCheck.score,
            fraud_factors: fraudCheck.factors,
            created_at: new Date().toISOString(),
            ip_address: req.ip
        });

        // Store fraud score
        fraudScores.set(order.id, fraudCheck);

        logSecurityEvent('ORDER_CREATED', {
            order_id: order.id,
            amount: amount,
            fraud_score: fraudCheck.score
        });

        res.json({
            success: true,
            order: order,
            key_id: process.env.RAZORPAY_KEY_ID || 'rzp_test_1DP5mmOlF5G5ag',
            fraud_score: fraudCheck.score
        });

    } catch (error) {
        console.error('Error creating order:', error);
        logSecurityEvent('ORDER_CREATION_FAILED', { error: error.message });
        
        res.status(500).json({
            success: false,
            error: 'Failed to create order. Please try again.'
        });
    }
});

// Verify Payment
app.post('/api/verify-payment', async (req, res) => {
    try {
        const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;

        // Validate required fields
        if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
            return res.status(400).json({
                success: false,
                error: 'Missing required payment parameters'
            });
        }

        // Verify signature
        const isValid = verifyRazorpaySignature(
            razorpay_order_id,
            razorpay_payment_id,
            razorpay_signature
        );

        if (!isValid) {
            logSecurityEvent('INVALID_SIGNATURE', {
                order_id: razorpay_order_id,
                payment_id: razorpay_payment_id
            });

            return res.status(400).json({
                success: false,
                error: 'Payment verification failed. Invalid signature.'
            });
        }

        // Fetch payment details from Razorpay
        const payment = await razorpay.payments.fetch(razorpay_payment_id);

        // Store payment details
        payments.set(razorpay_payment_id, {
            ...payment,
            order_id: razorpay_order_id,
            verified_at: new Date().toISOString(),
            ip_address: req.ip
        });

        // Update order status
        if (orders.has(razorpay_order_id)) {
            const order = orders.get(razorpay_order_id);
            order.payment_status = 'verified';
            order.payment_id = razorpay_payment_id;
            orders.set(razorpay_order_id, order);
        }

        logSecurityEvent('PAYMENT_VERIFIED', {
            order_id: razorpay_order_id,
            payment_id: razorpay_payment_id,
            amount: payment.amount,
            method: payment.method
        });

        res.json({
            success: true,
            message: 'Payment verified successfully',
            payment: {
                id: payment.id,
                order_id: razorpay_order_id,
                amount: payment.amount,
                currency: payment.currency,
                status: payment.status,
                method: payment.method
            }
        });

    } catch (error) {
        console.error('Error verifying payment:', error);
        logSecurityEvent('PAYMENT_VERIFICATION_FAILED', { error: error.message });

        res.status(500).json({
            success: false,
            error: 'Payment verification failed. Please contact support.'
        });
    }
});

// Webhook Handler
app.post('/api/webhook', (req, res) => {
    try {
        const webhookSignature = req.headers['x-razorpay-signature'];
        const webhookSecret = process.env.RAZORPAY_WEBHOOK_SECRET;

        if (!webhookSecret) {
            return res.status(500).json({ error: 'Webhook secret not configured' });
        }

        // Verify webhook signature
        const expectedSignature = crypto
            .createHmac('sha256', webhookSecret)
            .update(JSON.stringify(req.body))
            .digest('hex');

        if (webhookSignature !== expectedSignature) {
            logSecurityEvent('INVALID_WEBHOOK_SIGNATURE', {
                received: webhookSignature
            });
            return res.status(400).json({ error: 'Invalid signature' });
        }

        const event = req.body.event;
        const payload = req.body.payload;

        logSecurityEvent('WEBHOOK_RECEIVED', { event });

        // Handle different webhook events
        switch (event) {
            case 'payment.captured':
                console.log('Payment captured:', payload.payment.entity.id);
                break;
            case 'payment.failed':
                console.log('Payment failed:', payload.payment.entity.id);
                break;
            case 'order.paid':
                console.log('Order paid:', payload.order.entity.id);
                break;
            default:
                console.log('Unhandled event:', event);
        }

        res.json({ status: 'ok' });

    } catch (error) {
        console.error('Webhook error:', error);
        res.status(500).json({ error: 'Webhook processing failed' });
    }
});

// Get Order Details
app.get('/api/order/:orderId', (req, res) => {
    const orderId = req.params.orderId;
    
    if (!orders.has(orderId)) {
        return res.status(404).json({
            success: false,
            error: 'Order not found'
        });
    }

    const order = orders.get(orderId);
    
    res.json({
        success: true,
        order: order
    });
});

// Get Payment Details
app.get('/api/payment/:paymentId', (req, res) => {
    const paymentId = req.params.paymentId;
    
    if (!payments.has(paymentId)) {
        return res.status(404).json({
            success: false,
            error: 'Payment not found'
        });
    }

    const payment = payments.get(paymentId);
    
    res.json({
        success: true,
        payment: payment
    });
});

// Get Statistics (Admin)
app.get('/api/admin/stats', (req, res) => {
    res.json({
        success: true,
        stats: {
            total_orders: orders.size,
            total_payments: payments.size,
            verified_payments: Array.from(payments.values()).filter(p => p.status === 'captured').length,
            high_risk_transactions: Array.from(fraudScores.values()).filter(f => f.score >= 50).length
        }
    });
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Server error:', err);
    logSecurityEvent('SERVER_ERROR', { error: err.message, stack: err.stack });
    
    res.status(500).json({
        success: false,
        error: 'Internal server error'
    });
});

// Start server
app.listen(PORT, () => {
    console.log('='.repeat(80));
    console.log('🛡️  SecureShop Payment Gateway Server');
    console.log('='.repeat(80));
    console.log(`\n✓ Server running on port ${PORT}`);
    console.log(`✓ Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`✓ Razorpay Key ID: ${process.env.RAZORPAY_KEY_ID || 'rzp_test_1DP5mmOlF5G5ag'}`);
    console.log('\nEndpoints:');
    console.log('  POST /api/create-order     - Create payment order');
    console.log('  POST /api/verify-payment   - Verify payment signature');
    console.log('  POST /api/webhook          - Razorpay webhook handler');
    console.log('  GET  /api/order/:orderId   - Get order details');
    console.log('  GET  /api/payment/:paymentId - Get payment details');
    console.log('  GET  /api/admin/stats      - Get statistics');
    console.log('  GET  /health               - Health check');
    console.log('\n' + '='.repeat(80) + '\n');
});

module.exports = app;