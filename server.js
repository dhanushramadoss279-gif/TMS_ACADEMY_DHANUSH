const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const Razorpay = require('razorpay');
const crypto = require('crypto');
const path = require('path');
const { OAuth2Client } = require('google-auth-library');

require('dotenv').config();

const User = require('./models/User');

const app = express();

/* =========================================================
   BASIC CONFIGURATION
========================================================= */

const PORT = process.env.PORT || 3000;
const IS_PRODUCTION = process.env.NODE_ENV === 'production';

app.set('trust proxy', 1);

app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

/*
   Public files:
   login.html
   signup.html
   pay.html
   CSS
   JS
   images
*/
app.use(express.static(path.join(__dirname, 'public')));


/* =========================================================
   ENVIRONMENT VARIABLE CHECK
========================================================= */

const requiredEnv = [
    'MONGO_URI',
    'JWT_SECRET',
    'RAZORPAY_KEY_ID',
    'RAZORPAY_KEY_SECRET',
    'GOOGLE_CLIENT_ID'
];

const missingEnv = requiredEnv.filter(
    key => !process.env[key]
);

if (missingEnv.length > 0) {
    console.error(
        'ERROR: Missing environment variables:',
        missingEnv.join(', ')
    );

    process.exit(1);
}


/* =========================================================
   MONGODB CONNECTION
========================================================= */

mongoose.connect(process.env.MONGO_URI)
    .then(() => {
        console.log('MongoDB Connected Successfully!');
    })
    .catch((err) => {
        console.error('MongoDB Connection Error:', err);
        process.exit(1);
    });


/* =========================================================
   RAZORPAY
========================================================= */

const razorpay = new Razorpay({
    key_id: process.env.RAZORPAY_KEY_ID,
    key_secret: process.env.RAZORPAY_KEY_SECRET
});


/* =========================================================
   GOOGLE OAUTH
========================================================= */

const googleClient = new OAuth2Client(
    process.env.GOOGLE_CLIENT_ID
);


/* =========================================================
   COOKIE OPTIONS
========================================================= */

const cookieOptions = {
    httpOnly: true,

    secure: IS_PRODUCTION,

    sameSite: 'lax',

    maxAge: 7 * 24 * 60 * 60 * 1000,

    path: '/'
};


/* =========================================================
   HELPER: CREATE JWT
========================================================= */

function createToken(userId) {

    return jwt.sign(
        {
            id: userId.toString()
        },
        process.env.JWT_SECRET,
        {
            expiresIn: '7d'
        }
    );
}


/* =========================================================
   HELPER: SET LOGIN COOKIE
========================================================= */

function setLoginCookie(res, token) {

    res.cookie(
        'token',
        token,
        cookieOptions
    );
}


/* =========================================================
   HELPER: VERIFY JWT
========================================================= */

function getAuthenticatedUserId(req) {

    const token = req.cookies.token;

    if (!token) {
        return null;
    }

    const decoded = jwt.verify(
        token,
        process.env.JWT_SECRET
    );

    return decoded.id;
}


/* =========================================================
   HELPER: PAYMENT SIGNATURE VERIFY
========================================================= */

function verifyRazorpaySignature(
    orderId,
    paymentId,
    signature
) {

    const body =
        orderId + '|' + paymentId;

    const expectedSignature =
        crypto
            .createHmac(
                'sha256',
                process.env.RAZORPAY_KEY_SECRET
            )
            .update(body)
            .digest('hex');

    const expectedBuffer =
        Buffer.from(expectedSignature, 'utf8');

    const receivedBuffer =
        Buffer.from(signature, 'utf8');

    if (
        expectedBuffer.length !==
        receivedBuffer.length
    ) {
        return false;
    }

    return crypto.timingSafeEqual(
        expectedBuffer,
        receivedBuffer
    );
}


/* =========================================================
   MIDDLEWARE
   CHECK LOGIN + ACTIVE SUBSCRIPTION
========================================================= */

const verifySubscription = async (
    req,
    res,
    next
) => {

    try {

        const token = req.cookies.token;

        if (!token) {

            console.log(
                'Middleware: Token missing'
            );

            return res.redirect(
                '/login.html'
            );
        }

        const decoded = jwt.verify(
            token,
            process.env.JWT_SECRET
        );

        const user =
            await User.findById(decoded.id);

        if (!user) {

            console.log(
                'Middleware: User not found'
            );

            res.clearCookie(
                'token',
                {
                    httpOnly: true,
                    secure: IS_PRODUCTION,
                    sameSite: 'lax',
                    path: '/'
                }
            );

            return res.redirect(
                '/login.html'
            );
        }

        const isActive =
            user.isSubscribed === true &&
            user.subscriptionExpiry &&
            new Date() <=
            new Date(user.subscriptionExpiry);

        console.log(
            `Subscription Check | ${user.email} | Active: ${isActive} | Expiry: ${user.subscriptionExpiry}`
        );

        if (!isActive) {

            return res.redirect(
                '/pay.html'
            );
        }

        req.user = user;

        next();

    } catch (err) {

        console.error(
            'Middleware Error:',
            err.message
        );

        res.clearCookie(
            'token',
            {
                httpOnly: true,
                secure: IS_PRODUCTION,
                sameSite: 'lax',
                path: '/'
            }
        );

        return res.redirect(
            '/login.html'
        );
    }
};


/* =========================================================
   ROOT ROUTE
========================================================= */

app.get('/', async (req, res) => {

    try {

        const token = req.cookies.token;

        if (!token) {

            return res.redirect(
                '/login.html'
            );
        }

        const decoded = jwt.verify(
            token,
            process.env.JWT_SECRET
        );

        const user =
            await User.findById(decoded.id);

        if (!user) {

            return res.redirect(
                '/login.html'
            );
        }

        const active =
            user.isSubscribed === true &&
            user.subscriptionExpiry &&
            new Date() <=
            new Date(user.subscriptionExpiry);

        if (active) {

            return res.redirect(
                '/pages/index.html'
            );

        } else {

            return res.redirect(
                '/pay.html'
            );
        }

    } catch (err) {

        return res.redirect(
            '/login.html'
        );
    }
});


/* =========================================================
   1. SIGNUP
========================================================= */

app.post('/api/signup', async (req, res) => {

    try {

        let { email, password } = req.body;

        email = String(email || '')
            .trim()
            .toLowerCase();

        password = String(password || '');

        if (!email || !password) {

            return res.status(400).json({
                success: false,
                message: 'Email and password are required'
            });
        }

        if (password.length < 6) {

            return res.status(400).json({
                success: false,
                message:
                    'Password must contain at least 6 characters'
            });
        }

        const existingUser =
            await User.findOne({ email });

        if (existingUser) {

            return res.status(409).json({
                success: false,
                message:
                    'Email already registered'
            });
        }

        const hashedPassword =
            await bcrypt.hash(
                password,
                12
            );

        const newUser = new User({

            email,

            password:
                hashedPassword,

            isSubscribed: false,

            subscriptionExpiry: null
        });

        await newUser.save();

        return res.json({

            success: true,

            message:
                'Account created successfully!'
        });

    } catch (err) {

        console.error(
            'Signup Error:',
            err
        );

        return res.status(500).json({

            success: false,

            message:
                'Unable to create account'
        });
    }
});


/* =========================================================
   2. EMAIL LOGIN
========================================================= */

app.post('/api/login', async (req, res) => {

    try {

        let { email, password } = req.body;

        email = String(email || '')
            .trim()
            .toLowerCase();

        password = String(password || '');

        if (!email || !password) {

            return res.status(400).json({

                success: false,

                message:
                    'Email and password are required'
            });
        }

        const user =
            await User.findOne({ email });

        if (!user) {

            return res.status(400).json({

                success: false,

                message:
                    'Invalid email or password'
            });
        }

        const passwordMatch =
            await bcrypt.compare(
                password,
                user.password
            );

        if (!passwordMatch) {

            return res.status(400).json({

                success: false,

                message:
                    'Invalid email or password'
            });
        }

        const token =
            createToken(user._id);

        setLoginCookie(
            res,
            token
        );

        return res.json({

            success: true,

            message:
                'Logged in successfully!'
        });

    } catch (err) {

        console.error(
            'Login Error:',
            err
        );

        return res.status(500).json({

            success: false,

            message:
                'Server error'
        });
    }
});


/* =========================================================
   3. GOOGLE LOGIN
========================================================= */

app.post('/api/google-login', async (req, res) => {

    try {

        const { token } = req.body;

        if (!token) {

            return res.status(400).json({

                success: false,

                message:
                    'Google token missing'
            });
        }

        const ticket =
            await googleClient.verifyIdToken({

                idToken: token,

                audience:
                    process.env.GOOGLE_CLIENT_ID
            });

        const payload =
            ticket.getPayload();

        if (!payload) {

            return res.status(400).json({

                success: false,

                message:
                    'Invalid Google account'
            });
        }

        if (payload.email_verified !== true) {

            return res.status(400).json({

                success: false,

                message:
                    'Google email is not verified'
            });
        }

        const email =
            String(payload.email)
                .trim()
                .toLowerCase();

        let user =
            await User.findOne({ email });

        if (!user) {

            const randomPassword =
                crypto.randomBytes(32).toString('hex');

            const hashedPassword =
                await bcrypt.hash(
                    randomPassword,
                    12
                );

            user = new User({

                email,

                password:
                    hashedPassword,

                isSubscribed: false,

                subscriptionExpiry: null
            });

            await user.save();
        }

        const jwtToken =
            createToken(user._id);

        setLoginCookie(
            res,
            jwtToken
        );

        return res.json({

            success: true,

            message:
                'Google Login Successful!'
        });

    } catch (err) {

        console.error(
            'Google Login Error:',
            err
        );

        return res.status(400).json({

            success: false,

            message:
                'Google Login Failed!'
        });
    }
});


/* =========================================================
   4. CREATE RAZORPAY ORDER
   ₹49 / 30 DAYS
========================================================= */

app.post('/api/create-order', async (req, res) => {

    try {

        const userId =
            getAuthenticatedUserId(req);

        if (!userId) {

            return res.status(401).json({

                success: false,

                message:
                    'Please login first'
            });
        }

        const user =
            await User.findById(userId);

        if (!user) {

            return res.status(401).json({

                success: false,

                message:
                    'User not found'
            });
        }

        const amount = 49 * 100;

        const receipt =
            `TMS_${Date.now()}_${crypto
                .randomBytes(4)
                .toString('hex')}`;

        const options = {

            amount,

            currency: 'INR',

            receipt,

            notes: {

                userId:
                    user._id.toString(),

                email:
                    user.email,

                plan:
                    '30_DAYS'
            }
        };

        const order =
            await razorpay.orders.create(
                options
            );

        console.log(
            `Razorpay Order Created | ${order.id} | ${user.email}`
        );

        return res.json({

            success: true,

            orderId:
                order.id,

            amount:
                order.amount,

            currency:
                order.currency,

            key:
                process.env.RAZORPAY_KEY_ID
        });

    } catch (err) {

        console.error(
            'Razorpay Order Error:',
            err
        );

        return res.status(500).json({

            success: false,

            message:
                'Unable to create payment order'
        });
    }
});


/* =========================================================
   5. VERIFY RAZORPAY PAYMENT
========================================================= */

app.post('/api/verify-payment', async (req, res) => {

    try {

        /* -----------------------------------------
           CHECK LOGIN
        ----------------------------------------- */

        const userId =
            getAuthenticatedUserId(req);

        if (!userId) {

            return res.status(401).json({

                success: false,

                message:
                    'Please login first'
            });
        }


        /* -----------------------------------------
           GET PAYMENT DATA
        ----------------------------------------- */

        const {
            razorpay_order_id,
            razorpay_payment_id,
            razorpay_signature
        } = req.body;


        /* -----------------------------------------
           ALL THREE VALUES REQUIRED
        ----------------------------------------- */

        if (
            !razorpay_order_id ||
            !razorpay_payment_id ||
            !razorpay_signature
        ) {

            return res.status(400).json({

                success: false,

                message:
                    'Payment verification data missing'
            });
        }


        /* -----------------------------------------
           SIGNATURE VERIFICATION
        ----------------------------------------- */

        const signatureValid =
            verifyRazorpaySignature(
                razorpay_order_id,
                razorpay_payment_id,
                razorpay_signature
            );

        if (!signatureValid) {

            console.log(
                'Payment Signature Invalid'
            );

            return res.status(400).json({

                success: false,

                message:
                    'Invalid payment signature'
            });
        }


        /* -----------------------------------------
           FETCH ORDER FROM RAZORPAY
        ----------------------------------------- */

        const order =
            await razorpay.orders.fetch(
                razorpay_order_id
            );

        if (!order) {

            return res.status(400).json({

                success: false,

                message:
                    'Razorpay order not found'
            });
        }


        /* -----------------------------------------
           VERIFY ORDER AMOUNT
        ----------------------------------------- */

        const expectedAmount =
            49 * 100;

        if (
            Number(order.amount) !==
            expectedAmount
        ) {

            console.log(
                'Payment amount mismatch'
            );

            return res.status(400).json({

                success: false,

                message:
                    'Invalid payment amount'
            });
        }


        /* -----------------------------------------
           VERIFY CURRENCY
        ----------------------------------------- */

        if (order.currency !== 'INR') {

            return res.status(400).json({

                success: false,

                message:
                    'Invalid payment currency'
            });
        }


        /* -----------------------------------------
           VERIFY USER ↔ ORDER
        ----------------------------------------- */

        if (
            !order.notes ||
            order.notes.userId !==
            userId.toString()
        ) {

            console.log(
                'Payment user mismatch'
            );

            return res.status(403).json({

                success: false,

                message:
                    'Payment does not belong to this user'
            });
        }


        /* -----------------------------------------
           FETCH PAYMENT
        ----------------------------------------- */

        const payment =
            await razorpay.payments.fetch(
                razorpay_payment_id
            );


        /* -----------------------------------------
           VERIFY PAYMENT ↔ ORDER
        ----------------------------------------- */

        if (
            payment.order_id !==
            razorpay_order_id
        ) {

            return res.status(400).json({

                success: false,

                message:
                    'Payment order mismatch'
            });
        }


        /* -----------------------------------------
           VERIFY PAYMENT AMOUNT
        ----------------------------------------- */

        if (
            Number(payment.amount) !==
            expectedAmount
        ) {

            return res.status(400).json({

                success: false,

                message:
                    'Payment amount mismatch'
            });
        }


        /* -----------------------------------------
           PAYMENT MUST BE CAPTURED
        ----------------------------------------- */

        if (
            payment.status !== 'captured'
        ) {

            return res.status(400).json({

                success: false,

                message:
                    'Payment has not been captured'
            });
        }


        /* -----------------------------------------
           FIND USER
        ----------------------------------------- */

        const user =
            await User.findById(userId);

        if (!user) {

            return res.status(404).json({

                success: false,

                message:
                    'User not found'
            });
        }


        /* -----------------------------------------
           SUBSCRIPTION RENEWAL LOGIC

           If current subscription is still active:
           existing expiry + 30 days

           If expired/no subscription:
           today + 30 days
        ----------------------------------------- */

        const now = new Date();

        let expiryDate;

        if (
            user.isSubscribed &&
            user.subscriptionExpiry &&
            new Date(user.subscriptionExpiry) > now
        ) {

            expiryDate =
                new Date(
                    user.subscriptionExpiry
                );

            expiryDate.setDate(
                expiryDate.getDate() + 30
            );

        } else {

            expiryDate =
                new Date();

            expiryDate.setDate(
                expiryDate.getDate() + 30
            );
        }


        /* -----------------------------------------
           ACTIVATE SUBSCRIPTION
        ----------------------------------------- */

        user.isSubscribed = true;

        user.subscriptionExpiry =
            expiryDate;

        await user.save();


        /* -----------------------------------------
           SUCCESS
        ----------------------------------------- */

        console.log(
            `SUCCESS: Subscription activated | User: ${user.email} | Payment: ${razorpay_payment_id} | Expiry: ${expiryDate}`
        );

        return res.json({

            success: true,

            message:
                'Payment verified successfully! Subscription activated for 30 days.',

            expiry:
                expiryDate
        });

    } catch (err) {

        console.error(
            'Verify Payment Error:',
            err
        );

        return res.status(500).json({

            success: false,

            message:
                'Payment verification failed'
        });
    }
});


/* =========================================================
   6. CURRENT USER INFO
========================================================= */

app.get('/api/me', async (req, res) => {

    try {

        const token =
            req.cookies.token;

        if (!token) {

            return res.status(401).json({

                success: false,

                message:
                    'Not logged in'
            });
        }

        const decoded =
            jwt.verify(
                token,
                process.env.JWT_SECRET
            );

        const user =
            await User.findById(
                decoded.id
            )
            .select(
                'email isSubscribed subscriptionExpiry'
            );

        if (!user) {

            return res.status(401).json({

                success: false,

                message:
                    'User not found'
            });
        }

        const active =
            user.isSubscribed === true &&
            user.subscriptionExpiry &&
            new Date() <=
            new Date(user.subscriptionExpiry);

        return res.json({

            success: true,

            user: {

                email:
                    user.email,

                name:
                    user.email.split('@')[0],

                isActive:
                    !!active,

                premiumValidUntil:
                    user.subscriptionExpiry || null
            }
        });

    } catch (err) {

        return res.status(401).json({

            success: false,

            message:
                'Invalid or expired session'
        });
    }
});


/* =========================================================
   7. LOGOUT
========================================================= */

app.post('/api/logout', (req, res) => {

    res.clearCookie(
        'token',
        {
            httpOnly: true,
            secure: IS_PRODUCTION,
            sameSite: 'lax',
            path: '/'
        }
    );

    return res.json({

        success: true,

        message:
            'Logged out successfully!'
    });
});


/* =========================================================
   8. PROTECT ALL PREMIUM HTML FILES
========================================================= */

/*
   Specific index route
*/

app.get(
    '/pages/index.html',
    verifySubscription,
    (req, res) => {

        res.sendFile(
            path.join(
                __dirname,
                'protected-pages',
                'index.html'
            )
        );
    }
);


/*
   All other protected pages

   Example:

   /pages/page1.html
   /pages/page2.html
   /pages/page3.html
   ...
   /pages/page108.html

   All require active subscription.
*/

app.use(
    '/pages',
    verifySubscription,
    express.static(
        path.join(
            __dirname,
            'protected-pages'
        )
    )
);


/* =========================================================
   404 API HANDLER
========================================================= */

app.use('/api', (req, res) => {

    return res.status(404).json({

        success: false,

        message:
            'API endpoint not found'
    });
});


/* =========================================================
   GLOBAL ERROR HANDLER
========================================================= */

app.use((err, req, res, next) => {

    console.error(
        'Global Server Error:',
        err
    );

    if (res.headersSent) {
        return next(err);
    }

    return res.status(500).json({

        success: false,

        message:
            'Internal server error'
    });
});


/* =========================================================
   START SERVER
========================================================= */

app.listen(
    PORT,
    () => {

        console.log(
            `TMS Academy Server running on port ${PORT}`
        );

        console.log(
            `Environment: ${
                IS_PRODUCTION
                    ? 'PRODUCTION'
                    : 'DEVELOPMENT'
            }`
        );
    }
);