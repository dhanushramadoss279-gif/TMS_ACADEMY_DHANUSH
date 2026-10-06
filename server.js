
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

const IS_PRODUCTION =
    process.env.NODE_ENV === 'production';

app.set('trust proxy', 1);


/* =========================================================
   SECURITY HEADERS
========================================================= */

app.disable('x-powered-by');

app.use((req, res, next) => {

    res.setHeader(
        'X-Content-Type-Options',
        'nosniff'
    );

    res.setHeader(
        'X-Frame-Options',
        'SAMEORIGIN'
    );

    res.setHeader(
        'Referrer-Policy',
        'strict-origin-when-cross-origin'
    );

    next();

});


/* =========================================================
   BODY PARSERS
========================================================= */

app.use(
    express.json({
        limit: '100kb'
    })
);

app.use(
    express.urlencoded({
        extended: true,
        limit: '100kb'
    })
);

app.use(cookieParser());


/* =========================================================
   ENVIRONMENT VARIABLES
========================================================= */

const requiredEnv = [

    'MONGO_URI',
    'JWT_SECRET',
    'RAZORPAY_KEY_ID',
    'RAZORPAY_KEY_SECRET',
    'GOOGLE_CLIENT_ID'

];

const missingEnv =
    requiredEnv.filter(
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
   MONGODB
========================================================= */

mongoose.set(
    'strictQuery',
    true
);

mongoose
    .connect(
        process.env.MONGO_URI,
        {
            serverSelectionTimeoutMS: 10000
        }
    )
    .then(() => {

        console.log(
            'MongoDB Connected Successfully!'
        );

    })
    .catch((err) => {

        console.error(
            'MongoDB Connection Error:',
            err.message
        );

        process.exit(1);

    });


/* =========================================================
   RAZORPAY
========================================================= */

const razorpay =
    new Razorpay({

        key_id:
            process.env.RAZORPAY_KEY_ID,

        key_secret:
            process.env.RAZORPAY_KEY_SECRET

    });


/* =========================================================
   GOOGLE OAUTH
========================================================= */

const googleClient =
    new OAuth2Client(
        process.env.GOOGLE_CLIENT_ID
    );


/* =========================================================
   COOKIE OPTIONS
========================================================= */

const cookieOptions = {

    httpOnly: true,

    secure: IS_PRODUCTION,

    sameSite: 'lax',

    maxAge:
        7 * 24 * 60 * 60 * 1000,

    path: '/'

};


/* =========================================================
   CREATE JWT
========================================================= */

function createToken(userId) {

    return jwt.sign(

        {
            id:
                userId.toString()
        },

        process.env.JWT_SECRET,

        {
            expiresIn: '7d'
        }

    );

}


/* =========================================================
   SET LOGIN COOKIE
========================================================= */

function setLoginCookie(
    res,
    token
) {

    res.cookie(
        'token',
        token,
        cookieOptions
    );

}


/* =========================================================
   CLEAR LOGIN COOKIE
========================================================= */

function clearLoginCookie(res) {

    res.clearCookie(
        'token',
        {
            httpOnly: true,
            secure: IS_PRODUCTION,
            sameSite: 'lax',
            path: '/'
        }
    );

}


/* =========================================================
   GET AUTHENTICATED USER ID
========================================================= */

function getAuthenticatedUserId(req) {

    try {

        const token =
            req.cookies.token;

        if (!token) {
            return null;
        }

        const decoded =
            jwt.verify(
                token,
                process.env.JWT_SECRET
            );

        return decoded.id;

    } catch (err) {

        return null;

    }

}


/* =========================================================
   CHECK ACTIVE SUBSCRIPTION
========================================================= */

function isSubscriptionActive(user) {

    if (!user) {
        return false;
    }

    if (user.isSubscribed !== true) {
        return false;
    }

    if (!user.subscriptionExpiry) {
        return false;
    }

    return (
        new Date() <=
        new Date(
            user.subscriptionExpiry
        )
    );

}


/* =========================================================
   VERIFY RAZORPAY SIGNATURE
========================================================= */

function verifyRazorpaySignature(
    orderId,
    paymentId,
    signature
) {

    if (
        !orderId ||
        !paymentId ||
        !signature
    ) {
        return false;
    }

    const body =
        `${orderId}|${paymentId}`;

    const expectedSignature =
        crypto
            .createHmac(
                'sha256',
                process.env.RAZORPAY_KEY_SECRET
            )
            .update(body)
            .digest('hex');

    const expectedBuffer =
        Buffer.from(
            expectedSignature,
            'utf8'
        );

    const receivedBuffer =
        Buffer.from(
            signature,
            'utf8'
        );

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
   VERIFY SUBSCRIPTION MIDDLEWARE
========================================================= */

const verifySubscription =
    async (req, res, next) => {

        try {

            const token =
                req.cookies.token;

            /* -----------------------------------------
               NO LOGIN
            ----------------------------------------- */

            if (!token) {

                return res.redirect(
                    '/login.html'
                );

            }


            /* -----------------------------------------
               VERIFY JWT
            ----------------------------------------- */

            const decoded =
                jwt.verify(
                    token,
                    process.env.JWT_SECRET
                );


            /* -----------------------------------------
               FIND USER
            ----------------------------------------- */

            const user =
                await User.findById(
                    decoded.id
                );


            if (!user) {

                clearLoginCookie(res);

                return res.redirect(
                    '/login.html'
                );

            }


            /* -----------------------------------------
               CHECK SUBSCRIPTION
            ----------------------------------------- */

            const active =
                isSubscriptionActive(user);


            console.log(
                `Subscription Check | ${user.email} | Active: ${active} | Expiry: ${user.subscriptionExpiry}`
            );


            /* -----------------------------------------
               PAYMENT REQUIRED
            ----------------------------------------- */

            if (!active) {

                return res.redirect(
                    '/pay.html'
                );

            }


            req.user = user;

            next();

        } catch (err) {

            console.error(
                'Subscription Middleware Error:',
                err.message
            );

            clearLoginCookie(res);

            return res.redirect(
                '/login.html'
            );

        }

    };


/* =========================================================
   SEO: KEEP NON-LOGIN PAGES OUT OF GOOGLE
   (indexing control only - NOT a security measure;
   access control is still done by verifySubscription)
   - Sent on every response, including redirects, for:
     /pages/*, /pay.html, /signup.html
   - /login.html and / stay indexable (no header added)
   - robots.txt must NOT block these paths, so crawlers
     can read the noindex instruction
========================================================= */

const NOINDEX_PATHS = [
    '/pay.html',
    '/signup.html'
];

app.use((req, res, next) => {

    const isProtectedArea =
        req.path === '/pages' ||
        req.path.startsWith('/pages/');

    if (
        isProtectedArea ||
        NOINDEX_PATHS.includes(req.path)
    ) {

        res.setHeader(
            'X-Robots-Tag',
            'noindex, nofollow'
        );

    }

    next();

});


/* =========================================================
   PUBLIC FILES
========================================================= */

app.use(
    express.static(
        path.join(
            __dirname,
            'public'
        ),
        {
            index: false
        }
    )
);


/* =========================================================
   HEALTH CHECK
========================================================= */

app.get(
    '/api/health',
    (req, res) => {

        return res.json({

            success: true,

            status: 'OK',

            environment:
                IS_PRODUCTION
                    ? 'production'
                    : 'development',

            database:
                mongoose.connection.readyState === 1
                    ? 'connected'
                    : 'disconnected',

            time:
                new Date().toISOString()

        });

    }
);


/* =========================================================
   ROOT ROUTE
========================================================= */

app.get(
    '/',
    async (req, res) => {

        try {

            const token =
                req.cookies.token;


            /* -----------------------------------------
               NOT LOGGED IN
            ----------------------------------------- */

            if (!token) {

                return res.redirect(
                    '/login.html'
                );

            }


            /* -----------------------------------------
               VERIFY TOKEN
            ----------------------------------------- */

            const decoded =
                jwt.verify(
                    token,
                    process.env.JWT_SECRET
                );


            /* -----------------------------------------
               FIND USER
            ----------------------------------------- */

            const user =
                await User.findById(
                    decoded.id
                );


            if (!user) {

                clearLoginCookie(res);

                return res.redirect(
                    '/login.html'
                );

            }


            /* -----------------------------------------
               CHECK SUBSCRIPTION
            ----------------------------------------- */

            const active =
                isSubscriptionActive(user);


            if (active) {

                return res.redirect(
                    '/pages/index.html'
                );

            }


            return res.redirect(
                '/pay.html'
            );

        } catch (err) {

            console.error(
                'Root Route Error:',
                err.message
            );

            clearLoginCookie(res);

            return res.redirect(
                '/login.html'
            );

        }

    }
);


/* =========================================================
   1. SIGNUP
========================================================= */

app.post(
    '/api/signup',
    async (req, res) => {

        try {

            let {
                email,
                password
            } = req.body;


            email =
                String(email || '')
                    .trim()
                    .toLowerCase();

            password =
                String(password || '');


            if (!email || !password) {

                return res.status(400).json({

                    success: false,

                    message:
                        'Email and password are required'

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
                await User.findOne({
                    email
                });


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


            const newUser =
                new User({

                    email,

                    password:
                        hashedPassword,

                    isSubscribed:
                        false,

                    subscriptionExpiry:
                        null

                });


            await newUser.save();


            return res.status(201).json({

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

    }
);


/* =========================================================
   2. EMAIL LOGIN
========================================================= */

app.post(
    '/api/login',
    async (req, res) => {

        try {

            let {
                email,
                password
            } = req.body;


            email =
                String(email || '')
                    .trim()
                    .toLowerCase();

            password =
                String(password || '');


            if (!email || !password) {

                return res.status(400).json({

                    success: false,

                    message:
                        'Email and password are required'

                });

            }


            const user =
                await User.findOne({
                    email
                });


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
                createToken(
                    user._id
                );


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

    }
);


/* =========================================================
   3. GOOGLE LOGIN
========================================================= */

app.post(
    '/api/google-login',
    async (req, res) => {

        try {

            const {
                token
            } = req.body;


            if (!token) {

                return res.status(400).json({

                    success: false,

                    message:
                        'Google token missing'

                });

            }


            const ticket =
                await googleClient.verifyIdToken({

                    idToken:
                        token,

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


            if (
                payload.email_verified !== true
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        'Google email is not verified'

                });

            }


            const email =
                String(
                    payload.email || ''
                )
                    .trim()
                    .toLowerCase();


            if (!email) {

                return res.status(400).json({

                    success: false,

                    message:
                        'Google account email missing'

                });

            }


            let user =
                await User.findOne({
                    email
                });


            /* -----------------------------------------
               CREATE GOOGLE USER
            ----------------------------------------- */

            if (!user) {

                const randomPassword =
                    crypto
                        .randomBytes(32)
                        .toString('hex');


                const hashedPassword =
                    await bcrypt.hash(
                        randomPassword,
                        12
                    );


                user =
                    new User({

                        email,

                        password:
                            hashedPassword,

                        isSubscribed:
                            false,

                        subscriptionExpiry:
                            null

                    });


                await user.save();

            }


            /* -----------------------------------------
               CREATE JWT
            ----------------------------------------- */

            const jwtToken =
                createToken(
                    user._id
                );


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
                err.message
            );

            return res.status(400).json({

                success: false,

                message:
                    'Google Login Failed!'

            });

        }

    }
);


/* =========================================================
   4. CREATE RAZORPAY ORDER
   ₹49 / 30 DAYS
========================================================= */

app.post(
    '/api/create-order',
    async (req, res) => {

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
                await User.findById(
                    userId
                );


            if (!user) {

                return res.status(401).json({

                    success: false,

                    message:
                        'User not found'

                });

            }


            const amount =
                49 * 100;


            const receipt =
                `TMS_${Date.now()}_${crypto
                    .randomBytes(4)
                    .toString('hex')}`;


            const options = {

                amount,

                currency:
                    'INR',

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


            return res.status(200).json({

                success: true,

                id:
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
                    'Unable to create payment order',

                error:
                    err?.error?.description ||
                    err?.description ||
                    err?.message ||
                    'Unknown Razorpay error'

            });

        }

    }
);


/* =========================================================
   5. VERIFY RAZORPAY PAYMENT
========================================================= */

app.post(
    '/api/verify-payment',
    async (req, res) => {

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


            const {

                razorpay_order_id,

                razorpay_payment_id,

                razorpay_signature

            } = req.body;


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
               VERIFY SIGNATURE
            ----------------------------------------- */

            const signatureValid =
                verifyRazorpaySignature(

                    razorpay_order_id,

                    razorpay_payment_id,

                    razorpay_signature

                );


            if (!signatureValid) {

                return res.status(400).json({

                    success: false,

                    message:
                        'Invalid payment signature'

                });

            }


            /* -----------------------------------------
               FETCH ORDER
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


            const expectedAmount =
                49 * 100;


            if (
                Number(order.amount) !==
                expectedAmount
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        'Invalid payment amount'

                });

            }


            if (
                order.currency !==
                'INR'
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        'Invalid payment currency'

                });

            }


            /* -----------------------------------------
               VERIFY USER OWNERSHIP
            ----------------------------------------- */

            if (
                !order.notes ||
                order.notes.userId !==
                userId.toString()
            ) {

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


            if (
                payment.status !==
                'captured'
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
                await User.findById(
                    userId
                );


            if (!user) {

                return res.status(404).json({

                    success: false,

                    message:
                        'User not found'

                });

            }


            /* -----------------------------------------
               PREVENT SAME PAYMENT BEING USED AGAIN
            ----------------------------------------- */

            if (
                user.lastPaymentId &&
                user.lastPaymentId ===
                razorpay_payment_id
            ) {

                return res.status(409).json({

                    success: false,

                    message:
                        'This payment has already been processed'

                });

            }


            /* -----------------------------------------
               CALCULATE EXPIRY
            ----------------------------------------- */

            const now =
                new Date();

            let expiryDate;


            if (
                user.isSubscribed &&
                user.subscriptionExpiry &&
                new Date(
                    user.subscriptionExpiry
                ) > now
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
               UPDATE SUBSCRIPTION
            ----------------------------------------- */

            user.isSubscribed =
                true;

            user.subscriptionExpiry =
                expiryDate;

            user.lastPaymentId =
                razorpay_payment_id;


            await user.save();


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

    }
);


/* =========================================================
   6. CURRENT USER
========================================================= */

app.get(
    '/api/me',
    async (req, res) => {

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

                clearLoginCookie(res);

                return res.status(401).json({

                    success: false,

                    message:
                        'User not found'

                });

            }


            const active =
                isSubscriptionActive(user);


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
                        user.subscriptionExpiry ||
                        null

                }

            });

        } catch (err) {

            clearLoginCookie(res);

            return res.status(401).json({

                success: false,

                message:
                    'Invalid or expired session'

            });

        }

    }
);


/* =========================================================
   7. LOGOUT
========================================================= */

app.post(
    '/api/logout',
    (req, res) => {

        clearLoginCookie(res);


        return res.json({

            success: true,

            message:
                'Logged out successfully!'

        });

    }
);


/* =========================================================
   8. PREMIUM PAGE
========================================================= */

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


/* =========================================================
   9. PROTECTED STATIC FILES
========================================================= */

app.use(
    '/pages',
    verifySubscription,
    express.static(
        path.join(
            __dirname,
            'protected-pages'
        ),
        {
            index: false
        }
    )
);


/* =========================================================
   10. API 404
========================================================= */

app.use(
    '/api',
    (req, res) => {

        return res.status(404).json({

            success: false,

            message:
                'API endpoint not found'

        });

    }
);


/* =========================================================
   11. GLOBAL ERROR HANDLER
========================================================= */

app.use(
    (err, req, res, next) => {

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

    }
);


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

        console.log(
            `MongoDB Status: ${
                mongoose.connection.readyState === 1
                    ? 'CONNECTED'
                    : 'CONNECTING'
            }`
        );

    }
);