
const mongoose = require('mongoose');

const userSchema = new mongoose.Schema(
    {
        // User Email
        email: {
            type: String,
            required: true,
            unique: true,
            trim: true,
            lowercase: true
        },

        // Password login users
        // Google users-ku password தேவையில்லை
        password: {
            type: String,
            default: null
        },

        // Google Login ID
        googleId: {
            type: String,
            default: null
        },

        // Subscription status
        isSubscribed: {
            type: Boolean,
            default: false
        },

        // Subscription expiry date
        subscriptionExpiry: {
            type: Date,
            default: null
        }
    },

    {
        timestamps: true
    }
);

// Prevent duplicate email
userSchema.index(
    { email: 1 },
    { unique: true }
);

const User = mongoose.model(
    'User',
    userSchema
);

module.exports = User;