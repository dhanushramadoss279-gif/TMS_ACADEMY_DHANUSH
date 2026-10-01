const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String },
    googleId: { type: String },
    isSubscribed: { type: Boolean, default: false },
    subscriptionExpiry: { type: Date }
});

const User = mongoose.model('User', userSchema);

module.exports = User;