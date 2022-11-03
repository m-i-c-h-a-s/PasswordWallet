const mongoose = require('mongoose')

const UserSchema = new mongoose.Schema({
    login: {
        type: String,
        required: true
    },

    email: {
        type: String,
        required: true,
        unique: true
    },

    password: {
        type: String,
        required: true
    },

    salt: {
        type: String,
        required: false
    },

    is_password_kept_as_hash: {
        type: Boolean,
        required: true
    }
})

const User = mongoose.model('User', UserSchema)

module.exports = User