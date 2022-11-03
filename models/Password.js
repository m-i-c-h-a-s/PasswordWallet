const mongoose = require('mongoose')

const PasswordSchema = new mongoose.Schema({
    password: {
        type: String,
        required: true
    },

    id_user: {
        type: String,
        required: true
    },

    web_address: {
        type: String,
        required: true
    },

    description: {
        type: String,
        required: true
    },

    login: {
        type: String,
        required: true
    }
})

const Password = mongoose.model('Password', PasswordSchema)

module.exports = Password