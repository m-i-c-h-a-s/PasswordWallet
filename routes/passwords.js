const express = require('express')
const router = express.Router()
const { ensureAuthenticated, ensureNotAuthenticated } = require('../config/auth')
const Password = require('../models/Password')
const { encrypt, decrypt, encryptSHA, encryptHMAC, validateSHA } = require("../encryptionModule");

// Add Password Page
router.get('/add-password', ensureAuthenticated, (req, res) => {
    res.render('addPassword')
})

// Add Password Handle
router.post('/add-password', (req, res) => {
    const { password, web_address, description, login } = req.body
    let errors = []

    const loggedUser = req.user

    // Check required fields
    if (!password || !web_address || !description || !login) {
        errors.push({ msg: 'Please fill in all fields' })
        res.render('addPassword', { errors })
    }

    if (loggedUser) {
        const newPassword = new Password({
            password: encrypt(password),
            id_user: loggedUser.email,
            web_address: web_address,
            description: description,
            login: login
        })

        newPassword.save()
            .then(password => {
                res.redirect('/dashboard')
            })
            .catch(err => console.log(err))
    }
})

// Get user passwords
router.get('/get-passwords', ensureAuthenticated, async (req, res) => {
    const passwords = await Password.find({ 'id_user': { $eq: req.user.email }})
    res.send({ passwords: passwords })
})

// Decrypt password
router.post('/decrypt', ensureAuthenticated, (req, res) => {
    // res.send(decrypt(req.body.password))
    req.flash('encryptedPassword', decrypt(req.body.password))
    res.redirect('/dashboard')
})

module.exports = router