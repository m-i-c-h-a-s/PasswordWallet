const express = require('express')
const router = express.Router()
const { ensureAuthenticated, ensureNotAuthenticated } = require('../config/auth')
const Password = require('../models/Password')
const crypto = require('crypto')

// Welcome Page
router.get('/', ensureNotAuthenticated, (req, res) => {
    res.render('welcome')
})

// Dashboard
router.get('/dashboard', ensureAuthenticated, async (req, res) => {
    const passwords = await Password.find({ 'id_user': { $eq: req.user.email }})

    res.render('dashboard', {
        login: req.user.login,
        passwords: passwords
    })
})

module.exports = router