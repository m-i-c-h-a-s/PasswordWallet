const express = require('express')
const router = express.Router()
const bcrypt = require('bcrypt')
const passport = require('passport')
const { ensureAuthenticated, ensureNotAuthenticated } = require('../config/auth')
const { encrypt, decrypt, encryptSHA, encryptHMAC, validateSHA } = require("../encryptionModule");

// User model
const User = require('../models/User')

// Login Page
router.get('/login', ensureNotAuthenticated, (req, res) => {
    res.render('login')
})

// Register Page
router.get('/register', ensureNotAuthenticated, (req, res) => {
    res.render('register')
})

// Register Handle
router.post('/register', (req, res) => {
    const { login, email, password, password2, is_password_kept_as_hash } = req.body
    let errors = []

    // Check required fields
    if (!login || !email || !password || !password2 || !is_password_kept_as_hash) {
        errors.push({ msg: 'Please fill in all fields' })
    }

    // Check passwords match
    if (password !== password2) {
        errors.push({ msg: 'Passwords do not match '})
    }

    if (errors.length > 0) {
        res.render('register', {
            errors,
            login,
            email,
            password,
            password2
        })
    } else {
        // Validation passed
        User.findOne({ email: email })
            .then(user => {
                if (user) {
                    // User exists
                    errors.push({ msg: 'Email is already registered!' })
                    res.render('register', {
                        errors,
                        login,
                        email,
                        password,
                        password2
                    })
                } else {
                    if (is_password_kept_as_hash == 'true') {
                        result = encryptSHA(password)
                        const encryptedPassword = result.password
                        const saltt = result.salt

                        const newUser = new User({
                            login: login,
                            email: email,
                            is_password_kept_as_hash: is_password_kept_as_hash,
                            password: encryptedPassword,
                            salt: saltt
                        })

                        newUser.save()
                                .then(user => {
                                    req.flash('success_msg', 'You are now registered and can log in.')
                                    res.redirect('/users/login')
                                })
                                .catch(err => console.log(err))
                    } else if (is_password_kept_as_hash == 'false') {
                        const encryptedPassword = encryptHMAC(password)

                        const newUser = new User({
                            login: login,
                            email: email,
                            is_password_kept_as_hash: is_password_kept_as_hash,
                            password: encryptedPassword
                        })

                        newUser.save()
                                .then(user => {
                                    req.flash('success_msg', 'You are now registered and can log in.')
                                    res.redirect('/users/login')
                                })
                                .catch(err => console.log(err))
                    }
                }
            })

    }
})

// Login Handle
router.post('/login', (req, res, next) => {
    passport.authenticate('local', {
        successRedirect: '/dashboard',
        failureRedirect: '/users/login',
        failureFlash: true,
    })(req, res, next)
})

// Logout Handle
router.get('/logout', (req, res, next) => {
    req.logout(err => {
        if (err) {
            return next(err)
        }
    })
    req.flash('success_msg', 'You are logged out.')
    res.redirect('/users/login')
})

// Change Password Page
router.get('/change-password', ensureAuthenticated, (req, res) => {
    res.render('changePassword')
})

// Change Password Handle
router.post('/change-password', async (req, res) => {
    const { currentPassword, newPassword } = req.body
    let errors = []

    const loggedUser = req.user

    // Check required fields
    if (!currentPassword || !newPassword) {
        errors.push({ msg: 'Please fill in all fields' })
        res.render('changePassword', { errors })
    }

    if (loggedUser) {

        if (loggedUser.is_password_kept_as_hash === true) {
            if (validateSHA(currentPassword, loggedUser.salt, loggedUser.password)) {
                result = encryptSHA(newPassword)
                const update = {
                    password: result.password,
                    salt: result.salt
                }

                await User.findOneAndUpdate({ email: loggedUser.email }, update)
                res.redirect('/users/login')
            } else {
                errors.push({ msg: 'Invalid current password.' })
                res.render('changePassword', { errors })
            }
        } else {
            if (loggedUser.password === encryptHMAC(currentPassword)) {
                const update = {
                    password: encryptHMAC(newPassword)
                }

                await User.findOneAndUpdate({ email: loggedUser.email }, update)
                res.redirect('/users/login')
            } else {
                errors.push({ msg: 'Invalid current password.' })
                res.render('changePassword', { errors })
            }
        }
    } else {
        errors.push({ msg: 'No authentication!.' })
        res.render('changePassword', { errors })
    }
})

module.exports = router