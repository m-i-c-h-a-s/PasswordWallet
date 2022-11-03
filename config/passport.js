const LocalStrategy = require('passport-local').Strategy
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const { encrypt, decrypt, encryptSHA, encryptHMAC, validateSHA } = require("../encryptionModule");

// Load User Model
const User = require('../models/User')

module.exports = function(passport) {
    passport.use(
        new LocalStrategy({ usernameField: 'email' }, (email, password, done) => {
            // Match user
            User.findOne({ email: email })
                .then(user => {
                    if (!user) {
                        return done(null, false, { message: 'That email in not registered.' })
                    }

                    if (user.is_password_kept_as_hash === true) {
                        if (validateSHA(password, user.salt, user.password)) {
                            return done(null, user)
                        } else {
                            return done(null, false, { message: 'Password incorrect.' })
                        }
                    } else {
                        if (user.password === encryptHMAC(password)) {
                            return done(null, user)
                        } else {
                            return done(null, false, { message: 'Password incorrect.' })
                        }
                    }
                })
                .catch(err => console.log(err))
        })
    )

    passport.serializeUser((user, done) => {
        done(null, user.id)
    })

    passport.deserializeUser((id, done) => {
        User.findById(id, (err, user) => {
            done(err, user)
        })
    })
}