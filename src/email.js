var passport = require('passport');
var authCallback = require("./authCallback");
var mailer = require("nodemailer");

var hasher = require("passport-local-authenticate");

var hashOptions = {
    digestAlgorithm: "sha512"
};

function generateUUID() {
    var d = new Date().getTime();
    var uuid = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
        var r = (d + Math.random() * 16) % 16 | 0; // eslint-disable-line no-bitwise
        d = Math.floor(d / 16);
        return (c == 'x' ? r : (r & 0x7 | 0x8)).toString(16); // eslint-disable-line no-bitwise
    });
    return uuid;
}


module.exports = function(app, db, options) {


    var LocalStrategy = require('passport-local').Strategy;

    passport.use(new LocalStrategy(
        {
            usernameField: 'email',
            passwordField: 'password'
        },
        function(username, password, done) {
            db.Users.findOne({ email: username }, function (err, user) {
                if (err) { return done(err); }
                if (!user) { return done(null, false); }
                hasher.verify(password, {
                    hash: user.password,
                    salt: user.salt
                }, hashOptions, function(err, verified) {
                    if (err) return done(err);
                    else if (!verified) {
                        return done(null, false, {message: "Password does not match"})
                    }
                    else {
                        if (user.verifyToken) {
                            return done(null, false, {message: "Account not verified"});
                        }
                        else {
                            return done(null, user);
                        }
                    }
                })
            });
        }
    ));


    app.post('/login',
        passport.authenticate('local', {
            failureRedirect: '/login',
            failureFlash: true
        }),
        function(req, res) {
            var returnUrl = req.flash("returnUrl")[0];
            res.redirect(returnUrl || '/');
        }
    );


    app.post('/signup', function(req, res) {
        var email = req.body.email;
        var password = req.body.password;
        var valid = true;
        if (!email || email.length < 5 || email.indexOf("@") < 1) {
            req.flash("messages", "Please enter a valid email address")
            valid = false;
        }

        if (!password || password.length < 5) {
            req.flash("messages", "Please enter a valid password")
            valid = false;
        }

        if (!valid) {
            res.redirect('/signup');
        }
        else {
            db.Users.findOne({
                email: email
            }, function(err, user) {
                if (err) {
                    console.log(err);
                    // something went wrong
                }
                else if (user) {

                    // that email already exists in the system
                    // check the password - if they match, treat it as a successful login
                    // if not, show signup form with error
                    // todo: if email is unverified, potentially could remove from existing record
                    hasher.verify(password, {
                        hash: user.password,
                        salt: user.salt
                    }, hashOptions, function(err, verified) {
                        if (err || !verified || user.verifyToken) {
                            req.flash("messages", "The email " + email + " is already used.")
                            res.redirect('/signup');
                        }
                        else {
                            req.login(user, function(err) {
                                console.log(err);
                                var returnUrl = req.flash("returnUrl")[0];
                                res.redirect(returnUrl || '/');
                            });
                        }
                    })
                }
                else {
                    // valid new user - create
                    hasher.hash(password, hashOptions, function(err, hashed) {
                        console.log(hashed.hash); // Hashed password
                        console.log(hashed.salt); // Salt
                        var newUser = {
                            _id: generateUUID(),
                            email: email,
                            password: hashed.hash,
                            salt: hashed.salt
                        };
                        db.Users.save(newUser, function(err, user) {
                            if (err) {
                                req.flash("messages", err.message);
                                res.redirect('/signup');
                            } else {
                                sendEmailVerification(res, email, function(err) {
                                    if (err) {
                                        req.flash("messages", "Error sending mail");
                                    }
                                    else {
                                        req.flash("messages", "Mail sent");
                                    }
                                    res.redirect("/verify");
                                });
                            }
                        });
                    });
                }
            });
        }
    });

    app.get('/verify', function(req, res) {
        res.render("verify", {
            user: req.user,
            site: options.site,
            error: req.flash("error"),
            messages: req.flash("messages")
        });
    });


    app.get('/verify/:token', function(req, res) {
        if (!req.params.token) {
            req.flash("messages", "token required");
            res.redirect("/verify");
        }
        else {
            // check token, login and
            db.Users.findOne({verifyToken: req.params.token}, function(err, user) {
                if (user) {
                    // remove token and log in
                    delete user.verifyToken;
                    db.Users.update({_id: user._id}, {$unset: { verifyToken: null }})

                    req.login(user, function(err) {
                        console.log(err);
                        var returnUrl = req.flash("returnUrl")[0];
                        res.redirect(returnUrl || '/');
                    });
                }
                else {
                    // invalid
                    req.flash("messages", "token not valid");
                    res.redirect("/verify");
                }
            });
        }
    })

    function sendEmailVerification(views, email, done) {
        if (!options.email || !options.email.smtpUrl || !options.email.from) {
            done ("Email sending not configured");
            return;
        }

        var smtpTransport = mailer.createTransport(options.email.smtpUrl);

        var token = generateUUID();

        db.Users.update({email: email}, {$set: { verifyToken: token }})

        views.render("verifyemail", {
            layout: false,
            verifyLink: options.baseUrl + "/verify/" + token
        }, function(err, html) {
            if (err) console.log(err);
            var mail = {
                from: options.email.from,
                to: email,
                subject: "New account verification",
                html
            }

            smtpTransport.sendMail(mail, function(error, response){
                smtpTransport.close();
                if(error){
                    console.log(error);
                    done(error);
                }else{
                    done();
                }
            });
        });
    }


    app.post('/verifymail', function(req, res) {
        var email = req.body.email;
        sendEmailVerification(res, email, function(err) {
            if (err) {
                req.flash("messages", "Error sending mail");
            }
            else {
                req.flash("messages", "Mail sent");
            }
            res.redirect("/verify");
        });
    });



}