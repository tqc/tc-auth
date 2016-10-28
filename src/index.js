var passport = require('passport');
var hasher = require("passport-local-authenticate");

var hashOptions = {
    digestAlgorithm: "sha512"
};

module.exports = function(app, mongo, options) {
    if (options.live === false && options.site === undefined) options.site = false;
    var db = {
        Users: mongo.collection("Users"),
        AccessTokens: mongo.collection("AccessTokens"),
        AuthorizationCodes: mongo.collection("AuthorizationCodes")
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

    passport.serializeUser(function(user, done) {
        done(null, "" + user._id);
    });

    passport.deserializeUser(function(id, done) {
        if (typeof id !== "string") return done(null, null);

        if (options.fakeAuth && id == options.fakeAuth._id) {
            return done(null, options.fakeAuth);
        }


        db.Users.findOne({
            _id: id
        }, done);

    });

    function authCallback(serviceName, idField) {
        return function(req, accessToken, refreshToken, profile, done) {
            if (!req.user) {
                // Not logged-in. Authenticate based on this account.
                var q = {};
                q[serviceName + "Id"] = profile[idField];
                db.Users.findOne(q, function(err, user) {
                    if (!err && !user) {
                        user = {
                            displayName: profile.name || profile.username,
                            //picture: profile._json.picture,
                            _id: generateUUID()
                        };
                        user[serviceName + "Id"] = profile[idField];
                        user[serviceName + "Token"] = accessToken;
                        db.Users.insert(user, function(err2, user2) {
                            return done(err2, user2);
                        });
                    } else {
                        return done(err, user);
                    }
                });


            } else {
                // Logged in. Associate account with user.  Preserve the login
                // state by supplying the existing user after association.
                // return done(null, req.user);
                req.user[serviceName + "Id"] = profile[idField];
                req.user[serviceName + "Profile"] = profile;
                req.user[serviceName + "Token"] = accessToken;
                db.Users.save(req.user);
                return done(null, req.user);
            }
        };
    }


    app.use(passport.initialize());
    app.use(passport.session());


    if (options.handleErrors) {
        var count = 0;
        app.use(function(req, res, next) {
            var domain = require('domain').create();
            domain.id = new Date().getTime() + (count++);
            domain.add(req);
            domain.add(res);
            domain.run(function() {
                next();
            });
            domain.on('error', function(err) {
                console.log('error on request %d %s %s: %j', process.domain.id, req.method, req.url, err.message);
                res.status(500);
                res.send("Something bad happened. :(");
            });
        });

        app.get('/error', function(req, res) {
            process.nextTick(function() {
                throw new Error("Something broken");
                //  throw new Error("The individual request will be passed to the express error handler, and your application will keep running.");
            });

        });

    }

    if (options.fakeAuth) {
        app.get('/auth/fake', function(req, res) {
            req.login(options.fakeAuth, function(err) {
                console.log(err);
                var returnUrl = req.flash("returnUrl")[0];
                res.redirect(returnUrl || '/');
            });
        });
    }

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


    if (options.bitbucket && options.bitbucket.clientID) {
        var BitbucketStrategy = require('passport-bitbucket-oauth2').Strategy;

        passport.use(new BitbucketStrategy(
            {
                passReqToCallback: true,
                clientID: options.bitbucket.clientID,
                clientSecret: options.bitbucket.clientSecret,
                callbackURL: options.baseUrl + "/auth/bitbucket/callback"
            },
            authCallback("bitbucket", "id")
        ));

        app.get('/auth/bitbucket',
            passport.authenticate('bitbucket'),
            function(req, res) {
                // The request will be redirected to Bitbucket for authentication, so this
                // function will not be called.
            });

        app.get('/auth/bitbucket/callback',
            passport.authenticate('bitbucket', {
                failureRedirect: '/login'
            }),
            function(req, res) {
                var returnUrl = req.flash("returnUrl")[0];
                res.redirect(returnUrl || '/');
            });


    }

    if (options.github && options.github.clientID) {
        var GitHubStrategy = require('passport-github2').Strategy;

        passport.use(new GitHubStrategy(
            {
                passReqToCallback: true,
                clientID: options.github.clientID,
                clientSecret: options.github.clientSecret,
                callbackURL: options.baseUrl + "/auth/github/callback"
            },
            authCallback("github", "id")
        ));

        app.get('/auth/github',
            passport.authenticate('github', {
                scope: ['user', 'repo', 'write:repo_hook']
            }),
            function(req, res) {
                // The request will be redirected to GitHub for authentication, so this
                // function will not be called.
            });

        app.get('/auth/github/callback',
            passport.authenticate('github', {
                failureRedirect: '/login'
            }),
            function(req, res) {
                var returnUrl = req.flash("returnUrl")[0];
                res.redirect(returnUrl || '/');
            });


    }

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



    app.get('/login', function(req, res) {
        res.render('login', {
            user: req.user,
            site: options.site,
            fakeAuth: process.env.FAKE_AUTH,
            error: req.flash("error"),
            messages: req.flash("messages")
        });
    });


    app.get('/logout', function(req, res) {
        req.logout();
        res.redirect('/');
    });



    app.get('/signup', function(req, res) {
        res.render('signup', {
            user: req.user,
            site: options.site,
            error: req.flash("error"),
            messages: req.flash("messages")
        });
    });



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

    var mailer = require("nodemailer");

    var smtpTransport = mailer.createTransport(options.email.smtpUrl);

    function sendEmailVerification(views, email, done) {
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


    app.get('/', function(req, res) {
        var pageData = {
            user: req.user,
            site: options.site,
            error: req.flash("error"),
            messages: req.flash("messages")
        };
        if (options.live === false) {
            if (!req.user) {
                // show anon placeholder
                res.render("placeholder", pageData);
            }
            else if ((req.user.roles || []).indexOf("preview") >= 0) {
                // user with preview access - show app
                res.render("userhome", pageData);
            }
            else {
                // user registered - show limited app
                res.render("placeholderapp", pageData);
            }
        }
        else {
            if (!req.user) {
                // show anon homepage
                res.render("anonhome", pageData);
            }
            else {
                // user - show app
                res.render("userhome", pageData);
            }
        }
    });

    if (options.live === false) {
        app.get('/preview', function(req, res) {
            res.render({
                user: req.user,
                site: options.site,
                error: req.flash("error"),
                messages: req.flash("messages")
            });
        });
    }


    module.exports.requireRole = function(role) {
        return function(req, res, next) {
            if (!req.user) {
                res.status(401);
                res.send("401 Authentication Required")
                return;
            }
            if (role && (req.user.roles || []).indexOf(role) < 0) {
                res.status(403);
                res.send("403 Forbidden")
                return;
            }
            if (options.live === false && (req.user.roles || []).indexOf("preview") < 0) {
                res.status(403);
                res.send("403 Forbidden")
                return;
            }
            next();
        }
    };

    module.exports.ensureAuthenticated = function(req, res, next) {
        if (!req.user) {
            req.flash("returnUrl", req.url);
            res.redirect('/login');
            return;
        }
        next();
    }


};
