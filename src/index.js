var passport = require('passport');



module.exports = function(app, mongo, options) {
    var db = {
        Users: mongo.collection("Users"),
        AccessTokens: mongo.collection("AccessTokens"),
        AuthorizationCodes: mongo.collection("AuthorizationCodes")
    };


    passport.serializeUser(function(user, done) {
        done(null, "" + user._id);
    });

    passport.deserializeUser(function(id, done) {
        if (typeof id !== "string") return done(null, null);

        if (process.env.FAKE_AUTH) {
            return done(null, {
                _id: "fakeuser",
                displayName: "Test User"
            });
        }


        db.Users.findOne({
            _id: db.ObjectID(id)
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
                            _id: db.ObjectID()
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
                if (req.session.returnUrl) {
                    res.redirect(req.session.returnUrl);
                    delete req.session.returnUrl;
                } else {
                    res.redirect('/');
                }
            });
        });
    }



    if (options.bitbucket) {
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
                if (req.session.returnUrl) {
                    res.redirect(req.session.returnUrl);
                    delete req.session.returnUrl;
                } else {
                    res.redirect('/');
                }
            });


    }

    if (options.github) {
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
                if (req.session.returnUrl) {
                    res.redirect(req.session.returnUrl);
                    delete req.session.returnUrl;
                } else {
                    res.redirect('/');
                }
            });


    }


    app.get('/login', function(req, res) {
        console.log("login");
        console.log(req.session.returnUrl);
        res.render('login', {
            user: req.user,
            fakeAuth: process.env.FAKE_AUTH
        });
    });


    app.get('/logout', function(req, res) {
        req.logout();
        res.redirect('/');
    });


    app.get('/', function(req, res) {
        if (!options.isLive) {
            res.render("placeholder", {
                user: req.user
            });
        } else if (req.user) {
            res.render("userhome", {
                user: req.user
            });
        } else {
            res.render("anonhome", {});
        }
    });

    if (!options.isLive) {
        app.get('/preview', function(req, res) {
            if (req.user) {
                res.render("userhome", {
                    user: req.user
                });
            } else {
                res.render("anonhome", {});
            }
        });
    }


    module.exports.ensureAuthenticated = function(req, res, next) {
        if (!req.user) {
            req.session.returnUrl = req.url;
            res.redirect('/login');
            return;
        }
        next();
    }


};
