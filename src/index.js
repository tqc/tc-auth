var passport = require('passport');


module.exports = function(app, mongo, options) {
    if (options.live === false && options.site === undefined) options.site = false;

    if (!options.email || !options.email.smtpUrl || !options.email.from) {
        console.warn("Email not configured - account creation may fail");
    }

    var db = {
        Users: mongo.collection("Users"),
        Clients: mongo.collection("Clients"),
        AccessTokens: mongo.collection("AccessTokens"),
        AuthorizationCodes: mongo.collection("AuthorizationCodes")
    };



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




    require("./bitbucket")(app, db, options);
    require("./github")(app, db, options);

    require("./oauthserver")(app, db, options);

    require("./email")(app, db, options);

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
