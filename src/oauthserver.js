var passport = require('passport');

var oauth2orize = require('oauth2orize'),
    BasicStrategy = require('passport-http').BasicStrategy,
    ClientPasswordStrategy = require('passport-oauth2-client-password').Strategy,
    BearerStrategy = require('passport-http-bearer').Strategy;

module.exports = function(app, db, options) {

    var utils = {
        uid: function(len) {
            var buf = [],
                chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
                charlen = chars.length;

            for (var i = 0; i < len; ++i) {
                buf.push(chars[utils.getRandomInt(0, charlen - 1)]);
            }

            return buf.join('');
        },

        /**
         * Return a random int, used by `utils.uid()`
         *
         * @param {Number} min
         * @param {Number} max
         * @return {Number}
         * @api private
         */

        getRandomInt: function(min, max) {
            return Math.floor(Math.random() * (max - min + 1)) + min;
        }

    };

    function ensureLoggedIn(req, res, next) {
        if (!req.user) {
            req.flash("returnUrl", req.url);
            res.redirect('/auth/login');
            return;
        }
        next();
    }

    // create OAuth 2.0 server
    var server = oauth2orize.createServer();

    // Register serialialization and deserialization functions.
    //
    // When a client redirects a user to user authorization endpoint, an
    // authorization transaction is initiated.  To complete the transaction, the
    // user must authenticate and approve the authorization request.  Because this
    // may involve multiple HTTP request/response exchanges, the transaction is
    // stored in the session.
    //
    // An application must supply serialization functions, which determine how the
    // client object is serialized into the session.  Typically this will be a
    // simple matter of serializing the client's ID, and deserializing by finding
    // the client by ID from the database.

    server.serializeClient(function(client, done) {
        return done(null, client.clientId);
    });

    server.deserializeClient(function(id, done) {

        db.Clients.findOne({
            clientId: id
        }, function(err, client) {
            console.log(client)
            if (err) {
                return done(err);
            }
            return done(null, client);
        });
    });

    // Register supported grant types.
    //
    // OAuth 2.0 specifies a framework that allows users to grant client
    // applications limited access to their protected resources.  It does this
    // through a process of the user granting access, and the client exchanging
    // the grant for an access token.

    // Grant authorization codes.  The callback takes the `client` requesting
    // authorization, the `redirectURI` (which is used as a verifier in the
    // subsequent exchange), the authenticated `user` granting access, and
    // their response, which contains approved scope, duration, etc. as parsed by
    // the application.  The application issues a code, which is bound to these
    // values, and will be exchanged for an access token.

    server.grant(oauth2orize.grant.code(function(client, redirectUri, user, ares, done) {
        var code = utils.uid(16);

        db.AuthorizationCodes.insert({ code: code, clientId: client.clientId, redirectUri: redirectUri, userId: user._id }, function(err) {
            if (err) {
                return done(err);
            }
            done(null, code);
        });
    }));

    // Exchange authorization codes for access tokens.  The callback accepts the
    // `client`, which is exchanging `code` and any `redirectURI` from the
    // authorization request for verification.  If these values are validated, the
    // application issues an access token on behalf of the user who authorized the
    // code.

    server.exchange(oauth2orize.exchange.code(function(client, code, redirectURI, done) {


        db.AuthorizationCodes.findOne({
            clientId: client.clientId,
            code: code
        }, function(err, authCode) {
            if (err) {
                return done(err);
            }
            if (authCode === undefined) {
                return done(null, false);
            }
            if (client.clientId !== authCode.clientId) {
                return done(null, false);
            }
            if (redirectURI !== authCode.redirectUri) {
                return done(null, false);
            }

            db.AuthorizationCodes.remove({
                clientId: client.clientId,
                code: code
            }, function(err) {
                if (err) {
                    return done(err);
                }
                var token = utils.uid(256);
                db.AccessTokens.insert({ token: token, userId: authCode.userId, clientId: authCode.clientId }, function(err) {
                    if (err) {
                        return done(err);
                    }
                    done(null, token);
                });
            });
        });


    }));



    // user authorization endpoint
    //
    // `authorization` middleware accepts a `validate` callback which is
    // responsible for validating the client making the authorization request.  In
    // doing so, is recommended that the `redirectURI` be checked against a
    // registered value, although security requirements may vary accross
    // implementations.  Once validated, the `done` callback must be invoked with
    // a `client` instance, as well as the `redirectURI` to which the user will be
    // redirected after an authorization decision is obtained.
    //
    // This middleware simply initializes a new authorization transaction.  It is
    // the application's responsibility to authenticate the user and render a dialog
    // to obtain their approval (displaying details about the client requesting
    // authorization).  We accomplish that here by routing through `ensureLoggedIn()`
    // first, and rendering the `dialog` view.

    app.get('/auth', [
        ensureLoggedIn,
        server.authorization(function(clientId, redirectUri, done) {
            console.log("looking for client " + clientId);
            console.log("redirect is " + redirectUri);

            db.Clients.findOne({
                clientId: clientId
            }, function(err, client) {
                console.log(err);
                console.log(client);
                if (err) {
                    return done(err);
                }
                return done(null, client, client.redirectUri);
            });
        }),
        function(req, res) {
            res.render('decision', {
                transactionID: req.oauth2.transactionID,
                user: req.user,
                site: options.site,
                client: req.oauth2.client
            });
        }
    ]);

    // user decision endpoint
    //
    // `decision` middleware processes a user's decision to allow or deny access
    // requested by a client application.  Based on the grant type requested by the
    // client, the above grant middleware configured above will be invoked to send
    // a response.


    app.post('/auth/decision', [
        ensureLoggedIn,
        server.decision()
    ]);


    // token endpoint
    //
    // `token` middleware handles client requests to exchange authorization grants
    // for access tokens.  Based on the grant type being exchanged, the above
    // exchange middleware will be invoked to handle the request.  Clients must
    // authenticate when making requests to this endpoint.

    app.post('/auth/token', [
        passport.authenticate(['basic', 'oauth2-client-password'], {
            session: false
        }),
        server.token(),
        server.errorHandler()
    ]);




    /**
     * BasicStrategy & ClientPasswordStrategy
     *
     * These strategies are used to authenticate registered OAuth clients.  They are
     * employed to protect the `token` endpoint, which consumers use to obtain
     * access tokens.  The OAuth 2.0 specification suggests that clients use the
     * HTTP Basic scheme to authenticate.  Use of the client password strategy
     * allows clients to send the same credentials in the request body (as opposed
     * to the `Authorization` header).  While this approach is not recommended by
     * the specification, in practice it is quite common.
     */
    passport.use(new BasicStrategy(
        function(username, password, done) {
            console.log("Basic - "+username);
            if (username == "token") return checkAccessToken(password, done);

            db.Clients.findOne({
                clientId: username
            },  function(err, client) {
                if (err) {
                    return done(err);
                }
                if (!client) {
                    return done(null, false);
                }
                if (client.clientSecret != password) {
                    return done(null, false);
                }
                return done(null, client);
            });
        }
    ));

    passport.use(new ClientPasswordStrategy(
        function(clientId, clientSecret, done) {
            db.Clients.findOne({
                clientId: clientId
            },  function(err, client) {
                if (err) {
                    return done(err);
                }
                if (!client) {
                    return done(null, false);
                }
                if (client.clientSecret != clientSecret) {
                    return done(null, false);
                }
                return done(null, client);
            });
        }
    ));

    /**
     * BearerStrategy
     *
     * This strategy is used to authenticate users based on an access token (aka a
     * bearer token).  The user must have previously authorized a client
     * application, which is issued an access token to make requests on behalf of
     * the authorizing user.
     */

    function checkAccessToken(accessToken, done) {
        console.log("Checking token "+accessToken);
        db.AccessTokens.findOne({
            token: accessToken
        }, function(err, token) {
            if (err) {
                return done(err);
            }
            if (!token) {
                return done(null, false);
            }

            db.Users.findOne({
                _id: token.userId
            }, function(err, user) {
                if (err) {
                    return done(err);
                }
                if (!user) {
                    return done(null, false);
                }
                // to keep this example simple, restricted scopes are not implemented,
                // and this is just for illustrative purposes
                var info = {
                    scope: '*'
                };
                done(null, user, info);
            });
        });
    }
    passport.use(new BearerStrategy(checkAccessToken));



}