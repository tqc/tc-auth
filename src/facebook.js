var passport = require('passport');
var authCallback = require("./authcallback");

module.exports = function(app, db, options) {

    if (options.facebook && options.facebook.clientID) {
        var FacebookStrategy = require('passport-facebook').Strategy;

        passport.use(new FacebookStrategy(
            {
                passReqToCallback: true,
                clientID: options.facebook.clientID,
                clientSecret: options.facebook.clientSecret,
                callbackURL: options.baseUrl + "/auth/facebook/callback"
            },
            authCallback(db, "facebook", "id")
        ));

        app.get('/auth/facebook',
            passport.authenticate('facebook', {
                scope: ['public_profile']
            }),
            function(req, res) {
                // The request will be redirected to facebook for authentication, so this
                // function will not be called.
            });

        app.get('/auth/facebook/callback',
            passport.authenticate('facebook', {
                failureRedirect: '/auth/login'
            }),
            function(req, res) {
                var returnUrl = req.flash("returnUrl")[0];
                res.redirect(returnUrl || '/');
            });


    }


}