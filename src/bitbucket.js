var passport = require('passport');
var authCallback = require("./authcallback");

module.exports = function(app, db, options) {

    if (options.bitbucket && options.bitbucket.clientID) {
        var BitbucketStrategy = require('passport-bitbucket-oauth2').Strategy;

        passport.use(new BitbucketStrategy(
            {
                passReqToCallback: true,
                clientID: options.bitbucket.clientID,
                clientSecret: options.bitbucket.clientSecret,
                callbackURL: options.baseUrl + "/auth/bitbucket/callback"
            },
            authCallback(db, "bitbucket", "id")
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

}