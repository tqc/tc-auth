var passport = require('passport');
var authCallback = require("./authcallback");

module.exports = function(app, db, options) {

    if (options.twitter && options.twitter.clientID) {
        var TwitterStrategy = require('passport-twitter').Strategy;

        passport.use(new TwitterStrategy(
            {
                passReqToCallback: true,
                clientID: options.twitter.clientID,
                clientSecret: options.twitter.clientSecret,
                callbackURL: options.baseUrl + "/auth/twitter/callback"
            },
            authCallback("twitter", "id")
        ));

        app.get('/auth/twitter',
            passport.authenticate('twitter', {
            }),
            function(req, res) {
                // The request will be redirected to twitter for authentication, so this
                // function will not be called.
            });

        app.get('/auth/twitter/callback',
            passport.authenticate('twitter', {
                failureRedirect: '/login'
            }),
            function(req, res) {
                var returnUrl = req.flash("returnUrl")[0];
                res.redirect(returnUrl || '/');
            });


    }


}