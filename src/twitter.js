var passport = require('passport');
var authCallback = require("./authcallback");

module.exports = function(app, db, options) {

    if (options.twitter && options.twitter.clientID) {
        var TwitterStrategy = require('passport-twitter').Strategy;

        passport.use(new TwitterStrategy(
            {
                passReqToCallback: true,
                consumerKey: options.twitter.clientID,
                consumerSecret: options.twitter.clientSecret,
                callbackURL: options.baseUrl + "/auth/twitter/callback"
            },
            authCallback(db, "twitter", "id")
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