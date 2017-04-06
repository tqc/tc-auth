var passport = require('passport');
var authCallback = require("./authcallback");

module.exports = function(app, db, options) {

    if (options.github && options.github.clientID) {
        var GitHubStrategy = require('passport-github2').Strategy;

        passport.use(new GitHubStrategy(
            {
                passReqToCallback: true,
                clientID: options.github.clientID,
                clientSecret: options.github.clientSecret,
                callbackURL: options.baseUrl + "/auth/github/callback"
            },
            authCallback(db, "github", "id")
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


}