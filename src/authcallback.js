var cuid = require("cuid");

module.exports = function authCallback(db, serviceName, idField) {
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
                        _id: cuid()
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