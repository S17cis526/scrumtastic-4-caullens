/** @module sessions
  * A module representing a user sessions
  */

module.exports = {
  create,
  destroy,
  loginRequired
}

var json = require('../../lib/form-json');
var encryption = require('../../lib/encryption');

/** @function create
  * Creates a new session
  */
function create(req, res, db) {
  json(req, res, function(req, res) {
    var username = req.body.username;
    var password = req.body.password;
    db.get("SELECT * FROM users WHERE username=?", [username], function(err, user) {
      if(err) {
        console.error(err);
        res.statusCode = 500;
        res.end("Server error");
        return;
      }
      if(!user) {
        // Username not in database
        res.statusCode = 403;
        res.end("Incorrect username/password");
        return;
      }
      var cryptedPassword = encryption.digest(password + user.salt);
      if(cryptedPassword != user.cryptedPassword) {
        // Invalid password/username combination
        res.statusCode = 403;
        res.end("Incorrect username/password");
        return;
      } else {
        // Success
        // Store user.id in the cookie
        // Encrypt user.id
        var cookieData = JSON.stringify({userId: user.id});
        var encryptedCookieData = encryption.encypher.(cookieData);
        res.setHeader("Set-Cookie", ["session=" + encryptedCookieData]);
        res.statusCode = 200;
        res.end('Successful Login');
      }
    });
  });
}

/** @function destroy
  * Destroys a session
  */
function destroy(req, res) {
  res.setHeader("Set-Cookie", "");
  res.statusCode = 200;
  res.end("Logged our successfully");
}

/** @function loginRequired
  * Checks to see if a new login is required
  */
function loginRequired(req, res, next) {
  var session = req.headers.cookie.session;
  var sessionData = encryption.decypher(session);
  var sessionObj = JSON.parse(sessionData);
  if(sessionObj.userId) {
    req.currentUserId = sessionObj.userId;
    return next(req, res);
  } else {
    res.statusCode = 403;
    res.end("Authentication required");
  }
}
