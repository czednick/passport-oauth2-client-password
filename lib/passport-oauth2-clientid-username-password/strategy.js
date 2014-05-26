'use strict';

/**
 * Module dependencies.
 */
var passport = require('passport');
var util = require('util');


/**
 * `ClientIdUsernamePasswordStrategy` constructor.
 *
 * @api protected
 */
function Strategy(options, verify) {
    if (typeof options === 'function') {
        verify = options;
        options = {};
    }

    if (!verify) {
        throw new Error('OAuth 2.0 client password strategy requires a verify function');
    }
    
    passport.Strategy.call(this);
    this.name = 'oauth2-clientid-username-password';
    this._verify = verify;
    this._passReqToCallback = options.passReqToCallback;
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);

/**
 * Authenticate request based on client and user credentials in the request body.
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function(req) {

    if (req.body &&
        req.body['client_id'] &&
        req.body['username'] &&
        req.body['password']) {

        var clientId = req.body.client_id;
        var username = req.body.username;
        var password = req.body.password;
        
        var self = this;
        
        var verified = function verified(err, client, info) {
            if (err) { return self.error(err); }
            if (!client) { return self.fail(); }
            self.success(client, info);
        }
        
        if (self._passReqToCallback) {
            this._verify(req, clientId, username, password, verified);
        } else {
            this._verify(clientId, username, password, verified);
        }
        
    } else {
        return this.fail();
    }

}


/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
