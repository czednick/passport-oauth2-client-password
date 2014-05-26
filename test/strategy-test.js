var vows = require('vows');
var assert = require('assert');
var util = require('util');
var ClientIdUsernamePasswordStrategy = require('passport-oauth2-clientid-username-password/strategy');


var testClientId = 'testClientId123';
var testUsername = 'testUsername123';
var testPassword = 'testPassword123';

vows.describe('ClientIdUsernamePasswordStrategy').addBatch({

    'strategy': {
        topic: function() {
            return new ClientIdUsernamePasswordStrategy(function(){});
        },
        
        'should be named oauth2-clientid-username-password': function (strategy) {
            assert.equal(strategy.name, 'oauth2-clientid-username-password');
        },
    },
    
    'strategy handling a request': {
        topic: function() {
            var strategy = new ClientIdUsernamePasswordStrategy(function(clientId, username, password, done) {


                if ((clientId === testClientId) &&
                    (username === testUsername) &&
                    (password === testPassword)) {

                    done(null, {id: clientId,
                                username: username,
                                password: password});

                } else {

                    done(null, false);

                }

            });

            return strategy;
        },
        
        'after augmenting with actions': {
            topic: function(strategy) {
                var self = this;
                var req = {};
                strategy.success = function(user) {
                    self.callback(null, user);
                }
                strategy.fail = function() {
                    self.callback(new Error('should-not-be-called'));
                }
                strategy.error = function() {
                    self.callback(new Error('should-not-be-called'));
                }
                
                req.body = {};
                req.body.client_id = testClientId;
                req.body.username = testUsername;
                req.body.password = testPassword;
                
                process.nextTick(function () {
                    strategy.authenticate(req);
                });
            },
            
            'should not generate an error' : function(err, user) {
                assert.isNull(err);
            },
            'should authenticate' : function(err, user) {
                assert.equal(user.id, testClientId);
            },
        },
    },
    
    'strategy that verifies a request with additional info': {
        topic: function() {
            var strategy = new ClientIdUsernamePasswordStrategy(function(clientId, username, password, done) {

                if ((clientId === testClientId) &&
                    (username === testUsername) &&
                    (password === testPassword)) {

                    done(null, 
                         {id: clientId,
                          username: username,
                          password: password},
                         {foo: 'bar'});

                } else {

                    done(null, false);

                }

            });
            return strategy;
        },
        
        'after augmenting with actions': {
            topic: function(strategy) {
                var self = this;
                var req = {};
                strategy.success = function(user, info) {
                    self.callback(null, user, info);
                }
                strategy.fail = function() {
                    self.callback(new Error('should-not-be-called'));
                }
                strategy.error = function() {
                    self.callback(new Error('should-not-be-called'));
                }
                
                req.body = {};
                req.body.client_id = testClientId;
                req.body.username = testUsername;
                req.body.password = testPassword;

                process.nextTick(function () {
                    strategy.authenticate(req);
                });
            },
            
            'should not generate an error' : function(err, user) {
                assert.isNull(err);
            },
            'should authenticate' : function(err, user) {
                assert.equal(user.id, testClientId);
            },
            'should authenticate with additional info' : function(err, user, info) {
                assert.equal(info.foo, 'bar');
            },
        },
    },
    
    'strategy handling a request that is not verified': {
        topic: function() {
            var strategy = new ClientIdUsernamePasswordStrategy(function(clientId, clientSecret, done) {
                done(null, false);
            });
            return strategy;
        },
        
        'after augmenting with actions': {
            topic: function(strategy) {
                var self = this;
                var req = {};
                strategy.success = function(user) {
                    self.callback(new Error('should-not-be-called'));
                }
                strategy.fail = function() {
                    self.callback(null);
                }
                strategy.error = function() {
                    self.callback(new Error('should-not-be-called'));
                }
                
                req.body = {};
                req.body['client_id'] = 'c1234';
                req.body['client_secret'] = 'shh-its-a-secret';
                process.nextTick(function () {
                    strategy.authenticate(req);
                });
            },
            
            'should fail authentication' : function(err, user) {
                // fail action was called, resulting in test callback
                assert.isNull(err);
            },
        },
    },
    
    'strategy that errors while verifying request': {
        topic: function() {
            var strategy = new ClientIdUsernamePasswordStrategy(function(clientId, username, password, done) {
                done(new Error('something went wrong'));
            });
            return strategy;
        },
        
        'after augmenting with actions': {
            topic: function(strategy) {
                var self = this;
                var req = {};
                strategy.success = function(user) {
                    self.callback(new Error('should-not-be-called'));
                }
                strategy.fail = function() {
                    self.callback(new Error('should-not-be-called'));
                }
                strategy.error = function(err) {
                    self.callback(null, err);
                }
                
                req.body = {};
                req.body.client_id = testClientId;
                req.body.username = testUsername;
                req.body.password = testPassword;
                process.nextTick(function () {
                    strategy.authenticate(req);
                });
            },
            
            'should not call success or fail' : function(err, e) {
                assert.isNull(err);
            },
            'should call error' : function(err, e) {
                assert.instanceOf(e, Error);
                assert.equal(e.message, 'something went wrong');
            },
        },
    },
    
    'strategy handling a request without a body': {
        topic: function() {
            var strategy = new ClientIdUsernamePasswordStrategy(function(clientId, clientSecret, done) {
                done(null, false);
            });
            return strategy;
        },
        
        'after augmenting with actions': {
            topic: function(strategy) {
                var self = this;
                var req = {};
                strategy.success = function(user) {
                    self.callback(new Error('should-not-be-called'));
                }
                strategy.fail = function(challenge, status) {
                    self.callback(null, challenge, status);
                }
                strategy.error = function() {
                    self.callback(new Error('should-not-be-called'));
                }
                
                //req.body = {};
                //req.body['client_id'] = 'c1234';
                //req.body['client_secret'] = 'shh-its-a-secret';
                process.nextTick(function () {
                    strategy.authenticate(req);
                });
            },
            
            'should not call success or error' : function(err, challenge, status) {
                assert.isNull(err);
            },
            'should fail authentication with default status' : function(err, challenge, status) {
                assert.isUndefined(challenge);
            },
        },
    },
    
    'strategy handling a request without a client_id': {
        topic: function() {
            var strategy = new ClientIdUsernamePasswordStrategy(function(clientId, clientSecret, done) {
                done(null, false);
            });
            return strategy;
        },
        
        'after augmenting with actions': {
            topic: function(strategy) {
                var self = this;
                var req = {};
                strategy.success = function(user) {
                    self.callback(new Error('should-not-be-called'));
                }
                strategy.fail = function(challenge, status) {
                    self.callback(null, challenge, status);
                }
                strategy.error = function() {
                    self.callback(new Error('should-not-be-called'));
                }
                
                req.body = {};
                //req.body['client_id'] = 'c1234';
                req.body['client_secret'] = 'shh-its-a-secret';
                process.nextTick(function () {
                    strategy.authenticate(req);
                });
            },
            
            'should not call success or error' : function(err, challenge, status) {
                assert.isNull(err);
            },
            'should fail authentication with default status' : function(err, challenge, status) {
                assert.isUndefined(challenge);
            },
        },
    },
    
    'strategy handling a request without a client_secret': {
        topic: function() {
            var strategy = new ClientIdUsernamePasswordStrategy(function(clientId, clientSecret, done) {
                done(null, false);
            });
            return strategy;
        },
        
        'after augmenting with actions': {
            topic: function(strategy) {
                var self = this;
                var req = {};
                strategy.success = function(user) {
                    self.callback(new Error('should-not-be-called'));
                }
                strategy.fail = function(challenge, status) {
                    self.callback(null, challenge, status);
                }
                strategy.error = function() {
                    self.callback(new Error('should-not-be-called'));
                }
                
                req.body = {};
                req.body['client_id'] = 'c1234';
                //req.body['client_secret'] = 'shh-its-a-secret';
                process.nextTick(function () {
                    strategy.authenticate(req);
                });
            },
            
            'should not call success or error' : function(err, challenge, status) {
                assert.isNull(err);
            },
            'should fail authentication with default status' : function(err, challenge, status) {
                assert.isUndefined(challenge);
            },
        },
    },
    
    'strategy constructed without a verify callback': {
        'should throw an error': function () {
            assert.throws(function() { new ClientIdUsernamePasswordStrategy() });
        },
    },
    
    'strategy with passReqToCallback=true option': {
        topic: function() {
            var strategy = new ClientIdUsernamePasswordStrategy({passReqToCallback:true}, function(req, clientId, username, password, done) {

                assert.isNotNull(req);

                if ((clientId === testClientId) &&
                    (username === testUsername) &&
                    (password === testPassword)) {

                    done(null, 
                         {id: clientId,
                          username: username,
                          password: password,
                          foo: 'bar'});


                } else {

                    done(null, false);

                }




            });
            return strategy;
        },
        
        'after augmenting with actions': {
            topic: function(strategy) {
                var self = this;
                var req = {};
                req.params = { foo: 'bar' }
                strategy.success = function(user) {
                    self.callback(null, user);
                }
                strategy.fail = function() {
                    self.callback(new Error('should-not-be-called'));
                }
                strategy.error = function() {
                    self.callback(new Error('should-not-be-called'));
                }
                
                req.body = {};
                req.body.client_id = testClientId;
                req.body.username = testUsername;
                req.body.password = testPassword;
                process.nextTick(function () {
                    strategy.authenticate(req);
                });
            },
            
            'should not generate an error' : function(err, user) {
                assert.isNull(err);
            },
            'should authenticate' : function(err, user) {
                assert.equal(user.id, testClientId);
                assert.equal(user.foo, 'bar');
            },
        },
    },
    
}).export(module);
