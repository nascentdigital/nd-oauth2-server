'use strict';

// imports
const assert = require('assert');
const oauthServer = require('oauth2-server');
const Promise = require('bluebird');
const Request = require('oauth2-server').Request;
const Response = require('oauth2-server').Response;
const _ = require ('lodash');


// exports
exports.createServer = function(options) {
    return new OAuth2Server(options);
};
exports.createProvider = function(providerName, options = {}) {

    // create provider instance
    const providerModule = require(__dirname + '/providers/' + providerName);
    const provider = providerModule(options);

    // return provider
    return provider;
};

// class definition
class OAuth2Server {

    constructor(options) {

        // create server instance
        const provider = options.provider;
        this.scopeRequired = options.scopeRequired;
        this.oauth2Provider = provider;
        this.oauth2Server = new oauthServer({
            model: {

                getClient: function(clientId, clientSecret) {
                    return provider.getClient(clientId, clientSecret);
                },

                getUser: function(username, password) {
                    return provider.getUser(username, password);
                },

                getAccessToken: function(accessToken) {
                    return provider.getAccessToken(accessToken);
                },

                getRefreshToken: function(refreshToken) {
                    return provider.getRefreshToken(refreshToken);
                },

                saveToken: function(token, client, user) {
                    return provider.saveToken(token, client, user);
                },

                revokeToken: function(token) {
                    return provider.revokeToken(token);
                },

                validateScope: function(user, client, scope) {
                    return provider.validateScope(user, client, scope);
                }
            }
        });
    }

    authenticate(scopes) {

        // normalize scopes
        scopes = normalizeScopes(scopes);

        // return handler
        const instance = this;
        return function (req, res, next) {
            const request = new Request(req);
            const response = new Response(res);
            return Promise.bind(this)
                .then(function () {
                    return instance.oauth2Server.authenticate(request, response);
                })
                .tap(function (token) {

                    // fail if request is out of scope
                    if (scopes.indexOf(token.scope) < 0) {
                        throw Error('unauthorized scope: ' + token.scope);
                    }

                    // or apply token to application locals
                    req.oauthToken = token;

                    // continue processing
                    next();
                })
                .catch(function (e) {
                    return handleError(e, req, res, response);
                });
        };
    }

    anonymous(scopes) {

        // normalize scopes
        scopes = normalizeScopes(scopes);

        // return handler
        const instance = this;
        return function (req, res, next) {

            // extract authorization header (fail on error)
            const authorization = (req.headers.authorization || '').split(/[ ]+/);
            if (authorization.length !== 2) {
                return res.status(400).json({
                    error: '400 Bad Request',
                    error_description: 'Invalid authorization header'
                });
            }
            else if (authorization[0] !== 'Basic') {
                return res.status(400).json({
                    error: '400 Bad Request',
                    error_description: 'Invalid authorization scheme'
                });
            }

            // extract client credentials
            const credentials = Buffer(authorization[1], 'base64')
                .toString()
                .split(':', 2);
            if (!credentials) {
                return res.status(400).json({
                    error: '400 Bad Request',
                    error_description: 'Invalid authorization encoding'
                });
            }
            else if (credentials.length !== 2) {
                return res.status(400).json({
                    error: '400 Bad Request',
                    error_description: 'Invalid supplied authorization credentials'
                });
            }

            // fetch matching client
            instance.oauth2Provider.getClient(credentials[0], credentials[1])
                .then(function (client) {

                    // fail if there isn't a client
                    if (!client) {
                        return res.status(401).json({
                            error: '401 Unauthorized',
                            error_description: 'Invalid client credentials'
                        });
                    }

                    // fail if client support at least one of the required scopes
                    if (instance.scopeRequired) {

                        // find scope intersections
                        const applicableScopes = _.intersection(scopes, client.scopes);

                        // fail if required scope wasn't found
                        if (!applicableScopes) {
                            return res.status(403).json({
                                error: '403 Forbidden',
                                error_description: 'Forbidden client scope'
                            });
                        } else if (applicableScopes.length < 1) {
                            return res.status(403).json({
                                error: '403 Forbidden',
                                error_description: 'Forbidden client scope'
                            });
                        }
                    }

                    // or continue to route
                    next();
                })
                .catch(function () {
                    return res.status(500).json({
                        error: '500 Server Error',
                        error_description: 'A server error occurred.'
                    });
                });
        }
    }

    token() {

        // return handler
        const instance = this;
        return function (req, res, next) {
            const request = new Request(req);
            const response = new Response(res);
            return Promise.bind(this)
                .then(function () {
                    return instance.oauth2Server.token(request, response);
                })
                .tap(function (token) {
                    req.oauthToken = token;
                })
                .then(function () {
                    return handleResponse(req, res, response);
                })
                .catch(function (e) {
                    return handleError(e, req, res, response);
                });
        };
    }

    createUser(username, password, scopes) {

        // TODO: add validation

        // register using provider
        return this.oauth2Provider.createUser(username, password, scopes);
    }

    deleteUser(userId) {
    }
}


// helper methods
function normalizeScopes(scopes) {

    // assert that scopes are defined
    assert((scopes && (Array.isArray(scopes) || typeof scopes === 'string'))
        || !this.scopeRequired,
        'Expected scope to be defined when "scopeRequired" is enabled.');

    // convert as required
    if (typeof scopes === 'string') {
        scopes = [scopes];
    }
    else if (!Array.isArray(scopes)) {
        scopes = [];
    }
}

function handleResponse(req, res, response) {

    // set response headers
    res.set(response.headers);

    // return response
    res.status(response.status)
        .send(response.body);
}

function handleError(e, req, res, response) {

    // set response headers
    if (response) {
        res.set(response.headers);
    }

    // return error response
    res.status(e.code).send({
        error: e.name,
        error_description: e.message
    });
}
