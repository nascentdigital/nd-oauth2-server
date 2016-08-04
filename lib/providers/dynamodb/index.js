'use strict';

// imports
const AWS = require("aws-sdk");
const bcrypt = require('bcryptjs');
const uuid = require('node-uuid');
const OAuth2Error = require('../../error');


// exports
module.exports = function(options) {
    return new DynamoDbProvider(options);
};


// class definition
class DynamoDbProvider {

    constructor(options) {

        // TODO: add validation

        // initialize instance variables
        this.clients = options.clients;
        this.tokensTable = options.db.tokensTable;
        this.usersTable = options.db.usersTable;
        this.dbClient = new AWS.DynamoDB.DocumentClient({
            service: new AWS.DynamoDB({region: options.db.region })
        });
    }

    createUser(username, password, scopes, enabled = true) {

        return new Promise(function(resolve, reject) {

            // hash password
            bcrypt.hash(password, appConfig.saltFactor, function(err, passwordHash) {

                // stop on error
                if (err) {
                    return reject(err);
                }

                // persist
                const userId = uuid.v4();
                const options = {
                    TableName: usersTable,
                    Item: {
                        id: userId,
                        username: username,
                        passwordHash: passwordHash,
                        scopes: scopes,
                        emailVerified: false,
                        enabled: enabled
                    }
                };
                instance.dbClient.put(options, function (err, data) {
                    if (err) {
                        return reject(err);
                    }
                    else {
                        return resolve(userId);
                    }
                });
            });
        });
    }

    getClient(clientId, clientSecret) {

        const instance = this;
        return new Promise(function(resolve, reject) {

            console.log('fetching clients');

            // search for matching client
            for (var i in instance.clients) {

                // find matching client
                const client = instance.clients[i];
                if (client.id === clientId) {

                    // return grants if the secret matches
                    if (client.secret === clientSecret) {
                        return resolve(client);
                    }

                    // or stop processing (results in error)
                    break;
                }
            }

            // or raise error
            return resolve(null);
        });
    }

    getUser(username, password) {

        const instance = this;
        return new Promise(function(resolve, reject) {

            // query
            var options = {
                TableName: instance.usersTable,
                Key: {
                    username: username
                }
            };
            instance.dbClient.get(options, function (err, data) {

                // stop processing on error
                if (err) {
                    return reject(err);
                }

                // capture user
                const user = data.Item;

                // stop processing if user couldn't be found
                if (!user || !user.passwordHash) {
                    return resolve(null);
                }

                // stop processing if user isn't enabled
                if (!user.enabled) {
                    return reject(new OAuth2Error(400, 'account_disabled', 'User account is disabled'));
                }

                // compare password
                bcrypt.compare(password, user.passwordHash, function(err, res) {

                    // stop processing on error
                    if (err) {
                        return reject(err);
                    }

                    // or return user if passwords match
                    return resolve(res === true ? user : null);
                });
            });
        });
    }

    getAccessToken(accessToken) {

        const instance = this;
        return new Promise(function(resolve, reject) {

            // query
            var options = {
                TableName: instance.tokensTable,
                Key: {
                    accessToken: accessToken
                }
            };
            instance.dbClient.get(options, function (err, data) {
                if (err) {
                    reject(err);
                }
                else {
                    resolve(deserializeToken(data.Item));
                }
            });
        });
    }

    getRefreshToken(refreshToken) {

        const instance = this;
        return new Promise(function(resolve, reject) {

            // query
            var options = {
                TableName: instance.tokensTable,
                IndexName: 'index.refreshToken',
                KeyConditionExpression: "refreshToken = :refreshToken",
                ExpressionAttributeValues: {
                    ":refreshToken": refreshToken
                }
            };
            instance.dbClient.query(options, function (err, data) {
                if (err) {
                    return reject(err);
                }

                const items = data.Items || [];
                if (items.length === 1) {
                    return resolve(deserializeToken(items[0]));
                }
                else {
                    return resolve(null);
                }
            });
        });
    }

    saveToken(token, client, user) {

        const instance = this;
        return new Promise(function(resolve, reject) {

            // persist
            var options = {
                TableName: instance.tokensTable,
                Item: {
                    accessToken: token.accessToken,
                    accessTokenExpiry: token.accessTokenExpiresAt.getTime(),
                    refreshToken: token.refreshToken,
                    refreshTokenExpiry: token.refreshTokenExpiresAt.getTime(),
                    userId: user.id,
                    clientId: client.id,
                    scope: token.scope
                }
            };
            instance.dbClient.put(options, function (err, data) {
                if (err) {
                    reject(err);
                }
                else {
                    resolve(deserializeToken(options.Item));
                }
            });
        });
    }

    revokeToken(token) {

        const instance = this;
        return new Promise(function(resolve, reject) {

            // query
            var options = {
                TableName: instance.tokensTable,
                Key: {
                    accessToken: token.accessToken
                }
            };
            instance.dbClient.delete(options, function (err, data) {
                if (err) {
                    reject(err);
                }
                else {

                    // mark token as expired
                    token.refreshTokenExpiresAt = new Date(0);

                    // forward token to finalize revoke
                    resolve(token);
                }
            });
        });
    }

    validateScope(user, client, scope) {

        // FIXME: check intersection with client scopes to ensure security

        return new Promise(function(resolve, reject) {
            if (user.scopes.indexOf(scope) >= 0) {
                resolve(scope);
            }
            else {
                resolve(false);
            }
        });
    }
}


// helper methods
function deserializeToken(tokenData) {

    if (!tokenData) {
        return null;
    }

    const token = {
        accessToken: tokenData.accessToken,
        accessTokenExpiresAt: new Date(tokenData.accessTokenExpiry),
        refreshToken: tokenData.refreshToken,
        refreshTokenExpiresAt: new Date(tokenData.refreshTokenExpiry),
        user: {
            id: tokenData.userId
        },
        client: {
            id: tokenData.clientId
        },
        scope: tokenData.scope
    };
    return token;
}