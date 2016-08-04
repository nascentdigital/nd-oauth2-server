'use strict';

var _ = require('lodash');
const OAuthError = require('oauth2-server/lib/errors/oauth-error');
const util = require('util');


function OAuth2Error(code, name, message, properties) {
    properties = _.assign({
        code: code,
        name: name
    }, properties);

    OAuthError.call(this, message, properties);
}

util.inherits(OAuth2Error, OAuthError);

module.exports = OAuth2Error;