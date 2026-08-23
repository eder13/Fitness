// @ts-check
/*jshint esversion: 6 */

const Config = require('./Config');
const Log = require('./Log');
const config = new Config();

const logFile = new Log();

function AuthConfig() {
    this.confidentialClient = {
        auth: {
            clientId: process.env.MSAL_APP_CLIENT_ID ?? '',
            clientSecret: process.env.MSAL_CLIENT_SECRET ?? '',
            authority: `https://${process.env.MSAL_DOMAIN_NAME}.ciamlogin.com/`,
            authorityMetadata: ''
        },
        system: {
            loggerOptions: {
                loggerCallback(_, message = '', containsPii = false) {
                    if (containsPii) {
                        return;
                    }
                    logFile.log(message, true, 1);
                },
                piiLoggingEnabled: false,
            },
        }
    };

    this.flows = {
        signUpSignIn: process.env.SIGN_UP_SIGN_IN_FLOW ?? 'signIn'
    }; 

    this.tenantSubdomain = process.env.MSAL_DOMAIN_NAME ?? '';
    this.tokenSecret = process.env.TOKEN_SECRET ?? 'this_has_to_be_exactly_32_chars_';
    this.tokenExpirationTime = process.env.TOKEN_EXPIRATION_TIME_MINUTES ?? '60m';
    this.tokenCookieName = process.env.TOKEN_COOKIE_NAME ?? 'f_t';
    this.redirectURI = process.env.REDIRECT_URI ?? `http://localhost:${process.env.PORT || config.LOCAL_PORT}/auth/callback`;
    this.postLogoutURI = process.env.POST_LOGOUT_REDIRECT_URI ?? `http://localhost:${process.env.PORT || config.LOCAL_PORT}`;
    this.openIdConnectInfoURI = `${this.confidentialClient.auth.authority}${process.env.MSAL_DOMAIN_NAME}.onmicrosoft.com/v2.0/.well-known/openid-configuration`;
}

module.exports = AuthConfig;
