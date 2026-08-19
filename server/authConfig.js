// @ts-check
/*jshint esversion: 6 */

const Log = require('./Log');

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
        signUpSignIn: process.env.SIGN_UP_SIGN_IN_FLOW
    };

    this.redirectURI = process.env.REDIRECT_URI;
    this.postLogoutURI = process.env.POST_LOGOUT_REDIRECT_URI;
    this.openIdConnectInfoURI = `${this.confidentialClient.auth.authority}${process.env.MSAL_DOMAIN_NAME}.onmicrosoft.com/v2.0/.well-known/openid-configuration`
}

module.exports = AuthConfig;
