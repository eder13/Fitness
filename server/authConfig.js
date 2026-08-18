// @ts-check
/*jshint esversion: 6 */

const Log = require('./Log');

const logFile = new Log();

function AuthConfig() {
    this.confidentialClient = {
        auth: {
            clientId: process.env.CLIENT_ID ?? '',
            clientSecret: process.env.CLIENT_SECRET ?? '',
            authority: process.env.AUTHORITY ?? ''
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

    this.redirectURI = process.env.REDIRECT_URI;
    this.postLogoutURI = process.env.POST_LOGOUT_REDIRECT_URI;
}

module.exports = AuthConfig;
