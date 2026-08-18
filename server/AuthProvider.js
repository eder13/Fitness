// @ts-check
/*jshint esversion: 6 */

var AuthConfig = require('./authConfig');
var msal = require('@azure/msal-node');

class AuthProvider {
    _cryptoProvider = new msal.CryptoProvider();
    _config = new AuthConfig();

    constructor() {
        this._confidentialClient = new msal.ConfidentialClientApplication(this._config.confidentialClient);
    }

    async getAuthUrl(request, state = {}, authCodeUrlRequestParams = {}, authCodeRequestParams = {}) {
        // TODO: Do this check
        /* if (!this.config.msalConfig.auth.authorityMetadata) {
            const authorityMetadata = await this.getAuthorityMetadata();
            this.config.msalConfig.auth.authorityMetadata = JSON.stringify(authorityMetadata);
        } */
        
        await this._setRequestAuthValues(request, 
                        {
                ...authCodeUrlRequestParams,
                redirectUri: this._config.redirectURI,
                state: this.base64Encode(JSON.stringify(state))
            },
            { ...authCodeRequestParams, redirectUri: this._config.redirectURI, code: '' },
        );

        return await this._getAuthCodeUrl(request, state.nonce);
    }

    async _setRequestAuthValues(request, authCodeUrlRequest = {}, authCodeRequest = {}) {
        // Generate PKCE Codes before starting the authorization flow
        const { verifier, challenge } = await this._cryptoProvider.generatePkceCodes();

        // Set generated PKCE codes and method as session vars
        request.session.pkceCodes = {
            challengeMethod: 'S256',
            verifier: verifier,
            challenge: challenge,
        };
        request.session.authCodeUrlRequest = {
            ...authCodeUrlRequest,             
            responseMode: 'form_post', // recommended for confidential clients
            codeChallenge: request.session.pkceCodes.challenge,
            codeChallengeMethod: request.session.pkceCodes.challengeMethod,
        };
        request.session.authCodeRequest = authCodeRequest;
    }

    async _getAuthCodeUrl(request, nonce = '') {
        try {
            const authCodeUrlResponse = await this._confidentialClient.getAuthCodeUrl(request.session.authCodeUrlRequest);
            const authCodeUrlResponseObject = new URL(authCodeUrlResponse);
            authCodeUrlResponseObject.searchParams.set('nonce', nonce);
            return authCodeUrlResponseObject.toString();
        } catch(e) {
            console.error(e);
            return '';
        }
    }

    guid() {
        return this._cryptoProvider.createNewGuid();
    }

    base64Encode(par = '') {
        return this._cryptoProvider.base64Encode(par);
    }
}

module.exports = AuthProvider;
