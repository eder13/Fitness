// @ts-check
/*jshint esversion: 6 */

const AuthToken = require('./AuthToken');
const jose = require('jose');
const { convertExpirationTimeFromMinutesToSeconds } = require('./helpers');

class AuthService {
    _authProvider;

    constructor(authProvider) {
        this._authProvider = authProvider;
    }

    async callback(request, response, flow = '', code = '', decodedState = {}) {        
        switch(flow) {
            case this._authProvider.config.flows.signUpSignIn: {
                await this.login(request, response, code, decodedState);
                break;
            }
            default: {
                console.warn(`flow=${flow} does not match any callback ...`);
            }
        }
    }

    async login(request, response, code = '', decodedState = {}) {
        const authenticationResult = await this._authProvider.login(request, code, decodedState);
        
        if (!authenticationResult) {
            throw new Error('Could not acquire token...');
        }

        const { idToken, idTokenClaims } = authenticationResult;

        const authTokenPayload = new AuthToken();
        authTokenPayload.setToken(this._authProvider.TOKEN_NAME, { token: idToken, expiresAt: idTokenClaims.exp });
        authTokenPayload.setUser({
            id: idTokenClaims.sub,
            email: idTokenClaims.preferred_username,
            userName: idTokenClaims.name
        });

        if (!authTokenPayload.isValid()) {
            throw new Error('invalid auth token payload...');
        }

        const encrypted = {
            token: await this._signJWT(idTokenClaims.iss,'login', authTokenPayload),
            user: authTokenPayload.getUser()
        }

        await this._setAuthenticated(request, response, encrypted);
    }

    async _signJWT(issuer = '', subject = '', tokenPayload = new AuthToken(), type = 'token') {
        const encryptionKey = this.getEncryptionKey();
        const expirationTime = Math.floor(Date.now() / 1000) + convertExpirationTimeFromMinutesToSeconds(this._authProvider.config.tokenExpirationTime);
        const jwtPayload = {
            ...tokenPayload.build(),
            sub: subject,
            iat: Math.floor(Date.now() / 1000),
            exp: expirationTime,
            iss: issuer
        };

        const jsonPayload = Buffer.from(JSON.stringify(jwtPayload), 'utf-8');
        const encrypt = new jose.CompactEncrypt(jsonPayload).setProtectedHeader({ alg: 'dir', enc: 'A256GCM' });
        const jwe = await encrypt.encrypt(encryptionKey);
        return { token: jwe, expiresAt: expirationTime };
    }

    getEncryptionKey() {
        const KEY_LENGTH = 32;
        if (this._authProvider.config.tokenSecret.length !== KEY_LENGTH) {
            throw new Error(`Key length was not ${KEY_LENGTH}!`);
        }
        return new Uint8Array(Buffer.from(this._authProvider.config.tokenSecret, 'utf-8'));
    }

    async _setAuthenticated(request, response, encrypted) {
        request.session.isAuthenticated = true;
        request.session.user = encrypted.user;

        // ensure that session is saved before advancing, load does not happen before session is saved
        await new Promise((res, rej) => {
            request.session.save(function (err) {
                if (err) {
                    rej(err);
                }
                res(undefined);
            });
        });

        // save JWE inside Cookie
        response.cookie(this._authProvider.config.tokenCookieName, encrypted.token.token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
            maxAge: encrypted.token.expiresAt,
            path: '/'
        });
    }
}

module.exports = AuthService;
