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

        // save JWE inside a Cookie
        response.cookie(this._authProvider.config.tokenCookieName, encrypted.token.token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
            maxAge: encrypted.token.expiresAt, // TODO: I am not sure this is needed or even right value
            path: '/'
        });
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

    async decryptAndValidateJWE(jwe = '') {
        const { plaintext } = await jose.compactDecrypt(
            jwe,
            this.getEncryptionKey()
        );
        const payload = JSON.parse(
            new TextDecoder().decode(plaintext)
        );

        if (!this._authProvider.confidentialClient.config.auth?.authorityMetadata) {
            await this._authProvider.receiveAuthorityMetaData();
        }

        let jwksUrl = '';

        try {
            jwksUrl = JSON.parse(this._authProvider.confidentialClient.config.auth?.authorityMetadata).jwks_uri;
        } catch {
            console.error('Could not read jwks_url...');
            return false;
        }

        const token = payload[this._authProvider.TOKEN_NAME].token;
        const expiresAt = payload[this._authProvider.TOKEN_NAME].expiresAt;
        const currentUnixTimeInSeconds = Number((Date.now() / 1000).toFixed(0));
        const JWKS = jose.createRemoteJWKSet(new URL(jwksUrl));
        const { payload: jwtVerifyPayload } = await jose.jwtVerify(token, JWKS);

        if (!((expiresAt ?? Infinity) > currentUnixTimeInSeconds)) {
            throw new Error( 'Token already expired!');
        }

        if (!(jwtVerifyPayload.aud && jwtVerifyPayload.aud === this._authProvider.confidentialClient.config.auth?.clientId)) {
            throw new Error('The Token was audited from an unknown clientId!');
        }

        if (jwtVerifyPayload.iat && currentUnixTimeInSeconds < jwtVerifyPayload.iat) {
            throw new Error( 'The Token was issued somewhere in the future!');
        }

        if (jwtVerifyPayload.nbf && currentUnixTimeInSeconds < jwtVerifyPayload.nbf) {
            throw new Error('The Token is not yet valid and can not be used!');
        }

        return {
            id: jwtVerifyPayload.sub,
            username: jwtVerifyPayload.preferred_username,
            email: jwtVerifyPayload.preferred_username
        };
    }
}

module.exports = AuthService;
