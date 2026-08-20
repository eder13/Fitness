// @ts-check
/*jshint esversion: 6 */

class AuthService {
    _authProvider;

    constructor(authProvider) {
        this._authProvider = authProvider;
    }

    async callback(request, flow = '', code = '', decodedState = {}) {        
        switch(flow) {
            case this._authProvider.config.flows.signUpSignIn: {
                await this.login(request, code, decodedState);
                break;
            }
            default: {
                console.warn(`flow=${flow} does not match any callback ...`);
            }
        }
    }

    async login(request, code = '', decodedState = {}) {
        const authenticationResult = await this._authProvider.login(request, code, decodedState);
        
        if (!authenticationResult) {
            console.error('Could not acquire token...');
            return;
        }

        console.log('#####** authenticationResult', authenticationResult);

        // TODO: Save all the payload and the idToken inside a JWT and then on a signed encrypted cookie ...
        // example to just save it inside a session
        //req.session.idToken = authenticationResult.idToken;
        //req.session.account = authenticationResult.account;
        //req.session.isAuthenticated = true;
    }
}

module.exports = AuthService;
