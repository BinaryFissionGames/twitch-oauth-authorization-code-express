import * as assert from 'assert'
import {addClient, addOrGetUser, clearDb, closeMockServer, setUpMockAuthServer} from "twitch-mock-oauth-server/dist";
import * as express from 'Express';
import {OAuthTokenCallback, refreshToken, setupTwitchOAuthPath, TokenInfo} from "../oauth";
import * as http from 'http';
import {SessionOptions} from "express-session";
import session = require("express-session");
import {makeClientRequestToken, validateTokenInfo} from "./util";

const clientId = 'thisisaclientid';
const clientSecret = 'thisisacliendsecret';
const tokenUrl = 'http://localhost:3080/token';
const authUrl = 'http://localhost:3080/authorize';
const redirectUri = 'http://localhost:3000/auth';
const app = express();
const mockApp = express();

const userName = 'testuser';

let server: http.Server;
let mockServer: http.Server;
let userSessionId: string = '';
let tokenCallback: OAuthTokenCallback | undefined; // Tests should set this in order to catch token info

describe('OAuth', function () {
    before(async () => {
        await setUpMockAuthServer({
            token_url: tokenUrl,
            authorize_url: authUrl,
            logErrors: true,
            expressApp: mockApp
        });

        let sess: SessionOptions = {
            secret: 'aioghuihdg89hf783hjhrbhc89',
            resave: false,
            saveUninitialized: false
        };

        app.use(session(sess));

        setupTwitchOAuthPath({
            app,
            authorize_url: authUrl,
            token_url: tokenUrl,
            callback: (req, res, info: TokenInfo) => {
                if (tokenCallback) {
                    tokenCallback(req, res, info);
                }
                res.end();
            },
            client_id: clientId,
            client_secret: clientSecret,
            redirect_uri: redirectUri
        });

        return new Promise((resolve, reject) => {
            mockServer = mockApp.listen(3080, () => {
                server = app.listen(3000, resolve).on('error', reject);
            }).on('error', reject);
        })
    });

    beforeEach(async () => {
        tokenCallback = undefined;
        await clearDb();
        await addClient(clientId, clientSecret);
        let user = await addOrGetUser(userName);
        userSessionId = <string>user.sessionId;
    });

    after(async () => {
        await clearDb();
        await closeMockServer(true);
        server.close();
        mockServer.close();
    });

    describe('OAuth Flow', function () {
        it("Should return an oAuth token when the redirect uri is called", function (): Promise<void> {
            this.timeout(5000);
            this.slow(500);
            return new Promise(async (resolve, reject) => {
                tokenCallback = (req, res, tokenInfo: TokenInfo) => {
                    try {
                        validateTokenInfo(tokenInfo);
                    } catch (e) {
                        return reject(e);
                    }

                    return resolve();
                };

                try {
                    let response = await makeClientRequestToken(userSessionId, redirectUri);
                    assert.strictEqual(Math.floor(response.statusCode / 100), 2, 'Did not get a 200 response code');
                } catch (e) {
                    reject(e);
                }

            });
        });

        it('Should allow a returned oAuth token to be refreshed', async function() {
            this.timeout(5000);
            this.slow(500);
            return new Promise(async (resolve, reject) => {
                tokenCallback = async (req, res, tokenInfo: TokenInfo) => {
                   try{
                        validateTokenInfo(tokenInfo);

                        let newToken = await refreshToken(tokenInfo.refresh_token, clientId, clientSecret, undefined, tokenUrl);
                        validateTokenInfo(newToken);

                        if(newToken.refresh_token == tokenInfo.refresh_token && newToken.access_token == tokenInfo.refresh_token){
                            return reject(new Error('Returned/refreshed token was exactly the same as the original token'));
                        }
                    } catch (e) {
                       return reject(e);
                   }

                    return resolve();
                };

                try {
                    let response = await makeClientRequestToken(userSessionId, redirectUri);
                    assert.strictEqual(Math.floor(response.statusCode / 100), 2, 'Did not get a 200 response code');
                } catch (e) {
                    reject(e);
                }
            });
        });
    });
});