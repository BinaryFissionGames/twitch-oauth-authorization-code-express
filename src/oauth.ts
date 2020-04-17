import * as https from "https";
import * as crypto from "crypto";
import {Application} from "express";
import {URL} from "url";

type TwitchAccessTokenResponse = {
    access_token: string,
    refresh_token: string,
    expires_in: number,
    scope: string[],
    token_type: string
}

type TwitchRefreshTokenResponse = {
    access_token: string,
    refresh_token: string,
    scope: string
}

// app is the express application, redirect_uri is the specified witch API redirect_uri
// landing_path is the final path that the API redirects.
// scopes is a list of strings, identifying the requested scopes.
type TwitchOAuthPathOptions = {
    app: Application, // Express application to add path to
    redirect_uri: string, //URI twitch will redirect to with OAUTH code
    landing_path: string, // Final path to redirect the user to after session is filled with OAuth token
    scopes?: string[], //list of scopes you are requesting
    client_id: string, //Registered client id
    client_secret: string, // Registered client secret
    force_verify?: boolean // If true, user will always be prompted to confirm authorization.
};

// Assumes that the express application has the session middleware installed
function setupTwitchOAuthPath(options: TwitchOAuthPathOptions) {
    let redirect_uri_obj = new URL(options.redirect_uri);
    options.app.get(redirect_uri_obj.pathname, function (req, res) {
        if (req.query && req.query.code) {
            //Have code, make request with
            //Also assert state token is OK
            if (!req.query.state || req.query.state !== req.session.oauth_state) {
                //TODO better error handling?
                res.end('Invalid state token returned from twitch.');
                return;
            }

            let https_request = https.request(`https://id.twitch.tv/oauth2/token` +
                `?client_id=${options.client_id}` +
                `&client_secret=${options.client_secret}` +
                `&code=${req.query.code}` +
                `&grant_type=authorization_code` +
                `&redirect_uri=${encodeURIComponent(options.redirect_uri)}`,
                {
                    method: 'POST'
                },
                (https_res) => {
                    let rawData = '';
                    https_res.on('data', (chunk) => {
                        rawData += chunk;
                    });

                    https_res.on('end', () => {
                        let data: TwitchAccessTokenResponse = JSON.parse(rawData);
                        req.session.access_token = data.access_token;
                        req.session.refresh_token = data.refresh_token;
                        res.redirect(307, options.landing_path);
                    });
                }
            );

            https_request.on("error", (e) => {
                //TODO better error handling?
                res.send('Got error');
                res.end(e);
            });

            https_request.end();
        } else {
            // RFC 6749 suggests using a hash of the session cookie. Here, we use a random 16 bytes instead.
            // This may be more computationally expensive -
            //TODO see if there are benefits to switching to hashing session cookie instead
            req.session.oauth_state = crypto.randomBytes(16).toString('hex');

            let scope_string: string = options.scopes ? options.scopes.join(' ') : '';

            res.redirect(307, `https://id.twitch.tv/oauth2/authorize` +
                `?client_id=${options.client_id}` +
                `&redirect_uri=${encodeURIComponent(options.redirect_uri)}` +
                `&response_type=code` +
                `&scope=${encodeURIComponent(scope_string)}` +
                `&state=${req.session.oauth_state}` +
                (options.force_verify ? `&force_verify=${options.force_verify}` : ''));
        }
    });
}

// Refresh token from sessions - it is up to the user of this library to properly synchronize
// such that only one consumer for the related OAuth token calls this at a time.
async function refreshToken(session: Express.Session, client_id: string, client_secret: string, scopes?: string[]) : Promise<void>{
    return new Promise((resolve, reject) => {
        let scope_string: string = scopes ? scopes.join(' ') : undefined;

        let https_request = https.request(`https://id.twitch.tv/oauth2/token` +
            `?refresh_token=${session.refresh_token}` +
            `&client_id=${client_id}` +
            `&client_secret=${client_secret}` +
            `&grant_type=refresh_token` +
            (scope_string ? `&scope=${encodeURIComponent(scope_string)}` : ''),
            {
                method: 'POST',
                timeout: 10000
            },
            (https_res) => {
                let rawData = '';

                https_res.on('data', (chunk) => {
                    rawData += chunk;
                });

                https_res.on('end', () => {
                    if(Math.floor(https_res.statusCode / 100) != 2){
                        //Not a 2xx status code; Meaning this is an error.
                        reject(JSON.parse(rawData));
                        return;
                    }

                    let data: TwitchRefreshTokenResponse = JSON.parse(rawData);
                    session.access_token = data.access_token;
                    session.refresh_token = data.refresh_token;
                    resolve();
                });
            }
        );

        https_request.on("error", (e) => {
            reject(e);
        });

        https_request.end();
    });
}

export {
    setupTwitchOAuthPath,
    refreshToken
}