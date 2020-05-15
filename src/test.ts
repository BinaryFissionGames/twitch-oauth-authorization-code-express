import {refreshToken, setupTwitchOAuthPath} from "./oauth";
import express = require("express");
import * as session from "express-session";
import {SessionOptions} from "express-session";

const requiredEnvVars = [
    'SESSION_SECRET',
    'CLIENT_ID',
    'CLIENT_SECRET',
    'REDIRECT_URI'
];

for(let envVar of requiredEnvVars){
    if(process.env[envVar]){
        throw new Error('');
    }
}

type Env = {
    SESSION_SECRET: string;
    CLIENT_ID: string;
    CLIENT_SECRET: string;
    REDIRECT_URI: string;
}

const app = express();
let sess : SessionOptions = {
    secret: (<Env>process.env).SESSION_SECRET
};

app.use(session(sess)); // Need to set up session middleware!

setupTwitchOAuthPath({
    app: app, // The express app
    callback: ((req, res, info) =>  {
       req.session.access_token = info.access_token;
       req.session.refresh_token = info.refresh_token;
       res.redirect(307, "/success");
       res.end();
    }), // Callback when oauth info is gotten. Session info should be used
    client_id: (<Env>process.env).CLIENT_ID, // Twitch client ID
    client_secret: (<Env>process.env).CLIENT_SECRET, // Twitch client secret
    force_verify: true, // If true, twitch will always ask the user to verify. If this is false, if the app is already authorized, twitch will redirect immediately back to the redirect uri
    redirect_uri: (<Env>process.env).REDIRECT_URI, // URI to redirect to (this is the URI on this server, so the path defines the endpoint!)
    scopes: ['channel:read:subscriptions', 'user:read:email'] // List of scopes your app is requesting access to
});

app.get('/success', (req, res) => {
    if(req.session) {
        res.end("Auth token: " + req.session.access_token + ", Refresh token: " + req.session.refresh_token);
    } else {
        res.end();
    }
});

app.get('/refresh', (req, res) => {
    //This endpoint will use the refresh token to refresh the OAuth token.
    if(req.session && req.session.refresh_token) {
        refreshToken(req.session.refresh_token, (<Env>process.env).CLIENT_ID, (<Env>process.env).CLIENT_SECRET)
            .then((tokenInfo) => {
                if(req.session) {
                    req.session.access_token = tokenInfo.access_token;
                    req.session.refresh_token = tokenInfo.refresh_token;
                    res.end("New auth token: " + req.session.access_token + ", New refresh token: " + req.session.refresh_token);
                }
        });
    } else {

    }
});

app.listen(3000, function(){
    console.log("Listening on port 3000");
});
