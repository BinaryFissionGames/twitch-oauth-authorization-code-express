import {refreshToken, setupTwitchOAuthPath} from "./oauth";
import express = require("express");
import * as session from "express-session";
import {SessionOptions} from "express-session";

const app = express();
let sess : SessionOptions = {
    secret: process.env.SESSION_SECRET
};

if (app.get('env') === 'production') {
    app.set('trust proxy', 1); // trust first proxy
    sess.cookie.secure = true; // serve secure cookies
}

app.use(session(sess)); // MAKE SURE TO SET UP THE SESSION MIDDLEWARE!

setupTwitchOAuthPath({
    app: app, // The express app
    client_id: process.env.CLIENT_ID, // Twitch client ID
    client_secret: process.env.CLIENT_SECRET, // Twitch client secret
    force_verify: true, // If true, twitch will always ask the user to verify. If this is false, if the app is already authorized, twitch will redirect immediately back to the redirect uri
    landing_path: "/success", // Path that will be redirected to once the session has been filled in with the auth token
    redirect_uri: process.env.REDIRECT_URI, // URI to redirect to (this is the URI on this server, so the path defines the endpoint!)
    scopes: ['channel:read:subscriptions'] // List of scopes your app is requesting access to
});

app.get('/success', (req, res) => {
    res.end("Auth token: " + req.session.access_token + ", Refresh token: " + req.session.refresh_token);
});

app.get('/refresh', (req, res) => {
    //This endpoint will use the refresh token to refresh the OAuth token.
    refreshToken(req.session, process.env.CLIENT_ID, process.env.CLIENT_SECRET).then(() => {
        res.end("New auth token: " + req.session.access_token + ", New refresh token: " + req.session.refresh_token);
    });
});

app.listen(3000, function(){
    console.log("Listening on port 3000");
});
