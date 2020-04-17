# Twitch OAuth Authorization Code Express 

This module has code that provides an easily configurable method to set up an OAuth
endpoint, as described [here](https://dev.twitch.tv/docs/authentication/getting-tokens-oauth/#oauth-authorization-code-flow).

This module also provides a method to refresh using the refresh token.

See src/test.ts for an example of how to use this library.

## Testing

To run the test code, first clone this repo.

Install TypeScript (`npm i -g typescript`).

Copy config.example.env; fill it with the required details (secret, client id, and the session secret, and redirect uri).

Install required packages (`npm install`).

Build the test script, as well as the library (`npm run build-test`)

Run the test script (`npm run test`).

Connect on localhost:3000 to test the authentication flow.

After you get an access token, you can connect to localhost:3000/refresh to refresh the OAuth token.
