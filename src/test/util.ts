import {TokenInfo} from "../oauth";
import {CookieJar} from "tough-cookie";
import {Response} from "got";
import got from "got";

function validateTokenInfo(tokenInfo: TokenInfo): void {
    if (!tokenInfo.refresh_token || !tokenInfo.access_token) {
        throw new Error('Missing refresh token or access token');
    }

    if (tokenInfo.expiry_date.getTime() <= Date.now()) {
        throw new Error('Expiry date is in the past');
    }

    if (!tokenInfo.scopes) {
        new Error('Scope array not initialized');
    }
}

async function makeClientRequestToken(sessionId: string, redirectUri: string): Promise<Response<unknown>> {
    let response: Response;
    try {
        const cookieJar = new CookieJar();
        await cookieJar.setCookie(`oauth_session=${sessionId}`, 'http://localhost:3080');
        response = await got.get(redirectUri, {followRedirect: true, cookieJar});
    } catch (e) {
        if (e instanceof got.HTTPError) {
            throw new Error(`HTTPError: statusCode: ${e.response.statusCode}; Error: ${e.response.body}`);
        }
        throw e;
    }

    return response;
}

export {
    validateTokenInfo,
    makeClientRequestToken
}