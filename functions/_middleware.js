import { generateStateValue, getParams } from "./utils"
import cookie from "cookie"
import * as jose from "jose"

/*
1. A user makes a request to the Cloudflare pages site.
2. If the user is not logged in, they are redirected to the login page. By default this is hosted by Auth0.
3. After logging in, the user is redirected back to the Workers application with a login code query parameter.
4. The Workers application takes the login code parameter and exchanges it with Auth0 for authorization tokens.
5. The Workers application verifies the tokens and extracts information about the user from them.
*/

// Global environment variables
let domain = ""
let client_id = ""
let client_secret = ""
let redirect_uri = ""
let cookiekey = ""
let cookiedomain = ""
let kv = null
const oneDay = 86400
const tenMinutes = 600

export async function onRequest(context) {
    console.log("\n📢 Middleware called at", context.request.url)

    // Assign environment variables
    domain = context.env.DOMAIN
    client_id = context.env.CLIENT_ID
    client_secret = context.env.CLIENT_SECRET
    redirect_uri = context.env.REDIRECT_URI
    cookiekey = context.env.COOKIEKEY
    cookiedomain = context.env.COOKIEDOMAIN
    kv = context.env.KV

    // Case 0: Check for session cookie to verify if the user is already logged in
    const auth = await verifySession(context.request)
    if (auth && auth.accessToken) {
        console.log("🔓 authenticated ⏩ middleware next...")
        return await context.next()
    }

    // Case 1: User isn't logged in. Gets redirected to Auth0 login page
    // which on successful login will redirect the user back to /callback
    // route with the code parameter
    const url = new URL(context.request.url)
    if (!auth && url.pathname !== "/callback") {
        console.log("🚏 🚥 1️⃣  User isn't logged in")
        try {
            const requestState = await generateStateParam(url.href)

            let authorizeUrl = `https://${domain}/authorize`
            let params = {
                response_type: "code",
                client_id,
                redirect_uri,
                state: requestState,
                scope: "openid profile",
            }

            authorizeUrl += "?" + new URLSearchParams(params).toString()
            console.log("Redirecting to Auth0 /authorize endpoint to get a code.....")
            return new Response(null, {
                status: 302,
                headers: {
                    Location: authorizeUrl,
                },
            })
        } catch (error) {
            console.error("Error:", error)
        }
    }

    // Case 2: User has successfully logged in at Auth0 login page and has been
    // redirected to /callback. Middleware will now verify code in callback and make a call for tokens
    // and store them in a cookie. This will make case 0 true next time the page is visited.
    if (url.pathname === "/callback") {
        console.log("🚏 🚥 2️⃣  Callback after login")

        const resultHeaders = await handleCallback(context.request)
        return new Response("", resultHeaders)
    }

    return new Response(`${err.message}\n${err.stack}`, { status: 500 })
}

///////////
// Utils
///////////

// Validate a token like those described here:
// https://auth0.com/docs/secure/tokens/access-tokens#sample-access-token
async function validateIDToken(token) {
    // Get remote keyset
    const jwks = jose.createRemoteJWKSet(new URL(`https://${domain}/.well-known/jwks.json`))

    // Verify JWT. Auth0 recommends jose: https://jwt.io/libraries?language=JavaScript
    const { payload } = await jose.jwtVerify(token, jwks, {
        audience: client_id, // verify audience claim
        maxTokenAge: oneDay, // verify max age of token
    })

    // Verify issuer claim
    const iss = new URL(payload.iss).hostname
    if (iss !== domain) {
        throw new Error(`Token iss value (${iss}) doesn't match configured AUTH0_DOMAIN`)
    }

    // Verify expires time
    const date = new Date()
    if (payload.exp < dateInSecs(date)) {
        throw new Error(`Token exp value is before current time`)
    }

    // Return payload
    return payload
}

/**
 * Verify a user's session against the KV store
 * @param {Request} request
 * @returns object with auth info or null
 */
async function verifySession(request) {
    const cookieHeader = request.headers.get("Cookie")
    // Check existing cookie
    if (cookieHeader && cookieHeader.includes(cookiekey)) {
        const cookies = cookie.parse(cookieHeader)
        if (typeof cookies[cookiekey] !== "string") {
            return null
        }

        const id = cookies[cookiekey]
        const kvData = await getSession(id)

        if (!kvData) {
            // We have a cookie but the KV data is missing or expired
            return null
        }

        let kvStored = null
        let userInfo = null
        try {
            // this is the response body from the Auth0 token endpoint, saved by persistAuth()
            kvStored = JSON.parse(kvData)
            userInfo = await validateIDToken(kvStored.id_token)
        } catch (err) {
            // Invalid stored session
            await deleteSession(id)
            // TODO: Redirect instead....
            throw new Error("Unable to parse auth information from Workers KV")
        }
        if (!userInfo || !userInfo.sub) {
            return null
        }

        const { access_token: accessToken, id_token: idToken } = kvStored
        return { accessToken, idToken, userInfo }
    }
    return null
}

// Returns initialization object for Response
async function handleCallback(request) {
    const url = new URL(request.url)

    // Check state param
    let state = url.searchParams.get("state")
    if (!state) {
        return null
    }
    state = decodeURIComponent(state)
    // Fetch stored state (from this.generateStateParam)
    const storedState = await kv.get(`state-${state}`)
    if (!storedState) {
        return null
    }

    // We're using code type flow, exchange for auth token
    const code = url.searchParams.get("code")
    if (code) {
        // Return value is defined by this.persistAuth
        return exchangeCode(code, storedState)
    }
    return null
}

// Make a request for an auth token and store it in KV
async function exchangeCode(code, storedState) {
    const body = JSON.stringify({
        grant_type: "authorization_code",
        client_id,
        client_secret,
        code,
        redirect_uri,
    })
    // Persist in KV
    return persistAuth(
        await fetch(`https://${domain}/oauth/token`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body,
        }),
        storedState
    )
}

/**
 * Calls this.validateToken and persists the token in KV session store
 * @param {Promise} exchange Response from the token exchange endpoint
 * @param {*} storedState Stored state from original auth request
 * @returns object with status and headers for setting the cookie
 */
async function persistAuth(exchange, storedState) {
    // Get the token exchange response
    const body = await exchange.json()
    if (body.error) {
        throw new Error(body.error)
    }

    // Validate and decode the token
    let decoded = null
    try {
        decoded = await validateIDToken(body.id_token)
    } catch (err) {
        return { status: 401 }
    }
    if (!decoded || !decoded.sub) {
        return { status: 401 }
    }

    // Store exchange response body in KV (session handling) after validation
    const id = await putSession(JSON.stringify(body))
    const date = new Date()
    date.setTime(date.getTime() + oneDay * 1000)

    // Make headers and set cookie with session ID
    const headers = {
        Location: new URL(storedState)?.href || "/",
        "Set-Cookie": serializedCookie(cookiekey, id, {
            expires: date,
        }),
    }

    return { headers, status: 302 }
}

// Returns a serialized cookie string ready to be set in headers
function serializedCookie(key, value, options = {}) {
    options = {
        domain: cookiedomain,
        httpOnly: true,
        path: "/",
        secure: true, // requires SSL certificate
        sameSite: "lax",
        ...options,
    }
    return cookie.serialize(key, value, options)
}

// Utility functions to handle session-storage in KV
// If we want an extra layer of security, we can encrypt the values in KV
async function deleteSession(id) {
    await kv.delete(`id-${id}`)
}

async function getSession(id) {
    return kv.get(`id-${id}`)
}

// Store session data and return the id
async function putSession(data) {
    const id = crypto.randomUUID()
    await kv.put(`id-${id}`, data, {
        expirationTtl: oneDay,
    })
    return id
}

/**
 * Gets the supplied date in seconds
 * @param {Date} d
 * @returns number
 */
export const dateInSecs = (d) => Math.ceil(Number(d) / 1000)

// Utility to store a state param in KV
// Predominantly the value is the URL requested by the user when this.authorize is called
async function generateStateParam(data) {
    const resp = await fetch("https://csprng.xyz/v1/api")
    const { Data: state } = await resp.json()
    await kv.put(`state-${state}`, data, {
        expirationTtl: tenMinutes,
    })
    return state
}

// Curl request with cookie header
// curl -H "loku-cookie: hello" http://localhost:8788

/*
Code request

curl "https://dev-v3vdfzghznzkmkfh.us.auth0.com/authorize?response_type=code&client_id=YvxH3l3ISyUtPfLhh0lxbKfQ01vKEVOD&redirect_uri=http://localhost:8787&state=5O54vujdYLB/nI9v9HhimR2sXWW6lF24rbMDdHLXM5s="
*/

/*
Token request

curl -X POST 'https://dev-v3vdfzghznzkmkfh.us.auth0.com/oauth/token' \
-H 'Content-Type: application/json' \
-d '{
    "grant_type": "authorization_code",
    "client_id": "YvxH3l3ISyUtPfLhh0lxbKfQ01vKEVOD",
    "client_secret": "Fb4iyR08oqVrBuOA2V-4d4w-W-aWhCeO80pNVEpe_KfPaM7Fmqk1vqtcVX1lih4x",
    "code": "I48LDrZI7_5u4HR04qnVms6y20wAWu4UjmVyOL3qdazUY",
    "redirect_uri": "http://localhost:8787/auth/callback"
}'
*/
