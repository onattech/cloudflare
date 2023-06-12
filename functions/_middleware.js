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

export async function onRequest(context) {
    console.log("\n📢 Middleware called at", context.request.url)

    // Assign environment variables
    domain = context.env.DOMAIN
    client_id = context.env.CLIENT_ID
    client_secret = context.env.CLIENT_SECRET
    redirect_uri = context.env.REDIRECT_URI
    cookiekey = context.env.COOKIEKEY
    cookiedomain = context.env.COOKIEDOMAIN

    // Initialize KV state
    kv = context.env.KV

    let { code } = await getParams(context.request.url, ["code", "state"])
    const parsedUrl = new URL(context.request.url)

    // Check for session
    const keys = await verifySession(context.request)

    // Case 1: User isn't logged in. Gets redirected to Auth0 login page
    // which on successful login will redirect the user back to /callback
    // route with the code parameter
    if (!keys && parsedUrl.pathname !== "/callback") {
        console.log("🚏 🚥 1️⃣  User isn't logged in")
        try {
            const requestState = await generateStateValue()
            console.log("Setting request state in KV:", requestState)
            await kv.put("State", requestState, {
                expirationTtl: 600,
            })

            let url = "https://dev-v3vdfzghznzkmkfh.us.auth0.com/authorize"
            let params = {
                response_type: "code",
                client_id,
                redirect_uri,
                state: requestState,
                scope: "openid profile",
            }

            url += "?" + new URLSearchParams(params).toString()
            console.log("Redirecting to Auth0 /authorize endpoint to get a code.....")
            return new Response(null, {
                status: 302,
                headers: {
                    Location: url,
                },
            })
        } catch (error) {
            console.error("Error:", error)
        }
    }

    // Case 2: Check for code in callback and make a call for tokens
    if (parsedUrl.pathname === "/callback") {
        console.log("🚏 🚥 2️⃣  Callback after login")
        console.log("Code returned from Auth0:", code)

        const body = JSON.stringify({
            grant_type: "authorization_code",
            client_id,
            client_secret,
            audience: client_id,
            code,
            redirect_uri,
        })

        const resp = await fetch(`https://${domain}/oauth/token`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body,
        })
        const KVState = await kv.get("State")
        return new Response("", await persistAuth(resp, KVState))
    }

    // Case 3: User is logged in, continue
    try {
        console.log("⏩ middleware next...")
        return await context.next()
    } catch (err) {
        return new Response(`${err.message}\n${err.stack}`, { status: 500 })
    }
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
        maxTokenAge: "12 hours", // verify max age of token
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
            console.log("We have a cookie but the KV data is missing or expired")
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
            await kv.delete(id)
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
    date.setDate(date.getDate() + 1) // 1 day

    // Make headers and set cookie with session ID
    const headers = {
        // Location: new URL(storedState)?.href || "/",
        Location: "/",
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
        expirationTtl: 86400, // 1 day
    })
    return id
}

/**
 * Gets the supplied date in seconds
 * @param {Date} d
 * @returns number
 */
export const dateInSecs = (d) => Math.ceil(Number(d) / 1000)

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
