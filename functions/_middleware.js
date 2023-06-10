import { generateStateValue, getParams, isBaseURL, printContextRequestHeaders, printKVStorage, printContextRequest, printResponse } from "./utils"
import cookie from "cookie"
import * as jose from "jose"

const DOMAIN = "dev-v3vdfzghznzkmkfh.us.auth0.com"
const CLIENT_ID = "YvxH3l3ISyUtPfLhh0lxbKfQ01vKEVOD"
const CLIENT_SECRET = "Fb4iyR08oqVrBuOA2V-4d4w-W-aWhCeO80pNVEpe_KfPaM7Fmqk1vqtcVX1lih4x"
const REDIRECT_URI = "http://localhost:8788/callback"
const COOKIEKEY = "loku-cookie"

export async function onRequest(context) {
    console.log("\n📢 Middleware called at", context.request.url)

    // printContextRequest(context.request)
    // printContextRequestHeaders(context.request.headers)

    // Initialize KV state
    const kv = context.env.KV

    let { code, state: returnedState } = await getParams(context.request.url, ["code", "state"])

    // Check for session
    const keys = await verifySession(context.request)
    console.log("🚀 ~ file: _middleware.js:24 ~ onRequest ~ keys:", keys)

    // Step 1: Make a call to get the code
    if (!code && isBaseURL(context.request.url)) {
        try {
            const requestState = await generateStateValue()
            console.log("Setting request state in KV:", requestState)
            await kv.put("State", requestState, {
                expirationTtl: 600,
            })

            let url = "https://dev-v3vdfzghznzkmkfh.us.auth0.com/authorize"
            let params = {
                response_type: "code",
                client_id: CLIENT_ID,
                redirect_uri: REDIRECT_URI,
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

    // Step 2: Check for code in callback and make a call for tokens
    const parsedUrl = new URL(context.request.url)
    if (parsedUrl.pathname === "/callback") {
        console.log("Callback route detected...")
        console.log("Code returned from Auth0:", code)

        const body = JSON.stringify({
            grant_type: "authorization_code",
            client_id: CLIENT_ID,
            client_secret: CLIENT_SECRET,
            audience: CLIENT_ID,
            code,
            redirect_uri: REDIRECT_URI,
        })

        const resp = await fetch(`https://${DOMAIN}/oauth/token`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body,
        })
        printResponse(resp)
        const KVState = await kv.get("State")

        persistAuth(resp, KVState)

        return new Response(null, {
            status: 302,
            headers: { Location: "/" },
        })
    }

    // Step 3: Verify state
    if (code) {
        const KVState = await kv.get("State")
        KVState === returnedState
            ? console.log("State returned with Auth0 code matches with State in KV Storage ✅")
            : console.log("State returned with Auth0 code doesn't match with State in KV Storage ❌")
    }

    // Step 3: Make a call with code to get access token

    // DEBUGGING
    // printHeaders(context.request.headers)

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
    const jwks = jose.createRemoteJWKSet(new URL(`https://${DOMAIN}/.well-known/jwks.json`))

    // Verify JWT. Auth0 recommends jose: https://jwt.io/libraries?language=JavaScript
    const { payload } = await jose.jwtVerify(token, jwks, {
        audience: this.clientId, // verify audience claim
        maxTokenAge: "12 hours", // verify max age of token
    })

    // Verify issuer claim
    const iss = new URL(payload.iss).hostname
    if (iss !== this.domain) {
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
    if (cookieHeader && cookieHeader.includes(COOKIEKEY)) {
        const cookies = cookie.parse(cookieHeader)
        if (typeof cookies[COOKIEKEY] !== "string") {
            return null
        }

        const id = cookies[COOKIEKEY]
        const kvData = await kv.get(id)

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
        // Location: new URL(storedState).href || "/",
        Location: "/",
        "Set-Cookie": serializedCookie(COOKIEKEY, id, {
            expires: date,
        }),
    }
    return { headers, status: 302 }
}

// Returns a serialized cookie string ready to be set in headers
function serializedCookie(key, value, options = {}) {
    options = {
        domain: this.cookieDomain,
        httpOnly: true,
        path: "/",
        secure: true, // requires SSL certificate
        sameSite: "lax",
        ...options,
    }
    return cookie.serialize(key, value, options)
}

// Store session data and return the id
async function putSession(data) {
    const id = crypto.randomUUID()
    await KV.put(`id-${id}`, data, {
        expirationTtl: 86400, // 1 day
    })
    return id
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
