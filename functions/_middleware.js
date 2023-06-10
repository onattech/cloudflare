import { generateStateValue, getParams, isBaseURL, printContextRequestHeaders, printKVStorage, printContextRequest, printResponse } from "./utils"
import cookie from "cookie"
import * as jose from "jose"

const DOMAIN = "dev-v3vdfzghznzkmkfh.us.auth0.com"
const CLIENT_ID = "YvxH3l3ISyUtPfLhh0lxbKfQ01vKEVOD"
const CLIENT_SECRET = "Fb4iyR08oqVrBuOA2V-4d4w-W-aWhCeO80pNVEpe_KfPaM7Fmqk1vqtcVX1lih4x"
const REDIRECT_URI = "http://localhost:8788/callback"

export async function onRequest(context) {
    console.log("\n📢 Middleware called at", context.request.url)

    // printContextRequest(context.request)
    // printContextRequestHeaders(context.request.headers)

    // Initialize KV state
    const kv = context.env.KV

    let { code, state: returnedState } = await getParams(context.request.url, ["code", "state"])

    // Step 0: Check for code in callback and make a call for tokens
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
        const tokens = await resp.json()
        console.log(JSON.stringify(tokens, null, 4))

        // Verify JWT. Auth0 recommends jose: https://jwt.io/libraries?language=JavaScript
        const jwks = jose.createRemoteJWKSet(new URL(`https://${DOMAIN}/.well-known/jwks.json`))
        try {
            const { payload } = await jose.jwtVerify(tokens.id_token, jwks, {
                audience: CLIENT_ID, // verify audience claim
                maxTokenAge: "12 hours", // verify max age of token
            })
            console.log("🚀 ~ file: _middleware.js:76 ~ onRequest ~ payload:", JSON.stringify(payload))
            return new Response(null, {
                status: 302,
                headers: { Location: "/" },
            })
        } catch (error) {
            console.log("🚀 ~ file: _middleware.js:60 ~ onRequest ~ error:", error)
            return new Response(null, {
                status: 500,
                headers: { Location: "/login" },
            })
        }
    }

    // Step 1: Make a call to get the code
    try {
        if (!code && isBaseURL(context.request.url)) {
            const requestState = await generateStateValue()
            console.log("Setting request state in KV:", requestState)
            await kv.put("State", requestState)

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
        }
    } catch (error) {
        console.error("Error:", error)
    }

    // Step 2: Verify state
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
