import { Router } from "itty-router"
import Auth0 from "./auth0"
import manifestJSON from "__STATIC_CONTENT_MANIFEST"
const assetManifest = JSON.parse(manifestJSON)

console.log("🚀 Top level")

// Create a new router
const router = Router()

// Auth middleware
const withAuth = async (request, env) => {
    const auth0 = new Auth0(env)
    const sessionData = await auth0.verifySession(request)
    if (!sessionData) {
        return respondWithError(401)
    }
    request.userInfo = sessionData.userInfo
}

// User info endpoint @withAuth
router.get("/userinfo", withAuth, async (request, env) => {
    return Response.json(request.userInfo)
})

// Login
router.get("/login", async (request, env) => {
    const auth0 = new Auth0(env)
    const returnPath = "/userinfo"
    // We're just forwarding to the userinfo endpoint for now
    const [authorized, payload] = await auth0.authorize(request, returnPath)
    if (!authorized) {
        // User is not authenticated. We're in the login flow
        // If the authorize method returns a payload with a redirectUrl, redirect the user
        if (payload && payload.redirectUrl) {
            return new Response("", {
                status: 302,
                headers: {
                    Location: payload.redirectUrl,
                },
            })
        } else {
            return respondWithError(500, "Unable to authenticate")
        }
    }
    // This takes the user to an arbitrary page in the app.
    // In this example, it's the /userinfo endpoint
    return new Response("", {
        status: 302,
        headers: {
            Location: returnPath,
        },
    })
})

// Catch-all route
router.all("*", () => {
    console.log("catch all route")
    return respondWithError(404)
})

export default {
    async fetch(request, env, ctx) {
        if (request.method === "GET" && new URL(request.url).pathname.startsWith("/assets")) {
            try {
                return await getAssetFromKV(
                    {
                        request,
                        waitUntil(promise) {
                            return ctx.waitUntil(promise)
                        },
                    },
                    {
                        ASSET_NAMESPACE: env.__STATIC_CONTENT,
                        ASSET_MANIFEST: assetManifest,
                    }
                )
            } catch (err) {
                if (err instanceof NotFoundError) {
                    return respondWithError(404)
                } else {
                    return respondWithError(500)
                }
            }
        } else {
            try {
                return router.handle(request, env)
            } catch (err) {
                // Handle exceptions thrown from router calls
                return respondWithError(500)
            }
        }
    },
}

// Auth0 callback
router.get("/auth/callback", async (request, env) => {
    const auth0 = new Auth0(env)
    const resultHeaders = await auth0.handleCallback(request)
    return new Response("", resultHeaders)
})

function respondWithError(e) {
    return new Response(e.stack || e, {
        status: 500,
        headers: {
            "Content-Type": "text/plain;charset=UTF-8",
        },
    })
}
