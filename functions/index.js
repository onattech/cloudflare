export async function onRequest(context) {
    const { request, env, params, waitUntil, next, data } = context
    console.log("🚀 ~ data:", data)
    console.log("🚀 ~ next:", next)
    console.log("🚀 ~ waitUntil:", waitUntil)
    console.log("🚀 ~ params:", params)
    console.log("🚀 ~ env:", env)
    console.log("🚀 ~ request:", request)

    return new Response("Hello, Worker!")
}
