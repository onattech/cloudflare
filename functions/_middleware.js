export async function onRequest(context) {
    console.log("🚀 ~ file: _middleware.js:2 ~ onRequest ~ context:", JSON.stringify(context))

    console.log("Host: ", context.request.headers.get("host"))
    console.log("Referer: ", context.request.headers.get("referer"))
    console.log("Loku cookie: ", context.request.headers.get("loku-cookie"))
    const kv = context.env.KV
    console.log("🚀 ~ file: _middleware.js:8 ~ onRequest ~ kv:", kv)

    await kv.put("Task", "hi")
    const list = await kv.list()
    console.log("KV Task: ", await kv.get("Task"))

    for (const key of [...context.request.headers]) {
        console.log(key)
    }

    try {
        console.log("🚀 middleware returning...")
        return await context.next()
    } catch (err) {
        return new Response(`${err.message}\n${err.stack}`, { status: 500 })
    }
}

// curl -H "loku-cookie: hello" http://localhost:8788
