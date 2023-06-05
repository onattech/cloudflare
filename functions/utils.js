/**
 * Generates a secure random state value for use in OAuth and other authentication methods.
 *
 * This function generates a random binary array, encodes it in base64, and then URL-encodes the result, replacing '+' with '-', '/' with '_', and removing trailing '=' characters. This ensures the generated state value is URL-safe.
 *
 * The state value is 24 characters long, providing a good balance between security and length.
 *
 * @returns {Promise<string>} A promise that resolves to a string containing the generated state value.
 *
 * @example
 * ### Example 1: Generating a state value with then()
 * ```javascript
 * generateStateValue().then(state => {
 *   console.log('State:', state);
 *   // Outputs: "State: ..." (a random 24-character URL-safe string)
 * });
 * ```
 *
 * @example
 * ### Example 2: Generating a state value with async/await
 * ```javascript
 * (async () => {
 *   const state = await generateStateValue();
 *   console.log('State:', state);
 *   // Outputs: "State: ..." (a random 24-character URL-safe string)
 * })();
 * ```
 */
export async function generateStateValue() {
    let array = new Uint8Array(24)
    crypto.getRandomValues(array)
    let state = btoa(String.fromCharCode.apply(null, array)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
    return state
}

/**
 * Extracts the specified query parameters from a URL.
 *
 * @param {string} url - The URL from which to extract the query parameters.
 * @param {string[]} keys - An array of the names of the query parameters to extract.
 * @returns {object} An object containing the specified query parameters. Each key is a query parameter name, and the corresponding value is the query parameter's value. If a query parameter is not present in the URL, its value will be `null`.
 *
 * @example
 * ### Example 1: Extracting existing query parameters
 * ```javascript
 * const url = "http://localhost:8788/?code=9Xm&state=5O5";
 * const { code, state } = getParams(url, ["code", "state"]);
 * console.log('Code:', code); // Outputs: "Code: 9Xm"
 * console.log('State:', state); // Outputs: "State: 5O5"
 * ```
 *
 * @example
 * ### Example 2: Extracting a missing query parameter
 * ```javascript
 * const url = "http://localhost:8788/?code=9Xm&state=5O5";
 * const { missing, state } = getParams(url, ["missing", "state"]);
 * console.log('Missing:', missing); // Outputs: "Missing: null"
 * console.log('State:', state); // Outputs: "State: 5O5"
 * ```
 */
export function getParams(url, keys) {
    let params = new URLSearchParams(new URL(url).search)
    let result = {}

    keys.forEach((key) => {
        result[key] = params.get(key)
    })

    return result
}

/**
 * Checks if a URL is a base URL without any subdirectories.
 *
 * @export
 * @param {string} url - The URL to check.
 * @returns {boolean} - Returns `true` if the URL is a base URL without any subdirectories, `false` otherwise.
 *
 * @example
 * ### Examples
 * ```
 * isBaseURL('http://localhost:8788/?code=x123&state=y5O5') ✅ true
 * isBaseURL('http://localhost:8788/') ✅ true
 * isBaseURL('http://localhost:8788') ✅ true
 * isBaseURL('http://localhost:8788/members/?code=x123&state=y5O5') ❌ false
 * ```
 */
export function isBaseURL(url) {
    const parsedUrl = new URL(url)
    return parsedUrl.pathname === "/"
}

/**
 * Converts a URL string into a plain JavaScript object and prints it.
 * The object includes all the properties of a JavaScript URL object,
 * with `searchParams` converted into a plain object.
 *
 * @param {string} url - The URL string to be parsed and printed.
 *
 * @example
 * printURL('http://www.example.com/path?query=value&team=blue');
 *
 * ```js
 * { href: 'http://www.example.com/path?query=value&team=blue',
 *   origin: 'http://www.example.com',
 *   protocol: 'http:',
 *   username: '',
 *   password: '',
 *   host: 'www.example.com',
 *   hostname: 'www.example.com',
 *   port: '',
 *   pathname: '/path',
 *   search: '?query=value&team=blue',
 *   searchParams: {
 *       query: 'value',
 *       team: 'blue'
 *   },
 *   hash: '' }
 * ```
 */
function printURL(url) {
    url = new URL(url)
    let keys = Object.getOwnPropertyNames(Object.getPrototypeOf(url))

    let urlObject = {}
    for (let key of keys) {
        if (typeof url[key] !== "function") {
            if (key === "searchParams") {
                urlObject[key] = Object.fromEntries(url[key])
            } else {
                urlObject[key] = url[key]
            }
        }
    }

    console.log(urlObject)
}

/**
 * Converts a HTTP request headers object into a plain JavaScript object and prints it.
 * The object includes all the properties of the headers object.
 *
 * @param {http.IncomingMessage} request - The HTTP request object.
 *
 * @example
 * // prints: { 'content-type': 'application/json', 'user-agent': 'my-agent' }
 * printHeaders(request);
 */
export function printHeaders(headers) {
    let headersObject = {}
    for (let key of [...headers]) {
        headersObject[key[0]] = key[1]
    }

    console.log("Headers: ", JSON.stringify(headersObject, null, 4))
}

export function printRequest(request, isFull = false) {
    let headersObject = {}
    for (let key of [...request.headers]) {
        headersObject[key[0]] = key[1]
    }

    let requestObject = {
        keepalive: request.keepalive,
        integrity: request.integrity,
        ...(isFull && { cf: JSON.parse(JSON.stringify(request.cf)) }),
        ...(isFull && {
            signal: {
                reason: request.signal.reason || "undefined",
                aborted: request.signal.aborted,
                throwIfAborted: "function",
                addEventListener: "function",
                removeEventListener: "function",
                dispatchEvent: "function",
            },
        }),
        ...(isFull && {
            fetcher: {
                fetch: "function",
                connect: "function",
                get: "function",
                put: "function",
                delete: "function",
            },
        }),
        redirect: request.redirect,
        headers: isFull ? headersObject : undefined,
        url: request.url,
        method: request.method,
        clone: isFull ? "function" : undefined,
        bodyUsed: request.bodyUsed,
        body: request.body,
        arrayBuffer: isFull ? "function" : undefined,
        text: isFull ? "function" : undefined,
        json: isFull ? "function" : undefined,
        formData: isFull ? "function" : undefined,
        blob: isFull ? "function" : undefined,
    }

    console.log("Context.Request: ", JSON.stringify(requestObject, null, 4))
}

export async function printKVStorage(KV) {
    let KVStateObject = {}
    let list = await KV.list()

    for (let key of list.keys) {
        KVStateObject[key.name] = await KV.get(key.name)
    }

    console.log("KV all: ", JSON.stringify(KVStateObject, null, 4))
}
