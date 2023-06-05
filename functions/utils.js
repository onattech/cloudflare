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
 * const url = "http://localhost:8788/?code=9XmAS9oo6ZUAcfU3M6M9232_2tIlODCGyVl8nGU_dyWc-&state=5O54vujdYLB%2FnI9v9HhimR2sXWW6lF24rbMDdHLXM5s%3D";
 * const { code, state } = getParams(url, ["code", "state"]);
 * console.log('Code:', code); // Outputs: "Code: 9XmAS9oo6ZUAcfU3M6M9232_2tIlODCGyVl8nGU_dyWc-"
 * console.log('State:', state); // Outputs: "State: 5O54vujdYLB%2FnI9v9HhimR2sXWW6lF24rbMDdHLXM5s%3D"
 * ```
 *
 * @example
 * ### Example 2: Extracting a missing query parameter
 * ```javascript
 * const url = "http://localhost:8788/?code=9XmAS9oo6ZUAcfU3M6M9232_2tIlODCGyVl8nGU_dyWc-&state=5O54vujdYLB%2FnI9v9HhimR2sXWW6lF24rbMDdHLXM5s%3D";
 * const { missing, state } = getParams(url, ["missing", "state"]);
 * console.log('Missing:', missing); // Outputs: "Missing: null"
 * console.log('State:', state); // Outputs: "State: 5O54vujdYLB%2FnI9v9HhimR2sXWW6lF24rbMDdHLXM5s%3D"
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
