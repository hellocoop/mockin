// test/invite/helpers.js — shared utilities for invite specs.
//
// Mockin's accept handler fires the SET JWT to the configured events_uri
// via global fetch. Since fastify.inject() doesn't open a real socket,
// the spec swaps in a fetch stub that captures the body when the URL
// matches a known sink, and forwards everything else to the real fetch.
//
// Tests should call installFetchSink() in beforeEach and restoreFetch()
// in afterEach. Captured events live in the returned `captured` array.

export const SINK_URL = 'http://test-events.invalid/events'

export function installFetchSink() {
    const captured = []
    const original = globalThis.fetch
    globalThis.fetch = async (url, opts = {}) => {
        const u = typeof url === 'string' ? url : url?.toString?.()
        if (u === SINK_URL || u === SINK_URL + '/') {
            captured.push({
                url: u,
                method: opts.method || 'GET',
                headers: opts.headers || {},
                body: typeof opts.body === 'string'
                    ? opts.body
                    : opts.body ? Buffer.from(opts.body).toString() : '',
            })
            return new Response(null, { status: 202 })
        }
        return original(url, opts)
    }
    return { captured, restore: () => { globalThis.fetch = original } }
}
