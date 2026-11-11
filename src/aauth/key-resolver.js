// aauth/key-resolver.js — the one key resolver for AAuth signers.
//
// Every key mockin discovers goes through one @hellocoop/httpsig key
// resolver on one store: {id}/.well-known/{dwk} → jwks_uri → JWKS.
//   - the issuer of an agent, resource or auth token (entity-cache.js);
//   - a request signed through the jwks_uri scheme, resolved inside
//     httpsig verify() (verify-request.js, pending.js, bootstrap.js).
//
// Policy is the library's (draft-hardt-httpbis-signature-key, Caching and
// Performance): a 5 s fetch timeout, redirects refused, a one-minute refetch
// floor that also holds after a failed fetch, one refresh on an unknown kid,
// Cache-Control max-age honored down to the floor and capped at maxTtlMs.

import { createKeyResolver, BoundedTtlCache } from '@hellocoop/httpsig'

// The TTL entity-cache.js used before the resolver.
const MAX_TTL_MS = 5 * 60 * 1000

// Entries are keyed by URLs taken from requests that have not been verified
// yet, so the store is bounded.
const MAX_ENTRIES = 500

export const keyStore = new BoundedTtlCache(MAX_ENTRIES)

// Every outbound metadata or JWKS fetch, one JSON line each: stdout when it
// succeeded, stderr when it failed. Mockin has no log pipeline of its own;
// the line goes wherever the process output goes.
const onFetch = (event) => {
    const line = JSON.stringify({
        level: event.ok ? 30 : 40,
        event: 'aauth.mockin.key_fetch',
        msg: `${event.doc} fetch ${event.ok ? 'ok' : 'failed'} (${event.reason}): ${event.url}`,
        ...event,
    })
    if (event.ok) console.log(line)
    else console.warn(line)
}

const DEFAULTS = {
    store: keyStore,
    maxTtlMs: MAX_TTL_MS,
    // Mockin is a test server: its own ISSUER defaults to
    // http://127.0.0.1:3333 and the agents and resources it talks to are
    // test servers on plain http.
    requireHttps: false,
    onFetch,
}

let resolver = createKeyResolver(DEFAULTS)

export const getKeyResolver = () => resolver

// Test seam: rebuild the resolver with overrides (e.g. minRefetchIntervalMs: 0
// to exercise a refetch without waiting out the floor) and empty the store.
// Call with no arguments to restore the defaults.
export const _resetKeyResolver = (overrides = {}) => {
    keyStore.clear()
    resolver = createKeyResolver({ ...DEFAULTS, ...overrides })
}
