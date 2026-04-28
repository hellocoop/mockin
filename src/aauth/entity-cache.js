// aauth/entity-cache.js — fetch + cache external metadata and JWKS.
//
// The PS verifies agent_tokens (signed by an agent server) and
// resource_tokens (signed by a resource server). Both require fetching the
// signer's JWKS via its `.well-known/{dwk}` document.
//
// For tests and offline environments the mock config can preload entries
// into `trusted_servers` so no network call is needed.

import { getConfig } from './mock.js'

const TTL_MS = 5 * 60 * 1000
const cache = new Map() // key = `${url}::${dwk}` → { metadata, jwks, expires }

export const AGENT_DWK = 'aauth-agent.json'
export const RESOURCE_DWK = 'aauth-resource.json'
export const PERSON_DWK = 'aauth-person.json'

export function resetEntityCache() {
    cache.clear()
}

export function wkUrl(serverUrl, dwk) {
    return `${serverUrl.replace(/\/$/, '')}/.well-known/${dwk}`
}

function trustedFor(serverUrl) {
    const trusted = getConfig().trusted_servers || {}
    return trusted[serverUrl] || trusted[serverUrl.replace(/\/$/, '')] || null
}

async function loadEntity(serverUrl, dwk) {
    const trusted = trustedFor(serverUrl)
    if (trusted?.metadata && trusted?.jwks) {
        return { metadata: trusted.metadata, jwks: trusted.jwks }
    }

    const metaRes = await fetch(wkUrl(serverUrl, dwk))
    if (!metaRes.ok) {
        throw new Error(`metadata fetch failed: ${metaRes.status}`)
    }
    const metadata = await metaRes.json()
    const jwksUri = metadata.jwks_uri
    if (!jwksUri) throw new Error('metadata missing jwks_uri')
    const jwksRes = await fetch(jwksUri)
    if (!jwksRes.ok) throw new Error(`jwks fetch failed: ${jwksRes.status}`)
    const jwks = await jwksRes.json()
    return { metadata, jwks }
}

export async function getEntity(serverUrl, dwk) {
    const key = `${serverUrl}::${dwk}`
    const now = Date.now()
    const cached = cache.get(key)
    if (cached && cached.expires > now) return cached
    const entity = await loadEntity(serverUrl, dwk)
    const entry = { ...entity, expires: now + TTL_MS }
    cache.set(key, entry)
    return entry
}

export async function getJWK(serverUrl, dwk, kid) {
    const { jwks } = await getEntity(serverUrl, dwk)
    if (!jwks?.keys || !Array.isArray(jwks.keys)) {
        throw new Error('jwks has no keys array')
    }
    if (kid) {
        const match = jwks.keys.find((k) => k.kid === kid)
        if (!match) throw new Error(`kid ${kid} not in jwks`)
        return match
    }
    return jwks.keys[0]
}
