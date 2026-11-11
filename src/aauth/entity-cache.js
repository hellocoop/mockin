// aauth/entity-cache.js — external metadata and JWKS.
//
// The PS verifies agent_tokens (signed by an agent server), resource_tokens
// (signed by a resource server) and AS-issued auth tokens. Each requires the
// signer's JWKS via its `.well-known/{dwk}` document.
//
// The documents are fetched and cached by the shared key resolver
// (key-resolver.js): timeout, refetch floor, refresh on an unknown kid and
// the log of every fetch are its concern.
//
// For tests and offline environments the mock config can preload entries
// into `trusted_servers` so no network call is needed.

import { getConfig } from './mock.js'
import { getKeyResolver, keyStore } from './key-resolver.js'

export const AGENT_DWK = 'aauth-agent.json'
export const RESOURCE_DWK = 'aauth-resource.json'
export const PERSON_DWK = 'aauth-person.json'

export function resetEntityCache() {
    keyStore.clear()
}

export function wkUrl(serverUrl, dwk) {
    return `${baseOf(serverUrl)}/.well-known/${dwk}`
}

// The identifier as the resolver keys it: no trailing slash, so the metadata
// URL is the one wkUrl names. draft-hardt-httpbis-signature-key-08: the
// metadata document must carry an `issuer` byte-equal to it; the resolver
// checks that (requireIssuer, its default) before it caches the document.
function baseOf(serverUrl) {
    return serverUrl.replace(/\/$/, '')
}

function trustedFor(serverUrl) {
    const trusted = getConfig().trusted_servers || {}
    return trusted[serverUrl] || trusted[baseOf(serverUrl)] || null
}

/**
 * The signer's metadata and JWKS.
 *
 * @param {string} serverUrl  the token's `iss`
 * @param {string} dwk        the metadata document name
 * @param {string} [kid]      the key the caller is about to look for. When
 *   the cached JWKS lacks it, the resolver fetches the documents once more
 *   (key rotation), subject to its refetch floor, and throws when the key
 *   is still missing.
 * @returns {Promise<{ metadata: object, jwks: { keys: object[] } }>}
 */
export async function getEntity(serverUrl, dwk, kid) {
    const trusted = trustedFor(serverUrl)
    if (trusted?.metadata && trusted?.jwks) {
        return { metadata: trusted.metadata, jwks: trusted.jwks }
    }

    const id = baseOf(serverUrl)
    const resolver = getKeyResolver()
    if (kid) await resolver.resolveKey({ id, dwk, kid })
    const lookup = kid ? { kid } : {}
    const metadata = await resolver.getMetadata(id, dwk, lookup)
    const jwks = await resolver.getJwks(id, dwk, lookup)
    return { metadata, jwks }
}

export async function getJWK(serverUrl, dwk, kid) {
    const trusted = trustedFor(serverUrl)
    if (!(trusted?.metadata && trusted?.jwks) && kid) {
        return getKeyResolver().resolveKey({ id: baseOf(serverUrl), dwk, kid })
    }
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
