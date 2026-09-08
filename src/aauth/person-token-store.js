// aauth/person-token-store.js — issued person tokens, keyed by `jti`.
//
// Protocol -11 §Person Token Endpoint (issue #152): "A PS MUST record, for
// each person token it issues, the `jti`, the `aud`, and the `exp`, and,
// once it has presented the token to an access server, which one, and MUST
// keep the record until the token's `exp` plus clock skew." The record is
// for revocation, not verification — resource token verification step 6
// verifies the `presented_token` the agent sends, under this PS's own
// signature (verify-presented-token.js), and consults no record.
//
// mockin has no revocation endpoint and no AS federation, so the store is
// introspection only: tests can ask which jtis are live. A mock keeps it
// in memory and expires entries with the token itself.

const issued = new Map() // jti → record

/**
 * @param {object} record
 * @param {string} record.jti
 * @param {string} record.ps                the PS that issued it (our ISSUER)
 * @param {string} record.sub               directed subject
 * @param {string} record.aud               the resource the token names
 * @param {string} [record.mission_s256]
 * @param {string} [record.tenant]
 * @param {string} [record.agent_jkt]       thumbprint of cnf.jwk
 * @param {number} record.exp               seconds since epoch
 */
export function recordPersonToken(record) {
    issued.set(record.jti, record)
    return record
}

/** Returns the record, or null when unknown or expired (expired entries are dropped). */
export function getPersonToken(jti) {
    const record = issued.get(jti)
    if (!record) return null
    if (record.exp * 1000 <= Date.now()) {
        issued.delete(jti)
        return null
    }
    return record
}

export function clearPersonTokens() {
    issued.clear()
}

/** Test/introspection helper — the jtis currently held. */
export function issuedPersonTokenIds() {
    return [...issued.keys()]
}
