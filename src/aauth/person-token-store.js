// aauth/person-token-store.js — issued person tokens, keyed by `jti`.
//
// Protocol -11 §Resource Token Verification step 6:
//
//   "A PS MUST look up the person token identified by `person_token_jti`
//    among those it issued, and MUST verify that `ps`, `sub`,
//    `mission_s256`, and `tenant` match that token exactly, rejecting the
//    resource token on any mismatch or omission."
//
// The spec implies this store without stating it (AAuth issue #87). It is
// what makes mission stripping detectable: comparing claims alone would
// not do, because an agent running concurrent missions holds several
// person tokens for the same resource.
//
// A mock keeps it in memory and expires entries with the token itself.

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
