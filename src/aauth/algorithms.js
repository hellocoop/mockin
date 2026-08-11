// aauth/algorithms.js — the accepted-algorithm table.
//
// Protocol -10/-11 §Signature Algorithms: `alg` is REQUIRED, MUST be fully
// specified, and implementations MUST NOT accept `none`, the polymorphic
// `EdDSA` identifier, or any symmetric algorithm. There is no transition
// allowance, so mockin emits and accepts `Ed25519` only — an `EdDSA` JWT
// is rejected rather than tolerated.
//
// `@hellocoop/httpsig` 2.0 already excludes `EdDSA` from its own
// SignatureAlgorithm table, so this list covers the JWTs mockin verifies
// itself: agent tokens, sub-agent tokens, and resource tokens.

export const SIGNING_ALG = 'Ed25519'

export const ACCEPTED_JWT_ALGS = [SIGNING_ALG]

/**
 * jose accepts `EdDSA` and would happily verify it. Reject it (and any
 * other unlisted alg) explicitly so the failure names the algorithm.
 * @returns {string|null} an error message, or null when acceptable.
 */
export function checkJwtAlg(alg) {
    if (!alg) return 'JWT header missing alg'
    if (!ACCEPTED_JWT_ALGS.includes(alg)) {
        return `unacceptable alg "${alg}": ${ACCEPTED_JWT_ALGS.join(', ')} required (a fully-specified identifier; the polymorphic "EdDSA" MUST NOT be accepted)`
    }
    return null
}
