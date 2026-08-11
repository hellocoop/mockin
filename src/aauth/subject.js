// aauth/subject.js — directed (pairwise) subject derivation.
//
// Protocol -11 §Person Token Structure: the person token's `sub` MUST be
// "the same value the PS uses in the `sub` claim of auth tokens it issues
// for this `aud`". Every token mockin issues therefore derives its `sub`
// here and nowhere else — two derivations would make every resource token
// fail the PS's own step-6 comparison (§Resource Token Verification).
//
// The derivation is a mock, not a security boundary: SHA-256 over
// `{user.sub}|{aud}`, base64url. Stable across restarts for a given user
// and audience, and different per audience so resources cannot correlate.

import { createHash } from 'crypto'

import defaultUser from '../users.js'

/**
 * @param {string} aud   the audience the identifier is directed at — a
 *                       resource URL for person/auth tokens, the agent
 *                       server URL for bootstrap tokens.
 * @param {string} [userSub]
 */
export function directedSub(aud, userSub = defaultUser.sub) {
    return createHash('sha256').update(`${userSub}|${aud}`).digest('base64url')
}
