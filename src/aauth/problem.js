// aauth/problem.js — RFC 9457 error responses.
//
// -09 adopted HTTP problem details for AAuth error bodies
// (§Error Response Format):
//
//   Content-Type: application/problem+json
//   { "error": "<code>", "detail": "<human-readable explanation>" }
//
// `error` is the REQUIRED extension member and is what a receiver keys on
// — AAuth defines no problem type URIs, so `type` says nothing. `detail`
// replaced `error_description`; the two are never both sent, because a
// reference implementation emitting both is what teaches every client to
// guess.
//
// This is the AAuth surface only. Mockin's OIDC endpoints keep the OAuth
// 2.0 error shape they are specified to use.

export const PROBLEM_CONTENT_TYPE = 'application/problem+json'

/**
 * Send an RFC 9457 problem response.
 *
 * @param {object} reply    Fastify reply
 * @param {number} status
 * @param {string} error    the AAuth error code
 * @param {string} [detail] human-readable, specific to this occurrence
 * @param {object} [extra]  further members (e.g. mission_status)
 */
export function problem(reply, status, error, detail, extra) {
    const body = { error }
    if (detail) body.detail = detail
    if (extra) Object.assign(body, extra)
    return reply
        .code(status)
        .header('Content-Type', PROBLEM_CONTENT_TYPE)
        .send(body)
}

/**
 * The same body as a plain object, for the places that build a response
 * tuple before they have a reply to send it on (verify-request.js).
 */
export function problemBody(error, detail, extra) {
    const body = { error }
    if (detail) body.detail = detail
    if (extra) Object.assign(body, extra)
    return body
}
