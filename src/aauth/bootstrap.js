// aauth/bootstrap.js — POST /aauth/bootstrap (per draft-hardt-aauth-bootstrap).
//
// Signed under the HWK scheme using the agent's ephemeral key directly —
// there is no agent_token yet. Body carries the agent_server URL the
// bootstrap_token will be `aud`-bound to.
//
// Spec flow:
//   1. POST /aauth/bootstrap → 202 + AAuth-Requirement: requirement=interaction
//      with url+code, plus Location pointing at the pending URL.
//   2. Agent directs the user to {url}?code=…&callback=…
//   3. PS consent endpoint approves and redirects back.
//   4. Agent polls Location → 200 + bootstrap_token.
//
// Mockin auto-approves at the consent step (no user input). Tests that
// don't want to drive the full redirect can flip mock.auto_approve = true
// to short-circuit and pre-mark the pending entry as approved on creation.

import { randomUUID } from 'crypto'
import { SignJWT } from 'jose'
import {
    verify as httpSigVerify,
    generateSignatureErrorHeader,
    generateAcceptSignatureHeader,
    generateAcceptSignatureSchemeHeader,
} from '@hellocoop/httpsig'

import { ISSUER } from '../config.js'
import { privateKey, kid } from './keys.js'
import { SIGNING_ALG } from './algorithms.js'
import { directedSub } from './subject.js'
import { getConfig, mockErrorFor } from './mock.js'
import { checkBodySigning } from './verify-request.js'
import { problem } from './problem.js'
import { createPending, updatePending } from './state.js'

// -11: a body-carrying request to a PS endpoint covers content-digest and
// content-type on top of the base profile.
const ACCEPT_SIG = generateAcceptSignatureHeader({
    label: 'sig',
    components: [
        '@method', '@authority', '@path',
        'content-type', 'content-digest',
        'signature-key',
    ],
})

// Bootstrap accepts hwk (initial) or jwt (completion announcement).
const ACCEPT_SIG_SCHEME = generateAcceptSignatureSchemeHeader(['hwk', 'jwt'])

const BOOTSTRAP_TOKEN_TTL = 300 // 5 minutes

export async function issueBootstrapToken({ agent_server, ephemeral_jwk }) {
    const iat = Math.floor(Date.now() / 1000)
    const payload = {
        iss: ISSUER,
        dwk: 'aauth-person.json',
        aud: agent_server,
        // Same derivation as person and auth tokens — see subject.js.
        sub: directedSub(agent_server),
        cnf: { jwk: ephemeral_jwk },
        iat,
        exp: iat + BOOTSTRAP_TOKEN_TTL,
    }
    const bootstrap_token = await new SignJWT(payload)
        .setProtectedHeader({ alg: SIGNING_ALG, typ: 'aa-bootstrap+jwt', kid })
        .setJti(randomUUID())
        .sign(privateKey)
    return { bootstrap_token, expires_in: BOOTSTRAP_TOKEN_TTL }
}

export const bootstrap = async (req, reply) => {
    const cfg = getConfig()

    const url = new URL(
        req.url,
        `http://${req.headers.host || 'localhost'}`,
    )

    const sigResult = await httpSigVerify({
        method: req.method,
        authority: url.host,
        path: url.pathname,
        query: url.search ? url.search.slice(1) : '',
        headers: req.headers,
        body: req.rawBody || '',
    })

    if (!sigResult.verified) {
        const noSig = !req.headers.signature && !req.headers['signature-input']
        if (noSig) {
            reply
                .header('Accept-Signature', ACCEPT_SIG)
                .header('Accept-Signature-Scheme', ACCEPT_SIG_SCHEME)
            return problem(reply, 401, 'signature_required')
        }
        const headers = {}
        if (sigResult.signatureError) {
            headers['Signature-Error'] = generateSignatureErrorHeader(
                sigResult.signatureError,
            )
        }
        for (const [k, v] of Object.entries(headers)) reply.header(k, v)
        return problem(reply, 401, 'signature_verification_failed', sigResult.error)
    }

    // -11: the body signature must cover content-digest and content-type.
    const bodyFailure = checkBodySigning(req, sigResult)
    if (bodyFailure) {
        for (const [k, v] of Object.entries(bodyFailure.headers || {})) {
            reply.header(k, v)
        }
        return problem(
            reply, bodyFailure.status,
            bodyFailure.body.error, bodyFailure.body.detail,
        )
    }

    // Two valid request flavours per the wallet PS pattern:
    //   1. sig=hwk — initial bootstrap (no agent_token yet)
    //   2. sig=jwt + aa-agent+jwt — Bootstrap Completion Announcement,
    //      sent after the agent server mints the agent_token, so the PS
    //      can record (user, agent_server) → agent_id durably. Mockin
    //      doesn't persist bindings; we just acknowledge.
    if (sigResult.keyType === 'jwt' && sigResult.jwt) {
        const typ = sigResult.jwt.header?.typ
        if (typ !== 'aa-agent+jwt') {
            return problem(
                reply, 401, 'invalid_jwt', `expected aa-agent+jwt, got ${typ}`,
            )
        }
        return reply.code(204).send()
    }
    if (sigResult.keyType !== 'hwk' || !sigResult.publicKey) {
        return problem(
            reply, 401, 'invalid_key',
            'bootstrap requires hwk or jwt Signature-Key scheme',
        )
    }
    // Keep cnf.jwk minimal — { kty, crv, x, alg }. httpsig 2.0 (RFC 9864)
    // requires every JWK to carry a fully-specified alg; the hwk scheme now
    // transmits it, so sigResult.publicKey.alg is e.g. 'Ed25519' (never the
    // polymorphic 'EdDSA', which 2.0 rejects). Verifiers that later use
    // this cnf.jwk need it, so it stays in.
    const { kty, crv, x, alg } = sigResult.publicKey
    const ephemeral_jwk = { kty, crv, x, alg }

    const body = req.body || {}
    if (!body.agent_server || typeof body.agent_server !== 'string') {
        return problem(reply, 400, 'invalid_request', 'missing agent_server')
    }

    const mockErr = mockErrorFor('bootstrap')
    if (mockErr) {
        return problem(reply, 400, mockErr, `Mock error: ${mockErr}`)
    }

    // Always go through the deferred flow — that's what the spec mandates
    // and what spec-compliant clients (e.g. playground.aauth.dev) expect.
    // mock.auto_approve = true pre-marks the entry as approved so the very
    // first poll returns 200 without any consent redirect (used in tests).
    const { id, code } = createPending({
        kind: 'bootstrap',
        agent_server: body.agent_server,
        ephemeral_jwk,
    })
    if (cfg.auto_approve) {
        updatePending(id, { status: 'approved' })
    }

    const location = `${ISSUER}/aauth/pending/${id}`
    const consentUrl = `${ISSUER}/aauth/consent`

    return reply
        .code(202)
        .header('Location', location)
        .header(
            'AAuth-Requirement',
            `requirement=interaction; url="${consentUrl}"; code="${code}"`,
        )
        .header('Retry-After', '0')
        .header('Cache-Control', 'no-store')
        .send({
            status: 'pending',
            location,
            requirement: 'interaction',
            code,
        })
}
