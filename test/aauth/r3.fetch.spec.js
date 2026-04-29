// Unit coverage for r3.fetchR3Document's outbound HTTP signature.
//
// draft-hardt-aauth-r3 §Security Considerations requires the resource
// to reject R3 fetches that aren't signed by its AS (in our case, the
// PS). Pre-1.6.1 mockin sent a bare GET, so a spec-compliant resource
// would 401. These tests pin the new behavior:
//   - fetchR3Document signs with sig=jwks_uri pointing at our existing
//     /.well-known/aauth-person.json metadata, and
//   - the signature actually verifies with @hellocoop/httpsig — proving
//     a real resource doing the same verify mockin's r3demo / Admin do
//     would accept it.
//
// We stub globalThis.fetch so the test runs in-process: no listening
// port, no network. The stub plays both the R3 endpoint (capture +
// verify the signed request) and mockin's well-known/JWKS (so the
// httpsig verifier can resolve the signing key by id+dwk).

import { expect } from 'chai'
import { verify as httpsigVerify } from '@hellocoop/httpsig'

import { fetchR3Document } from '../../src/aauth/r3.js'
import { publicJwk, kid as MOCKIN_KID } from '../../src/aauth/keys.js'
import { ISSUER } from '../../src/config.js'

const R3_URI = 'https://rs.test.example/r3/abc'
const SAMPLE_DOC = {
    version: '1',
    vocabulary: 'urn:aauth:vocabulary:openapi',
    operations: [{ operationId: 'getProfile' }],
}

function jsonResponse(body, status = 200) {
    return new Response(JSON.stringify(body), {
        status,
        headers: { 'content-type': 'application/json' },
    })
}

// Compute r3_s256 over the bytes the stub will actually serve.
async function sha256B64url(str) {
    const buf = new TextEncoder().encode(str)
    const hash = await crypto.subtle.digest('SHA-256', buf)
    return Buffer.from(hash).toString('base64url')
}

describe('aauth/r3.fetchR3Document — signed R3 fetch', function () {
    const realFetch = globalThis.fetch
    let captured

    afterEach(function () {
        globalThis.fetch = realFetch
        captured = undefined
    })

    function installStub({ docBytes, on401 = false }) {
        captured = null
        globalThis.fetch = async (url, init) => {
            // httpsig.fetch passes a URL instance; well-known/JWKS pulls
            // pass a string. Cover both.
            const u = typeof url === 'string'
                ? url
                : (url instanceof URL ? url.href : (url?.url ?? String(url)))
            // Mockin's well-known + JWKS — needed so the signature
            // verifier can resolve our key by (id, dwk, kid).
            if (u === `${ISSUER}/.well-known/aauth-person.json`) {
                return jsonResponse({
                    issuer: ISSUER,
                    jwks_uri: `${ISSUER}/aauth/jwks.json`,
                })
            }
            if (u === `${ISSUER}/aauth/jwks.json`) {
                return jsonResponse({ keys: [publicJwk] })
            }
            // R3 endpoint — capture the request so the test can inspect
            // headers, then optionally 401 (to pre-fix behavior) or
            // verify the signature and return the doc.
            if (u === R3_URI) {
                // Normalize Headers (httpsig.fetch may pass a Headers
                // instance) to a plain object so chai property
                // assertions work and httpsigVerify accepts it.
                let headers = init?.headers || {}
                if (headers instanceof Headers) {
                    headers = Object.fromEntries(headers.entries())
                }
                captured = {
                    method: init?.method || 'GET',
                    headers,
                }
                if (on401) {
                    return new Response('unauthorized', { status: 401 })
                }
                return new Response(docBytes, {
                    status: 200,
                    headers: { 'content-type': 'application/json' },
                })
            }
            throw new Error(`unexpected fetch in test: ${u}`)
        }
    }

    it('signs the outbound GET with sig=jwks_uri', async function () {
        const docBytes = JSON.stringify(SAMPLE_DOC)
        const expected_s256 = await sha256B64url(docBytes)
        installStub({ docBytes })

        const result = await fetchR3Document({ r3_uri: R3_URI, expected_s256 })
        expect(result, result instanceof Error ? result.message : '').to.not.be.an.instanceof(Error)
        expect(result.document).to.deep.equal(SAMPLE_DOC)

        // Headers we promise the resource server can check.
        expect(captured).to.not.be.null
        const h = captured.headers
        expect(h).to.have.property('signature')
        expect(h).to.have.property('signature-input')
        expect(h).to.have.property('signature-key')
        // Signature-Key declares the jwks_uri scheme + our metadata.
        const sigKey = h['signature-key']
        expect(sigKey).to.match(/sig=jwks_uri/)
        expect(sigKey).to.include(`id=${JSON.stringify(ISSUER)}`)
        expect(sigKey).to.include(`kid=${JSON.stringify(MOCKIN_KID)}`)
        expect(sigKey).to.include('dwk="aauth-person.json"')
    })

    it("produces a signature a spec-compliant resource will accept", async function () {
        // The stub intercepts the outbound request before it actually
        // hits a server, so to "verify like a real resource would" we
        // re-run @hellocoop/httpsig.verify on the captured headers
        // afterward. This is the same call admin/svr/aauth/metadata.js
        // and r3demo/src/index.ts make on incoming /r3/:id requests.
        const docBytes = JSON.stringify(SAMPLE_DOC)
        const expected_s256 = await sha256B64url(docBytes)
        installStub({ docBytes })

        await fetchR3Document({ r3_uri: R3_URI, expected_s256 })
        expect(captured).to.not.be.null

        const url = new URL(R3_URI)
        const verifyResult = await httpsigVerify({
            method: 'GET',
            authority: url.host,
            path: url.pathname,
            query: '',
            headers: captured.headers,
        })

        expect(verifyResult.verified, verifyResult.error).to.equal(true)
        expect(verifyResult.keyType).to.equal('jwks_uri')
        expect(verifyResult.jwks_uri).to.deep.equal({
            id: ISSUER,
            kid: MOCKIN_KID,
            dwk: 'aauth-person.json',
        })
    })

    it('surfaces a 401 from the resource as an Error (regression)', async function () {
        // Pre-1.6.1, the bare GET would surface r3 fetch returned 401
        // here. Now that we sign, this only happens if a resource
        // doesn't trust mockin's keys — but the error path should still
        // round-trip cleanly so /aauth/token can return invalid_resource_token.
        installStub({ on401: true })
        const result = await fetchR3Document({
            r3_uri: R3_URI,
            expected_s256: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        })
        expect(result).to.be.an.instanceof(Error)
        expect(result.message).to.include('r3 fetch returned 401')
    })
})
