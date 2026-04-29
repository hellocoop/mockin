// invite.js — invitation flow (mirrors wallet's external contract).
//
// Wallet is canon. Mockin replicates the wire shapes (request/response,
// SET JWT format) and behaviour visible to apps. What can't be replicated
// in mockin is documented inline:
//
//   - No fastify session: POST /invite reads inviter context from the
//     request body instead of req.session.
//   - No real email: sendmail() is a log-only stub.
//   - No DB: invitations live in an in-memory Map, cleared on DELETE /mock.
//   - No MX / disposable-email checks: emails just have to look valid.
//   - SET fired on PUT /invitation/:id (accept) instead of after the
//     invitee's downstream OIDC consent. Mockin lacks the session
//     continuity to defer it; same JWT, slightly earlier in the timeline.
//
// SET JWT shape matches wallet exactly:
//   {
//     iss, aud=client_id, jti, iat, exp,
//     "https://hello.coop/invite/created": {
//       inviter, invitee: { sub, email },
//       role?, tenant?, state?
//     }
//   }

import { randomUUID } from 'crypto'
import { ISSUER } from './config.js'
import sign from './sign.js'
import defaultUser from './users.js'

const EXPIRY_SECONDS = 7 * 24 * 60 * 60 // 7 days
const EVENT_CLAIM = 'https://hello.coop/invite/created'

// Per RFC 5321 + the regex wallet uses (invite.js).
const EMAIL_REGEX =
    // eslint-disable-next-line no-useless-escape
    /^[a-zA-Z0-9.!#$%&'*+\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/

const invitations = new Map() // id → invitation

let MOCK = {
    error: null,            // 'invitation_not_found' | 'invitation_expired' | 'invalid_email' | ...
    error_endpoint: null,   // 'create' | 'accept' | 'decline' | 'invitation' | 'resend' | 'retract' | 'report'
    auto_accept: false,     // GET /invite auto-accepts inline + fires SET
    expires_in: EXPIRY_SECONDS,
}

function newId() {
    return 'inv_' + randomUUID().replace(/-/g, '').slice(0, 24)
}

// Stable email-keyed identifier; cosmetic. Wallet uses util.makeID('email', email).
function makeInviteeSubject(email) {
    return `email|${email.toLowerCase()}`
}

function sanitizeInvitation(i) {
    return {
        id: i.id,
        invitee: i.invitee.email,
        prompt: i.prompt,
        lastEmailedAt: i.lastEmailedAt,
        expiresAt: i.expiresAt,
        createdAt: i.createdAt,
        app_name: i.app_name || null,
        host: i.host || null,
        image_uri: i.client?.image_uri || null,
        dark_image_uri: i.client?.dark_image_uri || null,
        inviter: i.inviter?.email || null,
        client_id: i.client_id,
    }
}

async function sendEvent(invitation, pubSubId) {
    const data = {
        inviter: invitation.inviter.sub,
        invitee: { sub: pubSubId, email: invitation.invitee.email },
    }
    if (invitation.state) data.state = invitation.state
    if (invitation.role) data.role = invitation.role
    if (invitation.tenant) data.tenant = invitation.tenant
    const payload = {
        iss: ISSUER,
        aud: invitation.client_id,
        jti: randomUUID(),
        [EVENT_CLAIM]: data,
    }
    const event = await sign(payload)
    if (event instanceof Error) return { event: null, error: event }

    if (invitation.events_uri) {
        try {
            const response = await fetch(invitation.events_uri, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/jwt',
                    Accept: 'application/json',
                },
                body: event,
            })
            if (response.status !== 202) {
                return { event, error: new Error(`status ${response.status}`) }
            }
        } catch (err) {
            return { event, error: err }
        }
    }
    return { event }
}

function mockErrFor(endpoint) {
    if (!MOCK.error) return null
    if (MOCK.error_endpoint && MOCK.error_endpoint !== endpoint) return null
    return MOCK.error
}

function buildInvitation(input) {
    const now = Math.floor(Date.now() / 1000)
    const inviterSub = input.inviter_sub || defaultUser.sub
    const inviterEmail = input.inviter_email || defaultUser.email || null
    return {
        id: newId(),
        invitee: {
            email: input.email,
            subject: makeInviteeSubject(input.email),
        },
        inviter: { sub: inviterSub, id: inviterSub, email: inviterEmail },
        prompt: input.prompt,
        client_id: input.client_id,
        events_uri: input.events_uri || null,
        initiate_login_uri: input.initiate_login_uri || null,
        return_uri: input.return_uri || null,
        role: input.role || null,
        tenant: input.tenant || null,
        state: input.state || null,
        host: input.host || null,
        app_name: input.app_name || null,
        client: {},
        status: 'pending',
        createdAt: now,
        lastEmailedAt: now,
        expiresAt: now + (MOCK.expires_in || EXPIRY_SECONDS),
    }
}

// ── POST /invite ─────────────────────────────────────────────────────
// Wallet uses session for inviter/client_id. Mockin reads them inline.
export const create = async (req, res) => {
    const err = mockErrFor('create')
    if (err) {
        const status = err === 'disposable_email' ? 200 : 400
        return res.code(status).send({ error: err })
    }

    const body = req.body || {}
    if (!body.email || !body.prompt) {
        return res.code(400).send({ error: 'invalid_request' })
    }
    if (!EMAIL_REGEX.test(body.email)) {
        return res.code(400).send({ error: 'invalid_email' })
    }
    if (body.email.length > 320) {
        return res.code(400).send({ error: 'email_too_long' })
    }
    if (!body.client_id) {
        return res.code(400).send({ error: 'invalid_request' })
    }

    const invitation = buildInvitation(body)
    invitations.set(invitation.id, invitation)
    return res.send({ invite: sanitizeInvitation(invitation) })
}

// ── GET /invite — entry redirect ─────────────────────────────────────
// Wallet's GET /invite renders a SPA. Mockin treats it programmatically:
// builds the invitation from query params and redirects to `return_uri`.
// With auto_accept = true, also fires the SET inline.
export const entry = async (req, res) => {
    const err = mockErrFor('entry')
    if (err) return res.code(400).send({ error: err })

    const q = req.query || {}
    if (!q.client_id || !q.inviter) {
        return res.code(400).send({ error: 'invalid_request' })
    }
    const email = q.invitee_email || `invitee-${randomUUID().slice(0, 8)}@example.com`

    const invitation = buildInvitation({
        email,
        prompt: q.prompt || 'Invitation',
        client_id: q.client_id,
        inviter_sub: q.inviter,
        inviter_email: q.inviter_email,
        events_uri: q.events_uri,
        initiate_login_uri: q.initiate_login_uri,
        return_uri: q.return_uri,
        role: q.role,
        tenant: q.tenant,
        state: q.state,
        host: q.host,
        app_name: q.app_name,
    })
    invitations.set(invitation.id, invitation)

    if (MOCK.auto_accept) {
        invitation.status = 'accepted'
        await sendEvent(invitation, invitation.invitee.subject)
    }

    if (q.return_uri) return res.redirect(q.return_uri)
    return res.send({ invite: sanitizeInvitation(invitation) })
}

// ── PUT /invite/:id — resend ─────────────────────────────────────────
export const resend = async (req, res) => {
    const err = mockErrFor('resend')
    if (err) return res.code(400).send({ error: err })

    const inv = invitations.get(req.params.id)
    if (!inv) return res.code(404).send({ error: 'invitation_not_found' })
    inv.lastEmailedAt = Math.floor(Date.now() / 1000)
    return res.send({ invite: sanitizeInvitation(inv) })
}

// ── DELETE /invite/:id — retract ─────────────────────────────────────
export const retract = async (req, res) => {
    const err = mockErrFor('retract')
    if (err) return res.code(400).send({ error: err })

    const inv = invitations.get(req.params.id)
    if (!inv) return res.code(404).send({ error: 'invitation_not_found' })
    invitations.delete(req.params.id)
    return res.send({ success: true })
}

// ── GET /user/invite — list outgoing invites ─────────────────────────
// Wallet filters by req.user.profile.id; mockin filters by ?inviter_sub=
// when provided, otherwise returns all.
export const userInvites = async (req, res) => {
    const filter = req.query?.inviter_sub
    const out = []
    for (const inv of invitations.values()) {
        if (filter && inv.inviter.sub !== filter) continue
        out.push(sanitizeInvitation(inv))
    }
    return res.send({ invitations: out })
}

// ── GET /invitation/:id — invitee view ───────────────────────────────
export const invitation = async (req, res) => {
    const err = mockErrFor('invitation')
    if (err) return res.code(200).send({ error: err })

    const inv = invitations.get(req.params.id)
    if (!inv) return res.code(200).send({ error: 'invitation_not_found' })
    if (inv.expiresAt < Math.floor(Date.now() / 1000)) {
        return res.code(200).send({ error: 'invitation_expired' })
    }
    return res.send(sanitizeInvitation(inv))
}

// ── PUT /invitation/:id — accept ─────────────────────────────────────
// Same response shape as wallet: { initiate_login_url }. The SET JWT
// rides separately to events_uri (HTTP POST) — tests capture it via a
// global fetch stub.
export const accept = async (req, res) => {
    const err = mockErrFor('accept')
    if (err) return res.code(400).send({ error: err })

    const inv = invitations.get(req.params.id)
    if (!inv) return res.code(200).send({ error: 'invitation_not_found' })
    if (inv.expiresAt < Math.floor(Date.now() / 1000)) {
        return res.code(200).send({ error: 'invitation_expired' })
    }
    inv.status = 'accepted'

    await sendEvent(inv, inv.invitee.subject)

    let initiateLoginUrl = null
    if (inv.initiate_login_uri) {
        const u = new URL(inv.initiate_login_uri)
        u.searchParams.set('login_hint', inv.invitee.email)
        u.searchParams.set('iss', ISSUER)
        initiateLoginUrl = u.toString()
    }
    return res.send({ initiate_login_url: initiateLoginUrl })
}

// ── DELETE /invitation/:id — decline ─────────────────────────────────
export const decline = async (req, res) => {
    const err = mockErrFor('decline')
    if (err) return res.code(400).send({ error: err })

    const inv = invitations.get(req.params.id)
    if (!inv) return res.code(200).send({ error: 'invitation_not_found' })
    invitations.delete(req.params.id)
    return res.send({ success: true })
}

// ── POST /invitation/:id/report ──────────────────────────────────────
export const report = async (req, res) => {
    const inv = invitations.get(req.params.id)
    if (!inv) return res.code(400).send({ error: 'invitation_not_found' })
    invitations.delete(req.params.id)
    return res.send({ success: true })
}

// ── /mock/invite — controls ──────────────────────────────────────────
export const mockGet = async (req, res) => {
    return res.send({
        config: { ...MOCK },
        invitations: [...invitations.values()].map(sanitizeInvitation),
    })
}

export const mockPut = async (req, res) => {
    const body = req.body || {}
    if (body.error !== undefined) MOCK.error = body.error || null
    if (body.error_endpoint !== undefined) MOCK.error_endpoint = body.error_endpoint || null
    if (body.auto_accept !== undefined) MOCK.auto_accept = !!body.auto_accept
    if (body.expires_in !== undefined) {
        const n = Number(body.expires_in)
        MOCK.expires_in = Number.isFinite(n) && n > 0 ? n : EXPIRY_SECONDS
    }
    return res.send({ config: { ...MOCK } })
}

// Reset hook (called from DELETE /mock).
export function clearAll() {
    invitations.clear()
    MOCK = {
        error: null,
        error_endpoint: null,
        auto_accept: false,
        expires_in: EXPIRY_SECONDS,
    }
}

// Test helpers (not part of the public surface).
export const _internal = { invitations, sanitizeInvitation }
