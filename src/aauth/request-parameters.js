// aauth/request-parameters.js — the consent-flow request parameters both
// PS token endpoints take.
//
// -11 §Agent Token Request lists these on the auth token endpoint. The
// person token endpoint has the same deferred-consent shape — either can
// return 202 with requirement=interaction, either identifies the person,
// either renders a consent screen and creates a connected-agents entry —
// so mockin accepts the same set at both, and parses them in one place.
//
// Not here: `resource_token` (what makes the auth token endpoint the auth
// token endpoint) and `upstream_token` (call chaining, not implemented).

// AAuth Platform Value Registry.
export const PLATFORM_VALUES = new Set([
    'web', 'mobile', 'desktop', 'workload', 'self-hosted',
])

// §AAuth-Capabilities. "Recipients MUST ignore unrecognized capability
// values" — filter, never reject.
export const CAPABILITY_VALUES = new Set([
    'interaction', 'clarification', 'payment',
])

// [@!OpenID.Core] Section 3.1.2.1 defined values.
export const PROMPT_VALUES = new Set([
    'none', 'login', 'consent', 'select_account',
])

const DEVICE_MAX_LENGTH = 64
// eslint-disable-next-line no-control-regex
const CONTROL_CHARS = /[\u0000-\u001F\u007F]/

/**
 * @param {object} body
 * @returns {{params?: object, error?: string}}
 */
export function parseRequestParameters(body = {}) {
    const params = {}

    // justification (OPTIONAL): a Markdown string declaring why access is
    // being requested. The PS SHOULD present this value to the user during
    // consent, and MUST sanitize the Markdown before rendering.
    if (body.justification !== undefined) {
        if (typeof body.justification !== 'string') {
            return { error: 'justification must be a string' }
        }
        params.justification = body.justification
    }

    // login_hint (OPTIONAL): hint about who to authorize, per
    // [@!OpenID.Core] Section 3.1.2.1. It matters more at the person token
    // endpoint than at the auth token endpoint: this is first contact, and
    // the PS may not yet know which person the agent acts for.
    if (body.login_hint !== undefined) {
        if (typeof body.login_hint !== 'string') {
            return { error: 'login_hint must be a string' }
        }
        params.login_hint = body.login_hint
    }

    // tenant (OPTIONAL): tenant identifier, per OpenID Connect Enterprise
    // Extensions. This is what selects which tenant an issued token carries
    // when a person holds a personal context plus several managed ones.
    if (body.tenant !== undefined) {
        if (typeof body.tenant !== 'string') {
            return { error: 'tenant must be a string' }
        }
        params.tenant = body.tenant
    }

    // domain_hint (OPTIONAL): per OpenID Connect Enterprise Extensions.
    if (body.domain_hint !== undefined) {
        if (typeof body.domain_hint !== 'string') {
            return { error: 'domain_hint must be a string' }
        }
        params.domain_hint = body.domain_hint
    }

    // prompt (OPTIONAL): space-delimited, case-sensitive list of values
    // specifying whether the PS prompts for reauthentication and consent,
    // per [@!OpenID.Core] Section 3.1.2.1.
    if (body.prompt !== undefined) {
        if (typeof body.prompt !== 'string') {
            return { error: 'prompt must be a space-delimited string' }
        }
        const values = body.prompt.split(/\s+/).filter(Boolean)
        const unknown = values.filter((v) => !PROMPT_VALUES.has(v))
        if (unknown.length) {
            return { error: `unknown prompt value(s): ${unknown.join(' ')}` }
        }
        params.prompt = values
    }

    // platform (OPTIONAL): identifier for the runtime platform the agent
    // runs on. The value MUST be from the AAuth Platform Value Registry.
    // Agent-attested; used for display only.
    if (body.platform !== undefined) {
        if (typeof body.platform !== 'string' || !PLATFORM_VALUES.has(body.platform)) {
            return {
                error: `platform must be one of ${[...PLATFORM_VALUES].join(', ')}`,
            }
        }
        params.platform = body.platform
    }

    // device (OPTIONAL): short human-readable string identifying the
    // device or browser, for the connected-agents dashboard. UTF-8
    // printable characters only, at most 64 of them. Opaque to receivers.
    if (body.device !== undefined) {
        if (typeof body.device !== 'string') {
            return { error: 'device must be a string' }
        }
        if (body.device.length > DEVICE_MAX_LENGTH) {
            return { error: `device must not exceed ${DEVICE_MAX_LENGTH} characters` }
        }
        if (CONTROL_CHARS.test(body.device)) {
            return { error: 'device must not contain control characters' }
        }
        params.device = body.device
    }

    // capabilities (OPTIONAL): the capability values the agent can handle
    // for this request — the request-body equivalent of the
    // AAuth-Capabilities header, which is not used on PS endpoints.
    // Without a mission, this is how the PS learns whether the agent can
    // drive requirement=interaction.
    if (body.capabilities !== undefined) {
        if (
            !Array.isArray(body.capabilities) ||
            body.capabilities.some((c) => typeof c !== 'string')
        ) {
            return { error: 'capabilities must be an array of strings' }
        }
        params.capabilities = body.capabilities.filter((c) => CAPABILITY_VALUES.has(c))
    }

    return { params }
}

/**
 * Whether a deferred response the agent has to drive itself can be sent.
 *
 * `requirement=interaction` hands the agent a url + code and expects it to
 * put the person in front of them. An agent that declared its capabilities
 * and did not name `interaction` has said it cannot. Sending it a 202 it
 * can never complete is the gap AAuth issue #89 describes; the terminal
 * answer is `user_unreachable` (403).
 *
 * Capabilities omitted means unknown, not "cannot" — the PS may know them
 * from mission approval — so the deferred path stays open by default.
 *
 * `requireDeclared` closes it. Hellō's Wallet, which can only reach the
 * person through a browser the agent opens or an already-open wallet tab,
 * answers `user_unreachable` to an agent that declared nothing; an agent
 * built against mockin's lenient default therefore worked here and 403'd
 * against production (`@aauth/proxy` 4.0.0, fixed in 4.0.1). Tests that
 * want to pin the stricter production behaviour set the
 * `require_capabilities` mock switch.
 */
export function canDriveInteraction(params, { requireDeclared = false } = {}) {
    if (!params?.capabilities) return !requireDeclared
    return params.capabilities.includes('interaction')
}
