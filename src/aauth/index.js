// aauth/index.js — exports for AAuth handlers and mock controls.

export { metadata } from './metadata.js'
export { jwks } from './jwks.js'
export { token } from './token.js'
export { pendingGet, pendingPost, pendingDelete } from './pending.js'
export { permission } from './permission.js'
export { audit } from './audit.js'
export { interaction } from './interaction.js'
export { bootstrap } from './bootstrap.js'
export { consent } from './consent.js'
export { verifyPreHandler } from './verify-request.js'
export { get as mockGet, put as mockPut, resetConfig as mockReset } from './mock.js'
