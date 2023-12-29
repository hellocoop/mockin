// config.js
const { env } = process

export const PORT = env.PORT || 3333
export const IP = env.IP || '127.0.0.1'
export const ISSUER = env.ISSUER || `http:${IP}:${PORT}`

if ('https://issuer.hello.coop' === ISSUER.toLowerCase().replace(/\/$/, "")) {
    throw new Error('ISSUER must not be https://issuer.hello.coop')
}
console.log(`mockin ISSUER: ${ISSUER}`)
