// config.js
const { env } = process


export const ISSUER = env.ISSUER || 'http://mockin'

if ('https://issuer.hello.coop' === ISSUER.toLowerCase().replace(/\/$/, "")) {
    throw new Error('ISSUER must not be https://issuer.hello.coop')
}
console.log(`mockin ISSUER: ${ISSUER}`)

export const PORT = env.PORT || 3210
export const IP = env.IP || '0.0.0.0'