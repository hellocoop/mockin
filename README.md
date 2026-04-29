# Mockin - A Mock Login Server for Hellō

Mockin is a mock of the Hellō of the OpenID Connect Login Service and implements the authorization, token, introspection, and userinfo endpoints. 

- **Development** - speeds up development as you won't be redirecting through the Hellō production server. Start the login flow by clicking on the `[ ō Continue with Hellō ]` button. Your browser will redirect to Mockin and then back to your app which will then complete the login flow.

- **Testing** - simplifies creating end to end tests, and with the `/mock` APIs, you can simulate expired and invalid responses allowing you to ensure your app properly handles all exceptions, improving your security posture.

## Usage

Mockin is available as both an npm module and a docker image:

`npx @hellocoop/mockin@latest`

`docker run  -d -p 3333:3333 hellocoop/mockin:latest`

## Issuer

Mockin defaults to `http://127.0.0.1:3333` as the Issuer. Override by setting the `ISSUER` environment variable.

## Mock API

The mock API can change the returned claims, simulate errors, and invalid ID Tokens.

## AAuth

Mockin also acts as a mock **Person Server** for [draft-hardt-aauth-protocol](https://datatracker.ietf.org/doc/draft-hardt-aauth-protocol/) — useful for testing agent clients without spinning up a real PS. Endpoints include `/aauth/bootstrap`, `/aauth/token`, `/aauth/permission`, `/aauth/audit`, `/aauth/interaction`, plus R3 (Rich Resource Requests) support. Auto-approves all consent steps in default mode. See the [docs](https://www.hello.dev/docs/mockin#aauth-agent-auth) for details.

## Invite

Mockin also mirrors Hellō's invite flow — useful for testing how your app handles the `events_uri` SET (Security Event Token) JWT and the `initiate_login_uri` redirect for newly invited users. Endpoints include `POST /invite`, `GET /invitation/:id`, `PUT /invitation/:id` (accept), `DELETE /invitation/:id` (decline), `DELETE /invite/:id` (retract), and `POST /invitation/:id/report` (abuse). SET JWT is RS256-signed and delivered to `events_uri` on accept. See the [docs](https://www.hello.dev/docs/mockin#invite) for details.

For detailed information on installation, usage, and examples, visit the [documentation](https://www.hello.dev/docs/mockin).
