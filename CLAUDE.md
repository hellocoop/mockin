# Mockin Development Guide

## Project Overview

Mock OpenID Connect server for Hellō. Fastify v5, Node.js 22, ES modules.

## Commands

- `npm test` — run all tests (mocha + chai)
- `npm start` — start server on port 3333
- `npm run release` — bump patch version and publish (see Release Process below)
- `npm run release -- minor` — bump minor version and publish
- `npm run release -- major` — bump major version and publish

## Architecture

- `src/api.js` — route definitions
- `src/authorize.js` — OAuth authorization endpoint
- `src/oauth.js` — token, introspect, userinfo, JWKS, well-known endpoints
- `src/mock.js` — mock configuration management
- `src/command.js` — OP command token generation
- `src/sign.js` / `src/verify.js` — JWT signing and verification (jose library)
- `src/users.js` — mock user database
- `src/config.js` — PORT, IP, ISSUER configuration

## Testing

Tests use `fastify.inject()` for in-process HTTP testing (no server needed).
All test files are in `test/` and follow the pattern `*.spec.js`.

## CI/CD

### GitHub Actions Workflows

- **CI** (`.github/workflows/ci.yml`) — runs on PRs to main: `npm ci`, `npm test`, `npm pack --dry-run`
- **Release** (`.github/workflows/release.yml`) — runs when a GitHub Release is published: verifies tag matches package.json, runs tests, publishes to npm (with provenance) and Docker Hub (multi-arch)

### Required GitHub Secrets

Three secrets must be configured at https://github.com/hellocoop/mockin/settings/secrets/actions:

| Secret | Purpose | How to get it |
|--------|---------|---------------|
| `NPM_TOKEN` | npm publish with provenance | npmjs.com → Avatar → Access Tokens → Generate New Token → Granular Access Token → scope to `@hellocoop/mockin` with Read and Write |
| `DOCKERHUB_USERNAME` | Docker Hub login | Your Docker Hub username |
| `DOCKERHUB_TOKEN` | Docker Hub push | hub.docker.com → Account Settings → Personal access tokens → Generate → Read & Write |

### Release Process

From a clean main branch:

```bash
npm run release            # patch: 1.2.0 → 1.2.1
npm run release -- minor   # minor: 1.2.0 → 1.3.0
npm run release -- major   # major: 1.2.0 → 2.0.0
```

The script will:
1. Verify clean working tree and main branch
2. Run tests
3. Bump version in package.json (via `npm version`)
4. Push commit and tag to origin
5. Create a GitHub Release (via `gh release create`)
6. GitHub Actions then publishes to npm and Docker Hub

**Prerequisites:**
- `gh` CLI installed and authenticated (`gh auth login`)
- GitHub secrets configured (see table above)
- Push access to the repo
