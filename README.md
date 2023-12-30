# mockin - a mock login server for the Hellō Wallet

A mock OpenID Connect Service that fully implements the functionality of Hellō. Available as an npm module or a Docker image. Can be used during development, local testing, or automated E2E testing in a CI/CD pipeline.

## Development 

When you app is configured to use *mockin*, clicking on the `[ ō Continue with Hellō ]` button will act as an auto login flow, streamlining development of your application.

## Testing

Works with all browser test frameworks such as Selenium, Cypress, or Playwright. After redirecting the authorization request to the mockin endpoint, the authorization response will be sent with no UX per the provided (or default) `response_mode`. Your application processes the `code` or `id_token` response, or if mocked, the `error` response such as if a user has cancelled the request.

The mock API allows you to mock all errors that may be returned from all endpoints, generate invalid and expired ID Tokens.

See the [documention](https://www.hello.dev/docs/mockin) for installation, usage, and examples.
