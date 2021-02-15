# @cto.ai/ops-keycloak

> CTO.ai Keycloak library

Straightforward [Keycloak](https://www.keycloak.org/) integration.

## API

This is a native ESM module.

### `keycloak(opts) => instance`

**Options:**

* `realm` - the keycloak realm name
* `url` - the keycloak server URL
* `id` - client id
* `pages` - an object that must contain the following properties: `signup`, `signin`, `error`. Each must hold a [`Buffer`](https://nodejs.org/api/buffer.html) instance, containin HTML to redirect a users browser after a user has registered, logged in or if there was an error, respectively.
* `backend` default: `false` -  backend mode limited API. Only functionality that doesn't rely on client-side browser interactions is supplied: `refresh`, `signout` and `signin`, where `signin` must be passed user and password. Pages are not required when `backend` is `true`.

*Tokens objects:*

Much of the API either accepts or outputs `tokens`. A tokens object has the following shape:

```js
{
  accessToken: string
  refreshToken: string
  idToken: string
  sessionState: string
}
```

### `instance.signup() => Promise => tokens`

Opens the default browser to the registration URL and supplies `tokens` once the registration process has been completed in the browser.

### `instance.signin(opts) => Promise => tokens`

Triggers a browser-based login flow or logs in with a given username and password.

If both `user` and `password` options are supplied these credentials will be
exchanged for `tokens`. Otherwise, opens the default browser to the login URL and supplies `tokens` when the login process has been completed in the browser.

**Options:**

* `user` *Optional* - username
* `password` *Optional* - password

### `instance.refresh(tokens) => Promise => tokens`

Accepts a `tokens` object and fetches fresh `tokens`.

### `instance.signout(tokens) => Promise`

Invalidates the `tokens` passed.

### `instance.reset(opts)`

Will open a browser at a Keycloak password reset URL, which differs based on the `signedIn` options.

**Options:**

* `signedIn` (`boolean`), Default: `false` - If `true` the browser will open to the logged-in accounts password page. If `false` it will open to reset credentials page.

### `instance.validate(tokens) => boolean`

See [`keycloak.validate`](#keycloak-validate)


### `keycloak.validate(tokens) => boolean`

Checks whether `tokens.refreshToken` has expired. If it has `validate` returns `true`, otherwise `false`.


## Caveats

This library does not attempt to provide anything close to full Keycloak functionality integration.

## Engines

* Node 12.4+
* Node 14.0+

## Development

Test:

```sh
npm test
```

Visual coverage report (run after test):

```sh
npm run cov
```

Lint:

```sh
npm run lint
```

Autoformat:

```sh
npm run lint -- --fix
```

## Releasing

For mainline releases:

```sh
npm version <major|minor|patch>
git push --follow-tags
```

For prereleases:

```sh
npm version prerelease
git push --follow-tags
```

### License

MIT
