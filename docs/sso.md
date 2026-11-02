# Single sign-on with OpenID Connect

Vaultwarphpen logs users in at an OpenID Connect provider exactly like Vaultwarden does, with the same
`SSO_*` settings. This page explains how to set up Microsoft Entra ID, Keycloak and Google Workspace,
what to watch out for with each, and how to test the result.

SSO replaces the login, not the encryption. The vault stays encrypted with each user's master password:
at the first SSO login a new user sets one, and every user enters it to unlock the vault after logging
in. Vaultwarden, and so Vaultwarphpen, has no Key Connector and no trusted devices.

## How the login works

1. The client (web vault, browser extension, desktop or mobile app) sends the user to
   `<DOMAIN>/identity/connect/authorize`.
2. The server redirects to the provider's login page.
3. After the login the provider sends the browser back to `<DOMAIN>/identity/connect/oidc-signin`, the
   only redirect URI to register at the provider. `DOMAIN` must therefore be the public HTTPS address,
   including a path if Vaultwarphpen runs below one: `https://example.com/vault` gives
   `https://example.com/vault/identity/connect/oidc-signin`. The apps need no redirect URIs of their own;
   the server passes them on.
4. The server exchanges the code for tokens, checks the ID token and asks the user info endpoint, then
   finds the account:
   - by the provider's identity (issuer and subject) if the user logged in with SSO before;
   - otherwise by email address: an existing account is linked to the identity if the provider says the
     address is verified (see `SSO_SIGNUPS_MATCH_EMAIL` and `SSO_ALLOW_UNKNOWN_EMAIL_VERIFICATION`);
   - otherwise a new account is created (see `SSO_SIGNUPS_ALLOWED`).

Unless `SSO_AUTH_ONLY_NOT_SESSION` is set, the session follows the provider's tokens: the clients'
tokens expire with the provider's access token, a refresh goes through the provider's refresh token,
and when the provider ends the session, the clients are logged out at their next refresh.

## Settings

Set them as environment variables or in `.env` ([Configuration](configuration.md)), or in the admin
panel under *Settings → OpenID Connect SSO settings*, which writes `config.json`. Changes take effect
with the next request.

| Setting | Default | Meaning |
| --- | --- | --- |
| `SSO_ENABLED` | `false` | Turns SSO on. |
| `SSO_AUTHORITY` | | The provider's issuer, exactly as its discovery document names it, without `/.well-known/openid-configuration`. |
| `SSO_CLIENT_ID` | | The client (application) ID at the provider. |
| `SSO_CLIENT_SECRET` | | The client secret. `SSO_CLIENT_SECRET_FILE` reads it from a file. |
| `SSO_SCOPES` | `email profile` | Scopes besides `openid`. Add `offline_access` where the provider issues refresh tokens only then. |
| `SSO_AUTHORIZE_EXTRA_PARAMS` | | More parameters for the provider's login page, form encoded: `prompt=select_account&ui_locales=de`. |
| `SSO_PKCE` | `true` | Sends the client's PKCE challenge to the provider. |
| `SSO_SIGNUPS_ALLOWED` | `true` | New accounts at the first SSO login. `SIGNUPS_DOMAINS_WHITELIST`, if set, decides instead. |
| `SSO_SIGNUPS_MATCH_EMAIL` | `true` | Links an existing account with a master password to the identity with the same address. |
| `SSO_ALLOW_UNKNOWN_EMAIL_VERIFICATION` | `false` | Accepts tokens without `email_verified` for sign-ups and linking. |
| `SSO_ONLY` | `false` | No more login with the master password; sessions started with it end at their next refresh. |
| `SSO_AUTH_ONLY_NOT_SESSION` | `false` | SSO only for the login: the clients get the server's own tokens (two hours, refreshed for 30 days, 90 on mobile), and the provider's session no longer counts. |
| `SSO_AUDIENCE_TRUSTED` | | A regular expression for further audiences that ID tokens may name besides the client ID. |
| `SSO_CLIENT_CACHE_EXPIRATION` | `0` | Seconds to keep the provider's discovery document and keys; `0` fetches them for every login. |
| `SSO_MASTER_PASSWORD_POLICY` | | The master password policy for SSO users, as JSON: `{"minLength":14,"minComplexity":3,"requireUpper":true,"enforceOnLogin":true}`. |
| `SSO_DEBUG_TOKENS` | `false` | Vaultwarden logs the provider's tokens with it; Vaultwarphpen only logs the whole of the authenticated user instead of its identifier. |

Things that apply to every provider:

- **`SSO_AUTHORITY` must match the issuer character for character.** Open
  `<SSO_AUTHORITY>/.well-known/openid-configuration` in a browser: its `issuer` must be exactly
  `SSO_AUTHORITY`, with the same trailing slash or none. Otherwise every login fails with
  `Failed to discover OpenID provider: Validation error: unexpected issuer URI`.
- **Email addresses.** Linking by email address trusts the provider to vouch for the address. Only allow
  unknown verification (`SSO_ALLOW_UNKNOWN_EMAIL_VERIFICATION`) for a provider whose addresses only
  administrators can set: anyone who can put another person's address into a token can otherwise log in
  to that person's account (though not decrypt its vault). Once all existing users have linked their
  accounts, `SSO_SIGNUPS_MATCH_EMAIL=false` closes that door; invited users still link.
- **Who may log in** is decided at the provider (assign the application to users or groups there). With
  `SSO_SIGNUPS_ALLOWED=true` everyone the provider lets through gets an account. For a provider open to
  the public, turn sign-ups off and invite users in the admin panel, or restrict them with
  `SIGNUPS_DOMAINS_WHITELIST`.
- **Signing.** ID tokens may be signed with RS256 (the usual), RS384, RS512, PS256, PS384, PS512,
  ES256, ES384 or EdDSA, or with HS256 to HS512 using the client secret. ES512 does not work, in
  Vaultwarden neither. With `SSO_CLIENT_CACHE_EXPIRATION` above `0`, the first login after the provider
  rotates its keys fails with `Signature verification failed`; that failure drops the cache, and the
  next login works.
- **Client secrets expire** at most providers. When it has expired, every SSO login fails and SSO
  sessions end at their next refresh. Note the date.

## Microsoft Entra ID

### App registration

In the [Microsoft Entra admin center](https://entra.microsoft.com):

1. *Identity → Applications → App registrations → New registration*.
   - Name: `Vaultwarphpen`, or anything users should see.
   - Supported account types: *Accounts in this organizational directory only (Single tenant)*.
   - Redirect URI: platform **Web** (not *Single-page application*), URI
     `https://vault.example.com/identity/connect/oidc-signin`.
2. On the *Overview* page, note the *Application (client) ID* and the *Directory (tenant) ID*.
3. *Certificates & secrets → Client secrets → New client secret*. Copy the **Value** (not the
   *Secret ID*) right away; it is shown only once. Note the expiry date.
4. *API permissions*: Microsoft Graph's delegated permissions `openid`, `email`, `profile` and
   `offline_access` (and the preset `User.Read`). *Grant admin consent* spares users the consent prompt.
5. Optional, to decide who may log in: *Enterprise applications → Vaultwarphpen → Properties →
   Assignment required? → Yes*, then assign users or groups under *Users and groups*.

### Settings

```dotenv
SSO_ENABLED=true
SSO_AUTHORITY=https://login.microsoftonline.com/<Directory (tenant) ID>/v2.0
SSO_CLIENT_ID=<Application (client) ID>
SSO_CLIENT_SECRET=<client secret value>
SSO_SCOPES="email profile offline_access"
SSO_ALLOW_UNKNOWN_EMAIL_VERIFICATION=true
```

### Pitfalls

- **The authority contains the tenant ID**, the GUID, and ends with `/v2.0`, without a trailing slash.
  `common`, `organizations` and the tenant's domain name do not work: their discovery documents name a
  different issuer.
- **Entra ID sends no `email_verified`.** Without `SSO_ALLOW_UNKNOWN_EMAIL_VERIFICATION=true` new users
  are refused (`Your provider does not send email verification status`) and existing accounts are not
  linked (`Email verification status is unknown`). In a single-tenant directory, the `email` claim is
  the user's *Email* property (`mail`), which only administrators set, so allowing it is reasonable.
  With guest users in the directory, keep application assignment on, or set
  `SSO_SIGNUPS_MATCH_EMAIL=false` once the existing accounts are linked.
- **Users need an email address.** The `email` claim comes from the user's *Email* property. Users
  without one cannot log in (`Neither id token nor userinfo contained an email`). If the claim is missing
  although the property is set, add the optional claim `email` to the ID token under *Token
  configuration*.
- **`offline_access` is needed for refresh tokens.** Without it, Entra ID issues none, and users have to
  log in again when the access token expires (after an hour or so).
- **Ending sessions:** *Users → user → Revoke sessions* invalidates the refresh tokens, and the user's
  Bitwarden sessions end at their next refresh.
- **Keep the app registration.** Accounts are tied to the subject (`sub`) of the ID token, which Entra
  ID issues per application. A new registration gives every user a new identity; their logins then
  fail with `Existing SSO user with same email` until *Delete SSO Association* in the admin panel
  (*Users*) lets them link again.
- **Not tested automatically.** Vaultwarphpen's CI compares the SSO login with Vaultwarden against
  Keycloak, not against Entra ID. Please report anything that behaves differently.

## Keycloak

### Client

In the admin console of your realm:

1. *Clients → Create client*: type *OpenID Connect*, client ID `vaultwarden`.
2. *Capability config*: *Client authentication* on, *Standard flow* only (no *Direct access grants*).
3. *Login settings*: *Valid redirect URIs* `https://vault.example.com/identity/connect/oidc-signin`.
4. *Credentials*: client authenticator *Client Id and Secret*; copy the secret.
5. Optional: the PKCE method `S256` (under *Capability config* or *Advanced → Advanced settings*,
   depending on the version) makes PKCE mandatory; Vaultwarphpen sends it unless `SSO_PKCE=false`.

### Settings

```dotenv
SSO_ENABLED=true
SSO_AUTHORITY=https://keycloak.example.com/realms/<realm>
SSO_CLIENT_ID=vaultwarden
SSO_CLIENT_SECRET=<secret>
```

### Pitfalls

- **The authority** is the realm's URL without trailing slash. Keycloak before version 17 (and newer
  ones started with `--http-relative-path=/auth`) has `/auth` in front: `.../auth/realms/<realm>`.
- **`email_verified` is honoured.** Users whose address Keycloak has not verified are refused
  (`You need to verify your email with your provider`). Mark their addresses as verified, or turn on
  *Realm settings → Login → Verify email*.
- **Session length.** Keycloak issues refresh tokens without `offline_access`. The Bitwarden session
  then lasts as long as Keycloak's: it ends after *SSO Session Idle* (30 minutes by default) without a
  refresh and after *SSO Session Max* (10 hours) in any case (*Realm settings → Sessions*). For longer
  sessions, raise those, or add `offline_access` to `SSO_SCOPES` (offline sessions last 30 days and
  survive a logout at Keycloak), or set `SSO_AUTH_ONLY_NOT_SESSION=true`.
- **Ending sessions:** a logout at Keycloak, or *Users → user → Sessions → Sign out*, ends the user's
  Bitwarden sessions at their next refresh.
- **Refresh token rotation** (*Realm settings → Tokens → Revoke Refresh Token*) works: the server reuses
  the provider's answer for 30 seconds, so clients that refresh at the same time do not trip over it.
- **Further audiences.** An audience mapper that adds audiences to the ID token needs
  `SSO_AUDIENCE_TRUSTED`, for example `'^my-api$'`.
- **Signing algorithm:** RS256 by default. *Advanced → Fine grain OpenID Connect configuration → ID
  token signature algorithm* may be another one from the list above, except ES512, if the realm has an
  active key for it (*Realm settings → Keys → Add providers*).

## Google Workspace

### OAuth client

In the [Google Cloud console](https://console.cloud.google.com), in a project of your organization:

1. *APIs & Services → OAuth consent screen* (*Google Auth Platform*): user type **Internal**, so that only
   accounts of your Workspace can log in. Scopes: `openid`, `email`, `profile`.
2. *APIs & Services → Credentials → Create credentials → OAuth client ID*: type *Web application*,
   *Authorized redirect URIs* `https://vault.example.com/identity/connect/oidc-signin`.
3. Copy the client ID and the client secret.

### Settings

```dotenv
SSO_ENABLED=true
SSO_AUTHORITY=https://accounts.google.com
SSO_CLIENT_ID=<client ID>.apps.googleusercontent.com
SSO_CLIENT_SECRET=<client secret>
SSO_AUTHORIZE_EXTRA_PARAMS="access_type=offline&prompt=consent"
```

### Pitfalls

- **The authority** is `https://accounts.google.com`, without trailing slash.
- **No `offline_access`.** Google refuses that scope. It issues refresh tokens for `access_type=offline`,
  and only at a consent, hence `prompt=consent` (Google then asks for consent at every login). Without
  both, users log in again after an hour.
- **Restrict the users.** Vaultwarphpen does not check the Workspace domain (the `hd` claim). With user
  type *External*, any Google account would pass; then turn off `SSO_SIGNUPS_ALLOWED` or set
  `SIGNUPS_DOMAINS_WHITELIST=example.com`. `hd=example.com` in `SSO_AUTHORIZE_EXTRA_PARAMS` only
  preselects the account.
- **Not tested automatically**, like Entra ID.

## Testing the setup

Before you start, back up the database (*Admin panel → Settings → Backup Database* for SQLite, or your
database's tools), since linking changes existing accounts.

1. **Discovery.** Open `<SSO_AUTHORITY>/.well-known/openid-configuration` from the server, for example
   with `curl`. The `issuer` must be exactly `SSO_AUTHORITY`.
2. **A new user.** In a private browser window open the web vault, choose *Use single sign-on* and log
   in at the provider with a test user that has no account yet. If the client asks for an SSO
   identifier, any value works; the server ignores it. The web vault then asks for a new master password.
   The admin panel (*Users*) shows the account with its SSO identifier.
3. **An existing user.** Log in with SSO as a user who already has an account with the same address.
   The account is linked, and the vault unlocks with the existing master password.
4. **The session.** Keep the web vault open beyond the lifetime of the provider's access token (an hour
   at Entra ID and Google, five minutes at Keycloak) and keep using it: without a new login, refreshing
   works. Then end the user's sessions at the provider (see above) and wait for the next refresh, or
   reload the web vault: the user is logged out, unless `SSO_AUTH_ONLY_NOT_SESSION=true`.
5. **The other clients.** Log in with the browser extension, the desktop app, the mobile apps and the
   CLI (`bw login --sso`, then `bw unlock`). They need no further setup at the provider; the desktop
   app comes back through `http://localhost:8065` to `8070` or `bitwarden://sso-callback`, the CLI
   through `http://localhost:8065`.
6. **`SSO_ONLY`.** Only once every user can log in with SSO: logins with the master password are then
   refused, and the sessions started with one end.

### Error messages

The clients show the server's message, and the log (`storage/logs/laravel.log` unless configured
otherwise) has the details.

| Message | Cause |
| --- | --- |
| `Failed to discover OpenID provider: Validation error: unexpected issuer URI ...` | `SSO_AUTHORITY` differs from the issuer: tenant ID, `/v2.0`, trailing slash. |
| `Failed to discover OpenID provider: Server returned invalid response: HTTP status code 404 ...` | Wrong `SSO_AUTHORITY`: no discovery document there. |
| `Failed to contact token endpoint: ServerResponse(... invalid_client ...)` or `unauthorized_client` | Wrong or expired client secret, or wrong client ID. |
| `SSO authorization failed: <error>, <description>` | The provider refused the login, for example Entra ID's `AADSTS50105` for a user the application is not assigned to, or `invalid_scope` for an unknown scope. |
| `Could not read id_token claims, Invalid audiences: ...` | The ID token names further audiences: `SSO_AUDIENCE_TRUSTED`. |
| `Could not read id_token claims, Signature verification failed` | Keys rotated while cached (the next login works), or an algorithm that cannot be verified (ES512). |
| `Neither id token nor userinfo contained an email` | The user has no email address at the provider, or the `email` scope is missing. |
| `Your provider does not send email verification status. ...` | No `email_verified` claim: `SSO_ALLOW_UNKNOWN_EMAIL_VERIFICATION`. |
| `You need to verify your email with your provider before you can log in` | The provider says the address is not verified. |
| `Email verification status is unknown` / `Email is not verified by the SSO provider` | An existing account is not linked for that reason. |
| `Existing non SSO user with same email` | `SSO_SIGNUPS_MATCH_EMAIL=false` and an account with that address exists. |
| `Existing SSO user with same email` | The account belongs to another identity at the provider, for example because the user was deleted and created again there. *Admin panel → Users → Delete SSO Association* lets the new identity link. |
| `Signups are disabled. You will need an invitation` / `Email domain not allowed` | `SSO_SIGNUPS_ALLOWED=false` or `SIGNUPS_DOMAINS_WHITELIST`: invite the user in the admin panel. |
| `SSO sign-in is required` | `SSO_ONLY=true` and a login with the master password. |

## How this is tested

The differential tests run every SSO flow against Vaultwarden and Vaultwarphpen and compare the answers:
against a fake provider (`tests/Differential/SsoTest.php`) and against a real Keycloak
(`tests/Differential/KeycloakTest.php`, with the realm of `.github/scripts/keycloak-realm.json`). The
Keycloak tests cover sign-ups, linking by email, refresh with rotating refresh tokens, offline tokens,
access tokens without refresh tokens, sessions ended at the provider, key rotation, the signing
algorithms, a client without `email_verified` like Entra ID's, and the settings `SSO_ONLY`,
`SSO_SIGNUPS_ALLOWED`, `SSO_SIGNUPS_MATCH_EMAIL`, `SSO_ALLOW_UNKNOWN_EMAIL_VERIFICATION`,
`SSO_AUTH_ONLY_NOT_SESSION`, `SSO_AUDIENCE_TRUSTED`, `SSO_CLIENT_CACHE_EXPIRATION`,
`SSO_AUTHORIZE_EXTRA_PARAMS` and `SSO_MASTER_PASSWORD_POLICY`.

The client tests ([Testing with the official clients](clients.md), `tests/Clients/sso.spec.ts`) log in
with SSO in the web vault and with the CLI against the fake provider, on both servers: a new account
that sets its master password, later logins that unlock with it, and an existing account that is linked.
