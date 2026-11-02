# Testing with the official clients

The differential tests compare Vaultwarphpen's HTTP answers with Vaultwarden's, with keys made up for
the purpose. The tests in [`tests/Clients`](../tests/Clients) go further: they drive the official
Bitwarden clients against a running server, so every key is made and every item encrypted and
decrypted by the clients' own cryptography, as it is for users.

## The clients

- **The web vault** that Vaultwarphpen serves: the build of Vaultwarden's Docker image that
  `parity/reference.json` pins (`web_vault`, see [Installation](installation.md#web-vault)), driven by
  [Playwright](https://playwright.dev) in headless Chromium.
- **The Bitwarden CLI** from npm, [`@bitwarden/cli`](https://www.npmjs.com/package/@bitwarden/cli), in the
  release of the web vault.

Both versions, and Playwright's, are pinned in `tests/Clients/package.json` and `package-lock.json`. The
CLI pins its own dependencies exactly; where one of them has a known advisory, `overrides` in
`package.json` takes the release that fixes it (`npm audit` stays clean, and so do Dependabot's alerts).
Drop an override once the CLI brings that release itself.

## What they do

In `vault.spec.ts`, one account goes through all of it, in this order:

1. **Web vault:** creates the account; a folder; a login with a website, notes and an attachment (which
   it downloads and compares), a secure note and a card; edits the login's password and moves a note
   to the trash.
2. Creates an organization and moves a login into its default collection, encrypted with the
   organization's key.
3. Creates a text Send and opens it in another browser, without an account.
4. Logs in on another browser with a login request (login with a device), which the first one approves
   from its device list.
5. Switches the key derivation from PBKDF2 to Argon2id, then changes the master password and rotates the
   account key, which encrypts the items, folders, attachments and Sends again; logs in after each and
   checks that everything still decrypts.
6. Turns on two-step login with an authenticator app, taking the secret from the page and computing
   the codes in the test (RFC 6238), logs out and logs in again with a code.
7. **CLI:** `bw config server`, `bw login` with the master password and a code, `bw sync`; lists the
   folders, items, trash, organizations and collections and compares the decrypted items with what the
   web vault entered (password history included); downloads the attachment. The CLI derives its keys
   with Argon2id here.
8. Creates an item with `bw create item`. The open web vault shows it at once, through the
   notifications hub, and again after a reload and unlock.
9. Lists the Send of the web vault and opens it with `bw receive`; sends a file and a text behind a
   password with `bw send`, which another browser opens and downloads.

In `sharing.spec.ts`, two accounts work together, each in a browser of its own. What the server mails,
they read from the SMTP sink and follow its links, as people would:

1. **Web vault:** the owner creates an account with a login and a note in a folder, and an organization
   with a login that is encrypted with the organization's key from the start.
2. Invites a new member to the default collection. The member follows the mailed link, creates its
   account there (which accepts the invitation), and gives itself a name.
3. The owner confirms the member after comparing the fingerprint phrase with the one the member's account
   shows: it encrypts the organization's key with the public key the server hands out. The member opens
   the organization's login in the web vault, and the CLI logs in and decrypts it.
4. **Emergency access:** the owner makes the member an emergency contact with view access. The member
   accepts from the mailed link, the owner confirms (the account key, encrypted with the member's public
   key), the member requests access and the owner approves at once, without waiting. The member sees the
   owner's own items, not the organization's, and opens one. Every step mails the other account.
5. **Export and import:** the owner exports its vault as plain JSON and as JSON encrypted with a file
   password. The member imports the encrypted file in the web vault, and the CLI lists the imported items
   and folder, which match the plain export.

In `sso.spec.ts`, accounts log in with SSO, at a server of their own that has it turned on, and its
OpenID provider:

1. **Web vault:** a new account logs in with SSO (*Use single sign-on*), sets its master password, which
   creates its keys, and adds a login.
2. Logs out, logs in with SSO again and unlocks the vault with the master password.
3. **CLI:** `bw login --sso` opens the web vault's SSO page, which a browser of the test opens in its
   place; the CLI takes the code at `http://localhost:8065` when the login is done, unlocks with the
   master password and decrypts the login.
4. An account created with a master password logs in with it (*Other*), then with SSO: the server links
   it to its identity at the provider, and the vault unlocks with the same master password.

Not covered yet: other two-step methods than the authenticator, groups and the other member roles,
invitations of existing accounts to an organization, emergency access takeover and its waiting time,
account-restricted, CSV and zip exports, imports from other password managers, and `SSO_ONLY`.

## How it runs

[`.github/scripts/clients.sh`](../.github/scripts/clients.sh) starts the server with an empty SQLite
database and the web vault, and runs the tests:

- Vaultwarphpen on PHP's built-in server (port 8100), with the notifications daemon (port 8101).
- In front of it, an HTTPS proxy ([`tests/Clients/proxy.mjs`](../tests/Clients/proxy.mjs), port 8443)
  with a certificate from an authority the script makes. The clients talk to nothing but HTTPS, and
  `DOMAIN` is the proxy's address. WebSocket requests go to the daemon, as a reverse proxy in
  production would send them.
- The browser accepts the certificate; the CLI trusts the authority through `NODE_EXTRA_CA_CERTS`.
- An SMTP sink ([`smtp-sink.php`](../.github/scripts/smtp-sink.php), port 8102), to which the servers send
  their mail. It keeps every message in a folder of the run, `VW_CLIENTS_MAIL`, which
  [`support/mail.ts`](../tests/Clients/support/mail.ts) reads.
- A second server of the same kind for `sso.spec.ts` (ports 8104 and 8105, proxy 8444,
  `VW_CLIENTS_SSO_URL`) with SSO turned on, since SSO changes the web vault's login page. Its OpenID
  provider is the fake one of [`fake-services.php`](../.github/scripts/fake-services.php) (port 8103), which
  logs in whoever its authorization URL names; the browsers of the test add their account to that URL.
- Each run uses new data folders, and the servers' default settings, with these exceptions: the SMTP
  settings, the SSO settings of the second server, and a login burst (`LOGIN_RATELIMIT_MAX_BURST`) of 30
  instead of 10. Every client connects from 127.0.0.1, where people would each have an address of their
  own, so the burst allows the default for each of the tests' accounts.

`clients.sh --vaultwarden <binary>` runs the same tests against Vaultwarden, which serves the same web
vault and its hubs itself. The [Clients](../.github/workflows/clients.yml) workflow runs the tests on
every push; the `clients` job of the [Reference](../.github/workflows/reference.yml) workflow runs them
against the Vaultwarden it builds. A failure in both is the tests', a failure only in the first is ours.
Where we fix a bug Vaultwarden still has, the test expects Vaultwarden's failure when `VW_CLIENTS_SERVER`
is `vaultwarden` (which `clients.sh --vaultwarden` sets), so that it fails once Vaultwarden fixes it; at
present, the CLI's new item after the account key rotation in `vault.spec.ts`.
When a run fails, the workflow keeps Playwright's report and a trace of the browser as the
`clients-report` artifact; open the trace with `npx playwright show-trace`.

## Running them locally

You need PHP 8.5, Composer's dependencies and a `.env` (see [Installation](installation.md)), Node 22 and
the web vault:

```bash
php artisan vaultwarden:web-vault
```

Then install the clients and Playwright's Chromium once:

```bash
cd tests/Clients && npm ci --ignore-scripts && npx playwright install chromium && cd ../..
```

and run the tests from the repository's root. `PHP` names another PHP binary than `php` (with Herd,
`$HOME/Library/Application Support/Herd/bin/php86`); arguments after the options go to Playwright:

```bash
.github/scripts/clients.sh
```

Ports 8100 to 8105, 8443 and 8444 must be free, and 8065 for the CLI's SSO login. For Vaultwarden, pass
its binary:

```bash
.github/scripts/clients.sh --vaultwarden /path/to/vaultwarden
```

On macOS, Vaultwarden checks certificates against the system's trust store and ignores `SSL_CERT_FILE`, so
it cannot reach the OpenID provider and `sso.spec.ts` fails there; on Linux, as in CI, it passes.

To work on the tests, `--serve` starts the servers and keeps them running; it prints the environment
for `npx playwright test` in `tests/Clients` (add `--ui` or `--headed` to watch). Many runs against one
server need higher rate limits, for example
`LOGIN_RATELIMIT_MAX_BURST=1000 UNAUTHENTICATED_RATELIMIT_MAX_BURST=1000` in front of `clients.sh`. The
tests create new accounts each time.
