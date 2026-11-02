# Kennword

A PHP port of [Vaultwarden](https://github.com/dani-garcia/vaultwarden), the Bitwarden-compatible server
written in Rust. Kennword is a modified version of Vaultwarden: its Rust source, translated into PHP
on Laravel since October 2026, following Vaultwarden commit
[`6ed6921`](https://github.com/dani-garcia/vaultwarden/commit/6ed6921cc2b0e03b4d74189574d2a5e71c512e97)
(release 1.37.5). [NOTICE.md](NOTICE.md) names everything it is based on.

It is meant to run on an ordinary PHP host, without Docker, and to be a drop-in replacement for
Vaultwarden: the same HTTP API for the official Bitwarden clients, the same database and the same
environment variables, so an installation can move from Vaultwarden to Kennword and back.

Until version 0.2.0 it was called Vaultwarphpen; we renamed it so that it does not borrow Vaultwarden's
name. *Kennwort* is German for password: Kennword keeps the German "kenn" (to know) and makes the rest
English. Say it "KEN-word".

> [!WARNING]
> Kennword is in early development and has not been independently audited. Two internal reviews
> against Vaultwarden ([security review](docs/security-review.md)) found and fixed vulnerabilities, so
> more may remain. Do not trust it with real passwords yet; try it with test accounts or with a copy of
> your data.

## Why a PHP port

At Lumundi, we run our company software exclusively in PHP, on managed servers. We liked Vaultwarden's
approach so much, a lean self-hosted server for the official Bitwarden clients, that we decided to port
it to PHP with the help of AI (see [Credits](#credits)).

## Status

[PARITY.md](PARITY.md) lists every route, setting, scheduled job, table, template and static asset of the
pinned Vaultwarden version and whether it is ported. In short:

- **Ported:** the database schema for SQLite, MySQL/MariaDB and PostgreSQL, interchangeable with
  Vaultwarden's; registration and login with the master password; two-step login (authenticator,
  email, WebAuthn, YubiKey, Duo, recovery code); account management, devices and login with a
  device; folders and Sends; ciphers and attachments; the organization API (members, collections,
  groups, policies, account recovery, import and export, API keys, the event log); emergency access;
  mails over SMTP or sendmail; Vaultwarden's scheduled jobs; the admin panel; the web vault (from
  Vaultwarden's [builds](docs/installation.md#web-vault)); SSO with OpenID Connect ([setup](docs/sso.md)); live
  notifications over WebSocket, served by an optional daemon ([installation](docs/installation.md#live-notifications)),
  and mobile push through Bitwarden's relay; website icons, fetched and cached like Vaultwarden's or
  redirected to an external icon service.
- **Not ported:** attachments and Send files in anything but a local folder (Vaultwarden's S3 and other
  OpenDAL backends), TPM and Android key attestation for WebAuthn (the clients send it only when asked,
  which Vaultwarden does not do) and the SMTP debug log. A few settings have no effect in PHP, such as
  the database pool sizes; [Configuration](docs/configuration.md#differences-from-vaultwarden) lists
  every difference.

Every ported route is compared with Vaultwarden itself: the differential tests send the same requests
to both servers and compare the answers. End-to-end tests drive the official web vault and CLI against
both, with the clients' own cryptography ([docs/clients.md](docs/clients.md)).

## Requirements

- PHP 8.5.12 or newer with the `openssl`, `sodium` and `mbstring` extensions and `pdo_sqlite`, `pdo_mysql`
  or `pdo_pgsql` for the database; website icons also need `xmlreader` and `zlib`, which PHP usually has
- SQLite, MySQL/MariaDB or PostgreSQL
- A web server that passes requests to PHP (Apache, nginx, Caddy, ...) and serves HTTPS

## Getting started

To try it locally, let [Composer](https://getcomposer.org) install it into a new folder:

```bash
composer create-project lumundi/kennword kennword
cd kennword
```

That is the latest [release](https://github.com/Lumundi/kennword/releases); add `dev-main`
for the current state of `main`.

This installs the dependencies, creates `.env` and the application key, creates the database (SQLite at
`data/db.sqlite3` by default) and downloads the web vault that Vaultwarden ships. In a Git checkout,
`composer setup` does the same. Then start PHP's built-in server and open `http://127.0.0.1:8000`, or
point a Bitwarden client at it:

```bash
php -S 127.0.0.1:8000 -t public public/index.php
```

Hosts without Composer get everything from a release archive instead: the code with its dependencies and
the web vault, ready to upload ([Installing from a release archive](docs/installation.md#installing-from-a-release-archive)).

For a real installation, read the documentation:

- [Installation](docs/installation.md): with Composer or from a release archive, web server, PHP
  settings, updates
- [Configuration](docs/configuration.md): Vaultwarden's settings and where Kennword differs
- [Single sign-on](docs/sso.md): setting up Microsoft Entra ID, Keycloak or Google Workspace
- [Moving from Vaultwarden](docs/migrating-from-vaultwarden.md): taking over an existing database and
  data folder, and going back
- [Security review](docs/security-review.md): what was reviewed, found and fixed, and what is open

## Reporting problems

Please report problems with Kennword in [this repository's issues](https://github.com/Lumundi/kennword/issues),
not to Vaultwarden: its maintainers have nothing to do with this port. Security issues go through the
private channel described in [SECURITY.md](SECURITY.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). [AGENTS.md](AGENTS.md) describes the commands, the parity
workflow and the conventions of the code, [docs/clients.md](docs/clients.md) the tests with the official
clients, and [docs/maintenance.md](docs/maintenance.md) how advisories and Vaultwarden's changes are
followed.

## Credits

Kennword exists because of the work of others. [NOTICE.md](NOTICE.md) lists all of it in detail:

- **[Vaultwarden](https://github.com/dani-garcia/vaultwarden)** by Daniel García and the
  [Vaultwarden contributors](https://github.com/dani-garcia/vaultwarden/graphs/contributors) (AGPL-3.0):
  the behaviour Kennword ports, its database migrations, templates and domain lists, and the
  reference every test compares against.
- **[Bitwarden](https://github.com/bitwarden)** by Bitwarden, Inc.: the server whose API Vaultwarden
  reimplements (AGPL-3.0), and the clients Kennword serves (GPL-3.0).
- **[Rocket](https://rocket.rs)** (MIT), whose default error pages Kennword copies, and the Rust
  crates whose behaviour it reproduces, among them Diesel, serde_json, chrono, jsonwebtoken, lettre,
  handlebars, webauthn-rs, openidconnect and oauth2.
- **[scssphp](https://scssphp.github.io/scssphp/)** (MIT), which compiles the web vault's style changes
  as grass does in Vaultwarden.
- **[Laravel](https://laravel.com)** (MIT) and the PHP packages it runs on.

Every commit so far was written with [Claude Code](https://claude.com/claude-code), Anthropic's AI
coding assistant; the commits say so in a `Co-Authored-By` trailer.

## License

Copyright (C) 2026 Lumundi Versand GmbH and the Kennword contributors.

Kennword is free software under the [GNU Affero General Public License, version 3](LICENSE.txt)
(AGPL-3.0-only), like Vaultwarden. If you run a modified version for others, the AGPL asks you to offer
them its source code.

Bitwarden is a trademark of Bitwarden, Inc. Kennword is not affiliated with, associated with or
endorsed by Bitwarden, Inc. or the Vaultwarden project.
