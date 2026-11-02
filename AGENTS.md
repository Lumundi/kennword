# Kennword

A feature-equivalent PHP implementation of [Vaultwarden](https://github.com/dani-garcia/vaultwarden),
built on Laravel 13. The goal is a drop-in replacement: same HTTP API, same database, same
environment variables, so the official Bitwarden clients and existing Vaultwarden data keep working.
It was called Vaultwarphpen until version 0.2.0; the repository is github.com/Lumundi/kennword, the
Composer package `lumundi/kennword`.

## Environment

- PHP 8.5.12 or newer is required. In Herd, `php` on the PATH is still 8.4, so run everything with
  Herd's PHP 8.6: `"$HOME/Library/Application Support/Herd/bin/php86"` (shown as `php86` below).
- Tests: `php86 artisan test`. To include MySQL, point `VW_TEST_MYSQL_DATABASE` (or
  `VW_TEST_PGSQL_DATABASE`) at an empty database that the tests may wipe, e.g.
  `VW_TEST_MYSQL_DATABASE=kennword_test php86 artisan test`.
- Static analysis (PHPStan, max level, PHP 8.5): `php86 vendor/bin/phpstan analyse --memory-limit=1G`.
- Code style: `php86 vendor/bin/pint`.
- Differential tests (`tests/Differential`) send the same requests to Vaultwarden and to us and
  compare the answers. They are skipped unless `VW_REFERENCE_URL` and `VW_SUBJECT_URL` are set;
  `.github/scripts/differential.sh <vaultwarden binary>` starts both servers and runs them. Write
  one for every route you implement. The script raises the login and unauthenticated rate limits,
  since every flow logs in; `Exchange::jsonString()` throws, so a broken setup fails loudly.
  Besides the default pair it starts one on a shared database (`VW_SHARED_*`), one with groups
  and events enabled (`VW_FEATURES_*`, used with `assertSameFlowsOn()`; it also talks to fake
  Yubico and Duo services over HTTPS, `.github/scripts/fake-services.php`, whose certificate
  authority it trusts through `SSL_CERT_FILE`; tests get `VW_SERVICES_CA` and
  `VW_SERVICES_HOST`) and one that sends mail to SMTP sinks (`VW_MAIL_*`,
  `.github/scripts/smtp-sink.php`; use `assertSameMailFlows()`, and `Server::mail()` to compare a
  mail or take its token). The mail pair also sets up email 2FA for verified sign-ups and as
  fallback (`EMAIL_2FA_*`); accounts registered by the tests are unverified unless their token
  says otherwise. A fifth pair logs in with SSO (`VW_SSO_*`) at the fake OpenID provider of
  `fake-services.php` (`/oidc`), where tests pick the user with extra parameters on the
  authorization URL. With `KEYCLOAK_URL` (reference.yml starts Keycloak with
  `.github/scripts/keycloak-realm.json`) a sixth pair logs in at a real Keycloak (`VW_KEYCLOAK_*`,
  `tests/Differential/KeycloakTest`): the test signs in at its login form (`Tests\Differential\Keycloak`),
  switches SSO settings through the admin panel and uses Keycloak's admin API. The default pair also runs our notifications daemon (`VW_SUBJECT_NOTIFICATIONS_URL`);
  `assertSameNotificationFlows()` hands flows a `Server` whose `hub()` opens a WebSocket
  (`Tests\Support\WebSocketClient`) at Vaultwarden's or the daemon's address. The features pair pushes to
  fake relays of `fake-services.php` (`/relay/<label>`); `assertSamePushFlows()` and `Server::relayed()`
  compare what arrived. `signedToken()` signs tokens with the key all
  servers share (`VW_RSA_KEY`). Responses are compared as JSON with objects kept apart from
  lists, after placeholders replace random values (`DifferentialTestCase::PLACEHOLDERS`).
- Client tests (`tests/Clients`, [docs/clients.md](docs/clients.md)) drive the pinned web vault (Playwright,
  Chromium) and `@bitwarden/cli` with real cryptography: one account in `vault.spec.ts`, an owner and a member in
  `sharing.spec.ts`, SSO logins in `sso.spec.ts`. `.github/scripts/clients.sh [--vaultwarden <binary>] [--serve]`
  starts the server with SQLite, the notifications daemon, an SMTP sink whose mail the tests read
  (`support/mail.ts`) and an HTTPS proxy (`tests/Clients/proxy.mjs`), and a second one with SSO at the fake
  OpenID provider (`VW_CLIENTS_SSO_URL`); `clients.yml` runs it on every push, `reference.yml` against Vaultwarden.
  Run `npm ci --ignore-scripts` and `npx playwright install chromium` there first; `PHP=php86` picks Herd's PHP.
- Live notifications: `php86 artisan vaultwarden:notifications` (`App\Notifications\Server`) serves the hubs of
  `src/api/notifications.rs` over WebSocket; upgrade requests go through the HTTP kernel to
  `NotificationsController`, which only accepts them inside the daemon. Handlers send updates with
  `App\Notifications\Notify` (Rust's `nt`), which hands them over a signed `Channel` (a Unix socket in the data
  folder, or `NOTIFICATIONS_SOCKET`) and calls `App\Support\Push` (src/api/push.rs); tests put
  `Tests\Fakes\NotificationsChannelFake` in the container. Work Vaultwarden spawns runs after the response
  (`App\Support\Deferred`).
- Mail: `App\Mail\Mail` ports `src/mail.rs`; the transport (`App\Mail\Transport`) is SMTP or
  sendmail. Tests put `Tests\Fakes\MailTransportFake` in the container. Locally, Herd Pro's mail
  service catches SMTP on 127.0.0.1:2525 (`SMTP_SECURITY=off`).
- Two-factor login: `App\Auth\Webauthn` ports webauthn-rs and keeps its stored formats;
  `Tests\Support\SoftwareAuthenticator` answers WebAuthn ceremonies in tests. Outgoing requests
  (Yubico, Duo, SSO) go through `App\Support\HttpClient`.
- SSO ([setup guide](docs/sso.md)): `App\Auth\Sso\Sso` ports src/sso.rs, `OidcClient` src/sso_client.rs with what it takes from
  the openidconnect and oauth2 crates (discovery, token requests, ID token checks in `Jws`).
- Scheduled jobs: `App\Scheduler\Jobs` ports the jobs of `schedule_jobs` (src/main.rs), `JobScheduler`
  and `Job` port job_scheduler_ng, `App\Support\CronSchedule` the cron crate. `php86 artisan
  vaultwarden:schedule` runs them (`--once` for cron), `vaultwarden:job <name>` runs one now.
- Web vault: `WebController` serves `WEB_VAULT_FOLDER` like src/api/web.rs, its catch-all as Laravel's
  fallback route; `App\Support\WebVault` holds Rocket's path segment rules, NamedFile's content types and
  the web vault version that the `webver` helper compares. scssphp compiles `/css/vaultwarden.css`.
  `php86 artisan vaultwarden:web-vault` installs the web vault from the Docker image Vaultwarden pins
  (`App\Support\WebVaultImage`, downloads through `App\Support\Downloader`, which tests fake);
  `composer create-project` and `composer setup` run it after `key:generate` and `vaultwarden:migrate`.
- Release archives: `php86 artisan release:build [ref]` clones the ref, installs it without dev
  dependencies and with the web vault, drops `ReleaseBuild::LEFT_OUT` and writes reproducible tar.gz
  and zip archives (`App\Release\ArchiveWriter`) with a `.sha256` to `build/`, next to the web vault's
  source archives (the tags of `web_vault_source` in `parity/reference.json`, GPL-3.0 section 6).
  `release.yml` runs it for `v*` tags and attaches them to the release (a draft if there is none). When a
  new top-level file or folder is only for development, add it to `LEFT_OUT`. When the web vault pin
  moves, move `web_vault_source` with it; `NoticeTest` checks that NOTICE.md names those tags.
- Uploads: Vaultwarden takes files up to 525 MB, so PHP needs `upload_max_filesize=525M` and a
  `post_max_size` above it (or `0`). PHP cuts uploaded file names at the last slash, which encrypted
  names contain; read them with `getClientOriginalPath()` (see `App\Http\Data\UploadData`).
- Database schema: `php86 artisan vaultwarden:migrate`. It also converts old U2F and WebAuthn data,
  which Vaultwarden does at every start.
- Moving installations ([docs/migrating-from-vaultwarden.md](docs/migrating-from-vaultwarden.md)):
  `php86 artisan vaultwarden:check` looks at an installation before it moves (settings, data folder,
  schema against `parity/schema`, rows we could not read). Its output may be shared, so it prints counts
  and names only, never values or paths; keep it that way. The migration test (`tests/Migration`,
  `.github/scripts/migration.sh <vaultwarden binary> sqlite|mysql|pgsql`) lets Vaultwarden fill an
  installation, moves it to us and back, and compares what the clients read after each move. When you
  port something that stores data, add it to the test's fill or move phase.
- CI (GitHub Actions): `tests.yml` runs Pint, PHPStan, `composer audit` and the tests on SQLite, MySQL
  and PostgreSQL.
  `reference.yml` builds the pinned Vaultwarden for Linux, and for macOS (arm64) only when started by
  hand (Actions → Reference → Run workflow), and keeps the binaries as workflow artifacts. Its databases job lets Vaultwarden create SQLite, MySQL and PostgreSQL databases
  and checks both directions with `.github/scripts/database-parity.sh`; its migrate job runs the
  migration test on all three. It runs when the pin, the snapshots or the migrator change, or on demand.
- Advisories and upstream changes ([docs/maintenance.md](docs/maintenance.md)): Dependabot proposes
  security updates and patches (`.github/dependabot.yml`), and `watch.yml` runs `php artisan
  parity:watch --issues`, which keeps one issue per finding (`app/Parity/Watch`). Run it without
  `--issues` to see the findings; it never changes code.

## Parity workflow

Everything is measured against one pinned Vaultwarden commit.

- `parity/reference.json` pins the commit, release and web vault version, with the digest of the web
  vault's Docker image. Both come from Vaultwarden's `docker/DockerSettings.yaml`; `parity:generate`
  checks them. `web_vault_source` names the tags of vw_web_builds and bw_web_builds that build it.
- `php artisan parity:fetch` checks that commit out into `reference/vaultwarden` (git-ignored).
- `php artisan parity:sync` copies Vaultwarden's SQL migrations to `database/vaultwarden/<dialect>`,
  its Handlebars templates to `resources/vaultwarden/templates` and `global_domains.json` to
  `resources/vaultwarden/static`. Never edit those copies.
- `php artisan parity:generate` extracts every route, setting, scheduled job, table, template and
  static asset into `parity/matrix.json` and writes `PARITY.md`. Status and notes survive.
- Status is `todo`, `partial`, `done` or `wontfix`. An item may only be `done` when a test carries
  `#[Parity('<id>')]` (a trailing `*` matches a prefix); `tests/Unit/Parity/ParityMatrixTest` enforces this.
- Set a status with `php artisan parity:report --mark='route:GET /api/sync' --status=done --note='...'`.
- `php artisan parity:upstream [revision]` lists the upstream commits since the pin with the parity
  items whose source they change. Run it for the release before moving the pin: a changed item keeps
  its status, so `parity:generate` does not show it.
- Moving to a newer upstream: update `parity/reference.json`, then `parity:fetch`, `parity:sync`,
  `parity:generate`, and work through the added and removed items and the list of `parity:upstream`.
  Push, and commit the `parity-schema` artifact of the Reference run to `parity/schema`.

## Rules

- Port behaviour from the Rust source at the pinned commit. Each matrix item names its source
  location; read it before implementing.
- The schema comes only from Vaultwarden's own migrations, applied by `App\Database\VaultwardenMigrator`,
  which books them in Diesel's `__diesel_schema_migrations`. The database stays interchangeable with
  Vaultwarden in both directions. Do not add Laravel migrations or extra tables; cache, sessions and
  queues use file or sync drivers.
- Where `src/db/schema.rs` and the migrations disagree, the migrations win. The known cases are listed
  in `tests/Feature/Database/VaultwardenMigratorTest.php`.
- `parity/schema/<dialect>.json` describes the databases Vaultwarden itself creates (booked migrations,
  tables, columns, indexes, foreign keys; see `App\Database\SchemaSnapshot`). The Reference workflow
  writes them with `php artisan parity:schema` and fails when they differ from the committed ones;
  never edit them by hand, commit its `parity-schema` artifact instead. The migrator tests compare
  our databases against them.
- Vaultwarden's settings are not Laravel configuration. `App\Config\Config` reads them like Vaultwarden:
  environment variables (raw, with `<NAME>_FILE`), overridden by `config.json` in the data folder,
  completed with the defaults of `App\Config\Settings` (a port of `make_config!`, checked against the
  matrix) and validated by `App\Config\ConfigValidator`. Use `app(Config::class)->string('domain')` etc.
  Relative paths are relative to the base path, where Vaultwarden uses its working directory.
- `DATABASE_URL` configures the default `vaultwarden` connection (`App\Database\DatabaseUrl`), with
  Vaultwarden's session settings (UTC, SQLite foreign keys enforced like Diesel, `DATABASE_CONN_INIT`). The
  `sqlite`, `mysql` and `pgsql` connections are only for tests and tools that name them.
- The project is licensed AGPL-3.0-only, like Vaultwarden, from which it is derived. `NOTICE.md`
  credits every work it builds on. Whoever copies a file, starts from one or reproduces another
  library's behaviour adds it there, with the license text when the license asks for it. After a
  Composer change, update its package tables; `tests/Unit/NoticeTest` compares them with `composer.lock`
  and checks that every directory `parity:sync` fills is named.
- Where Vaultwarden names itself to clients (the `server` object of `/api/config`), we name Kennword
  and link to this repository: users must be able to find the source of the server they talk to (AGPL
  section 13), and bug reports must not land at Vaultwarden. Copied templates and setting defaults stay
  as they are. The same holds for the diagnostics of the admin panel: they name Kennword with the
  Vaultwarden release it mirrors (`App\Support\Release`), look for newer versions in this repository and
  show PHP's runtime instead of Rust's; the differential test compares that page by its structure only.

## HTTP conventions

- Routes live in `routes/vaultwarden.php`, mounted below `DOMAIN`'s path like Vaultwarden's mount points,
  and are named after their Rust handler (`core::now`). One controller per Rust module
  (`src/api/core/mod.rs` → `CoreController`), methods named after the handlers.
- No Laravel middleware groups: the only global middleware are `Cors` and `AppHeaders`, ports of
  Vaultwarden's response fairings. Laravel's input trimming, empty-string-to-null and CORS are off.
- Errors: throw `App\Http\ApiError` for `err!`, `err_code!`, `err_json!` and friends. Everything else is
  rendered by `App\Http\ErrorRenderer` like Rocket's catchers (API 404 JSON, the 404 page, Rocket's
  default catcher). Database errors become `{"message":"Db",...}` like Vaultwarden's `?` conversions.
- JSON: use `App\Http\Json`. Values built with `json!()` in Rust have their keys sorted (serde_json runs
  without `preserve_order`), so pass them through `Json::sorted()`; derived structs keep field order.
- Request guards like Rocket's (`App\Auth\Headers`, ...) are resolved by type-hinting them in a
  controller method; failures throw `App\Http\Unauthorized` (401, reason logged).
- Models (`app/Models`) extend `App\Models\Model`: `save()` writes every column with an upsert like
  Diesel, bytes go through the `Binary` cast, timestamps through `NaiveDateTime`. `toApi()` is Rust's
  `to_json()`.
- Tokens: `App\Auth\Jwt` with the key file `App\Auth\RsaKeys` shares with Vaultwarden. Claims are arrays
  in the field order of the Rust struct. `.github/scripts/token-parity.sh` checks interop in CI.
