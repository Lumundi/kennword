# Configuration

Vaultwarphpen takes Vaultwarden's settings, under the same names, with the same defaults and the same
validation. Vaultwarden's documentation therefore applies:

- [`.env.template`](https://github.com/dani-garcia/vaultwarden/blob/6ed6921cc2b0e03b4d74189574d2a5e71c512e97/.env.template)
  of the pinned commit lists every setting with its description
- the [Vaultwarden wiki](https://github.com/dani-garcia/vaultwarden/wiki) explains them in depth

This page covers where the settings come from and where Vaultwarphpen differs.

## Where settings come from

Like Vaultwarden, in this order:

1. **Environment variables**, either real ones (set by the web server, PHP-FPM or the shell) or lines
   in `.env`. Real environment variables win over `.env`.
2. **`<NAME>_FILE`** instead of `<NAME>` reads the value from a file, for secrets such as
   `ADMIN_TOKEN_FILE` or `DATABASE_URL_FILE`.
3. **`config.json`** in the data folder (or at `CONFIG_FILE`) overrides the environment. The admin panel
   writes it, in Vaultwarden's format, so either implementation reads what the other saved.
4. **Defaults** for everything not set.

Invalid values and combinations are refused with Vaultwarden's error messages.

## Laravel's settings

The upper part of `.env` belongs to Laravel. Leave it as `.env.example` has it, set up for a server
(`APP_ENV=production`, `APP_DEBUG=false`), except:

- `APP_KEY`: created by `php artisan key:generate`
- `APP_ENV=local` and `APP_DEBUG=true` for development only
- `LOG_CHANNEL` and `LOG_STACK` if you want the log somewhere other than `storage/logs/laravel.log`

Keep the cache, session and queue drivers on `file` and `sync`. Laravel's `DB_*` variables are not
used; the database is configured with Vaultwarden's `DATABASE_URL`.

## Which settings take effect

Every setting is read and validated, and nearly all of them work as in Vaultwarden. These have no
effect:

- the database pool settings (see below)
- `TMP_FOLDER`: uploads wait in PHP's own temporary folder (`upload_tmp_dir`) until they are stored
- `DNS_PREFER_IPV6`: outgoing requests take the addresses in the order the system's resolver gives them
- `SMTP_DEBUG`, which makes Vaultwarden log the SMTP conversation; `SSO_DEBUG_TOKENS` only switches
  what is logged about the user who logged in with SSO, not the provider's tokens and answers

The `config:` items in [PARITY.md](../PARITY.md) show the state of each setting and how it is tested.

## Differences from Vaultwarden

- **Relative paths** (`DATA_FOLDER`, `DATABASE_URL` with SQLite, ...) are relative to the installation
  folder. Vaultwarden takes them relative to its working directory.
- **Storage** is a local folder. `ATTACHMENTS_FOLDER`, `SENDS_FOLDER` and `ICON_CACHE_FOLDER` take
  paths only; the `s3://` URLs that Vaultwarden builds with the `s3` feature accept are not supported.
- **Rocket's settings** (`ROCKET_ADDRESS`, `ROCKET_PORT`, `ROCKET_TLS` and the other `ROCKET_*`
  variables) do not exist: the web server and PHP take over their jobs. Upload limits are PHP's
  ([Installation](installation.md#php-settings)).
- **The database pool settings** `DATABASE_MAX_CONNS`, `DATABASE_MIN_CONNS`, `DATABASE_IDLE_TIMEOUT`,
  `DATABASE_TIMEOUT` and `DB_CONNECTION_RETRIES` are validated but have no effect: PHP opens one
  connection per request.
- **Logging** goes through Laravel's log (`storage/logs/laravel.log`, or wherever `LOG_CHANNEL` sends
  it), not to standard output. `LOG_LEVEL` takes Vaultwarden's values and sets the level of every
  channel: `trace` and `debug` become Laravel's `debug`, `warn` becomes `warning`, and `off` turns the
  log off. Levels for single modules, as in `info,vaultwarden::api::icons=debug`, are checked like
  Vaultwarden does, but only the first level counts. The lines look like Vaultwarden's
  (`EXTENDED_LOGGING`, `LOG_TIMESTAMP_FORMAT`), with `vaultwarphpen` where Vaultwarden names its Rust
  module. `LOG_FILE` adds a file and `USE_SYSLOG` the syslog (as `vaultwarden`, facility user), as in
  Vaultwarden; a file is not reopened on `SIGHUP`, which PHP does not need.
- **Scheduled jobs** run in a process of their own (`php artisan vaultwarden:schedule`) or from cron
  (`--once`), not inside the web server ([Installation](installation.md#scheduled-jobs)).
  `JOB_POLL_INTERVAL_MS` sets how often the process checks; with cron, cron decides, but `0` still
  turns all jobs off.
- **Live notifications** over WebSocket come from a daemon of their own (`php artisan
  vaultwarden:notifications`), to which the web server passes `/notifications/`
  ([Installation](installation.md#live-notifications)). Requests reach it through a socket in the data
  folder, or at `NOTIFICATIONS_SOCKET`, a setting of Vaultwarphpen's (`unix:///path` or
  `tcp://host:port`, on a loopback or other non-public address) for both sides. `ENABLE_WEBSOCKET=false`
  keeps the daemon from starting.
- **Push notifications** (`PUSH_*`) go to Bitwarden's relay like Vaultwarden's. The relay's access token
  is kept in Laravel's cache, shared by all PHP workers, for half of its lifetime. Notifications that
  Vaultwarden sends in the background go out after the response.
- **Rate limits** live in Laravel's cache (`storage/framework/cache`) instead of in memory, so all PHP
  workers share them. Vaultwarden keeps them per process.
- **Waiting on purpose.** Where Vaultwarden waits a second so that unknown addresses cannot be told
  apart by timing (the password hint, registration), a PHP worker waits with it; Vaultwarden's task
  waits without holding anything. The rate limits bound how many workers one address can keep busy.
- **The server's name.** Where Vaultwarden names itself to the clients (the `server` object of
  `/api/config`), Vaultwarphpen names itself and links to its own repository, so that users find the
  source of the server they use and report problems in the right place.
- **SSO** works like Vaultwarden's ([setup guide](sso.md)), except that `SSO_DEBUG_TOKENS` logs none
  of the provider's tokens. The discovered provider is cached for `SSO_CLIENT_CACHE_EXPIRATION` seconds in Laravel's
  cache, so all PHP workers share it.
- **The admin diagnostics** name Vaultwarphpen, with the Vaultwarden release it follows, and look for
  newer versions in Vaultwarphpen's repository (its latest release, or the latest commit for an
  installation from a branch). The installed version is what Composer recorded when it last installed
  the checkout, so run `composer install` after updating. The page shows PHP's version and server API
  where Vaultwarden shows Rust's runtime.
- **Settings take effect at once.** Vaultwarden reads `config.json` when it starts and when its admin
  panel saves; PHP reads the configuration for every request. Setting or removing `ADMIN_TOKEN` in
  `config.json` therefore opens or closes the admin panel right away, where Vaultwarden needs a restart.
- **The id of the user key.** Clients since 2026.10 record the id of the account's user key once
  (`POST /api/accounts/key-management/user-key-id`) and send it with new items. Vaultwarden 1.37.5 keeps
  it when the account key is rotated and then refuses the items encrypted by the new key ("Invalid key
  cipher"). Vaultwarphpen, like Bitwarden's server, takes the id of the new key from the rotation
  (`newUserKeyId`), and drops the old one when the request names none, as the web vault's does, so that
  the clients record the new one. An account whose key Vaultwarphpen rotated has no id or the new one,
  which Vaultwarden reads like any other.
- **Development routes.** Vaultwarden's debug builds serve static files from the source tree at
  `/vw_static/`; release builds do not, and neither does Vaultwarphpen.
- **Caches.** Do not cache Laravel's configuration or routes (see
  [Installation](installation.md#things-not-to-do)).
