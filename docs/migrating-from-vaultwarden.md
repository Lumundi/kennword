# Moving from Vaultwarden

Kennword uses Vaultwarden's database, data folder and settings unchanged. An existing installation
can therefore move over, and back again. Check a copy of your installation first: `php artisan
vaultwarden:check` tells you what needs attention before you switch.

> [!NOTE]
> Kennword covers Vaultwarden's features ([status](../README.md#status)). A few things work
> differently on a PHP host ([differences](configuration.md#differences-from-vaultwarden)): files stay on
> the local disk, so a data folder on S3 (`s3://`) cannot move; the web server takes the place of the
> `ROCKET_*` settings; PHP's upload limits must allow Vaultwarden's 525 MB; and live notifications need
> the [notifications daemon](installation.md#live-notifications). Try the move with a copy first.

## What carries over

| What | Where | Why it matters |
|---|---|---|
| Database | `data/db.sqlite3`, or the MySQL/PostgreSQL database in `DATABASE_URL` | all accounts, vaults and organizations |
| RSA key | `data/rsa_key.pem` | signs the login tokens; with the same key, clients stay logged in |
| Attachments | `data/attachments/` | files attached to vault items |
| Sends | `data/sends/` | files shared with Send |
| `config.json` | `data/config.json` | settings saved in Vaultwarden's admin panel |
| Settings | Vaultwarden's environment variables | same names, see [Configuration](configuration.md) |
| Icon cache | `data/icon_cache/` | optional; icons are fetched again when it is missing |

With Docker, the data folder is the volume mounted at `/data`.

## Checking your installation

Run the check on a copy of your data folder and database, with Vaultwarden's settings, before you
switch:

```bash
php artisan vaultwarden:check
```

It changes nothing. It looks at:

- **the settings:** whether Vaultwarden would accept them, which settings `config.json` holds and which
  of them it overrides in the environment, environment variables with invalid values, `DOMAIN`, and
  `ROCKET_*` settings that have no effect here;
- **the data folder:** whether `DATA_FOLDER` and the folders for attachments, Sends, icons and temporary
  files exist and PHP can write to them, whether they are relative (Vaultwarden resolves relative paths
  against its working directory, Kennword against its own folder), whether the RSA key is there
  and readable, the web vault, and PHP's upload limits;
- **the database:** the migrations booked in Diesel's table against the ones Kennword knows, and
  the schema against the one Vaultwarden creates (`parity/schema/<type>.json`), table by table and
  column by column;
- **the rows:** how many users, ciphers, attachments and so on there are, ciphers of types the clients
  cannot sync, JSON columns that do not parse, timestamps Vaultwarden does not write (SQLite), files
  of attachments and Sends that are missing, and old U2F and WebAuthn data, which `vaultwarden:migrate`
  converts.

Each finding is either a **problem**, which you fix before moving (the command then exits with 1), or a
**warning**, which you read and may accept. A missing `rsa_key.pem`, for instance, only means that every
client has to log in again.

The output is meant to be shared, for example in an issue or a support chat: it holds counts, table,
column and setting names, and yes or no. It never shows a value from a row or a setting, an email
address, a name or a path.

To check a database that is not the one in `DATABASE_URL`, name a connection of `config/database.php`:

```bash
php artisan vaultwarden:check --database=mysql
```

## Moving over

1. **Stop Vaultwarden**, so that nothing changes while you copy.
2. **Back up** the database and the data folder. With SQLite, copy `db.sqlite3` together with any
   `db.sqlite3-wal` and `db.sqlite3-shm` files.
3. **Install Kennword** as described in [Installation](installation.md), without creating a new
   database yet.
4. **Bring the data folder:** copy it to Kennword's `data` folder, or set `DATA_FOLDER` to where it
   is. PHP must be able to write to it.
5. **Bring the settings:** copy Vaultwarden's environment variables into `.env` (or the server's
   environment). Keep `DOMAIN` as it was, so that the clients and their security keys do not notice the
   change. Leave out the `ROCKET_*` settings.
6. **Check the installation:**

   ```bash
   php artisan vaultwarden:check
   ```

   Fix every problem it reports, and read the warnings.
7. **Apply missing migrations:**

   ```bash
   php artisan vaultwarden:migrate
   ```

   If your Vaultwarden was older than the version Kennword follows, this brings the schema up to
   date, exactly as a Vaultwarden update would. Kennword books the migrations in Diesel's own
   table, so Vaultwarden sees them as applied. It also converts old U2F and WebAuthn data, as
   Vaultwarden does at every start.
8. **Switch the web server** to Kennword and log in with a client. Clients that were logged in stay
   logged in, as long as the RSA key moved with the data folder.

Kennword follows the Vaultwarden commit pinned in
[`parity/reference.json`](../parity/reference.json). A database from a newer Vaultwarden may contain
migrations Kennword does not know (the check reports them); move over from that version or an
older one.

## Going back

1. **Stop Kennword** (and the notifications daemon and the scheduler, if they run).
2. **Start Vaultwarden** with the same database, data folder and settings.

Use a Vaultwarden that knows at least the migrations Kennword applied, that is the pinned version
or a newer one. Nothing needs converting: Kennword writes the rows, files, `config.json` and RSA key
in Vaultwarden's own formats, and tokens it issued stay valid with Vaultwarden.

## How the move is tested

The CI moves an installation in both directions on SQLite, MySQL and PostgreSQL
(`.github/scripts/migration.sh`, `tests/Migration`):

1. The pinned Vaultwarden fills a new installation through its API: users with each kind of KDF
   settings, ciphers of every type with attachments, folders, favourites and archived items, an
   organization with collections, groups, policies, account recovery and an API key, emergency access,
   Sends with a password and with a file, devices, login requests, events, two-step login with an
   authenticator app, a security key, email and a recovery code, and settings saved in the admin
   panel.
2. Vaultwarden stops; `vaultwarden:check` must find no problem, and `vaultwarden:migrate` runs.
3. Kennword serves the same database and data folder. Everything the clients read (syncs, devices,
   two-factor methods, emergency access, login requests, the organization, its events and API key,
   attachments and their files, Sends, the admin panel) must be exactly what Vaultwarden answered, and
   every way to log in must work with what Vaultwarden stored: tokens, remembered devices, the
   authenticator app, the security key, email codes, the recovery code, API keys and an approved login
   request. Then Kennword changes the installation: new and changed ciphers, folders, attachments,
   Sends, members, groups, policies, KDF settings, passwords, security keys and settings.
4. Vaultwarden starts on what Kennword left and must answer exactly as Kennword did, and log in
   with what Kennword stored.

Since `parity/schema` describes the databases Vaultwarden creates, the Reference workflow also checks
that both create the same schema, in both directions (`.github/scripts/database-parity.sh`).
