<?php

namespace App\Console\Commands;

use App\Auth\Webauthn\Registrations;
use App\Auth\Webauthn\U2fRegistration;
use App\Config\Config;
use App\Config\ConfigException;
use App\Config\ConfigFileStatus;
use App\Config\Settings;
use App\Database\DatabaseUrl;
use App\Database\SchemaComparison;
use App\Database\SchemaSnapshot;
use App\Database\VaultwardenMigrator;
use App\Models\Cipher;
use App\Models\Send;
use App\Models\TwoFactor;
use App\Support\JsonValue;
use App\Support\Release;
use Illuminate\Console\Command;
use Illuminate\Database\Connection;
use Illuminate\Database\DatabaseManager;
use Illuminate\Support\Env;
use PDO;
use PDOException;
use stdClass;
use Throwable;

/**
 * Looks at a copy of a Vaultwarden installation before it moves here: the
 * settings, the data folder, the schema against the one Vaultwarden creates
 * (parity/schema) and the rows we could not read. It changes nothing.
 *
 * What it prints is meant to be shared, in a chat or an issue: counts,
 * table, column and setting names, yes and no. Never a value of a row or of
 * a setting, and no paths, which may name people.
 */
class VaultwardenCheck extends Command
{
    /**
     * @var string
     */
    protected $signature = 'kennword:check {--database= : The database connection to check}';

    /**
     * @var string
     */
    protected $description = 'Check a copy of a Vaultwarden installation before moving it here; prints counts and names only';

    /**
     * Rows read at a time where every row is looked at.
     */
    private const int CHUNK = 500;

    /**
     * Folders the data lives in; they are made when first needed.
     */
    private const array FOLDERS = ['attachments_folder', 'sends_folder', 'icon_cache_folder', 'tmp_folder'];

    /**
     * Tables whose rows are counted, with what they hold.
     */
    private const array COUNTED = [
        'users' => 'Users',
        'organizations' => 'Organizations',
        'ciphers' => 'Ciphers',
        'folders' => 'Folders',
        'attachments' => 'Attachments',
        'sends' => 'Sends',
        'devices' => 'Devices',
        'twofactor' => 'Two-factor methods',
        'emergency_access' => 'Emergency access',
        'auth_requests' => 'Login requests',
        'event' => 'Events',
    ];

    private int $warnings = 0;

    private int $problems = 0;

    public function handle(DatabaseManager $databases, VaultwardenMigrator $migrator): int
    {
        $this->components->info(Release::NAME.' '.Release::installed().' follows Vaultwarden '.Release::vaultwarden().'. Nothing is changed.');

        $config = $this->settings();
        $this->folders($config);
        $connection = $this->database($databases, $migrator, $config);
        if ($connection !== null) {
            $this->rows($connection, $config);
        }

        $this->newLine();
        $warnings = $this->warnings === 1 ? '1 warning' : "{$this->warnings} warnings";
        if ($this->problems > 0) {
            $this->components->error(($this->problems === 1 ? '1 problem' : "{$this->problems} problems").", {$warnings}: fix the problems before moving.");

            return self::FAILURE;
        }
        $this->components->info($this->warnings === 0 ? 'Ready to move.' : "Ready to move, {$warnings} to read.");

        return self::SUCCESS;
    }

    /**
     * The settings as Vaultwarden would load them. With invalid ones, which
     * keep Vaultwarden from starting, the rest is checked with them anyway.
     */
    private function settings(): Config
    {
        $this->section('Settings');
        $env = static fn (string $key): ?string => Env::getRepository()->get($key);
        try {
            $config = Config::load($env, base_path());
            $this->ok('Valid', 'yes');
        } catch (ConfigException $exception) {
            $config = Config::load($env, base_path(), validate: false);
            $names = self::settingNames($exception->getMessage());
            $this->problem('Valid', 'no', 'Vaultwarden would not start with these settings either'.($names === [] ? '.' : ': '.implode(', ', $names).'.')
                .' php artisan kennword:migrate tells why; its message may quote values, so do not share it.');
            // So that the database can be checked with them.
            app()->instance(Config::class, $config);
        }

        match ($config->fileStatus) {
            ConfigFileStatus::NotFound => $this->note('config.json', 'none'),
            ConfigFileStatus::Loaded => $this->note('config.json', self::plural(count($config->file->values), 'setting').': '.self::upper(array_keys($config->file->values))),
            ConfigFileStatus::Error => $this->warning('config.json', 'unreadable', 'Vaultwarden ignores it as a whole, and so do we. Save the settings again in the admin panel.'),
        };
        if ($config->overrides !== []) {
            $this->note('Also in the environment', implode(', ', $config->overrides).' (config.json wins)');
        }
        if ($config->env->invalid !== []) {
            $this->warning('Invalid values', self::upper($config->env->invalid), 'These environment variables are ignored, here as in Vaultwarden.');
        }
        if (isset($config->env->values['domain']) || isset($config->file->values['domain'])) {
            $this->ok('DOMAIN', 'set');
        } else {
            $this->warning('DOMAIN', 'not set', 'Set the DOMAIN Vaultwarden had: security keys and the links in mails and attachments depend on it.');
        }
        $rocket = array_filter(array_keys(getenv()), static fn (string $name): bool => str_starts_with($name, 'ROCKET_'));
        if ($rocket !== []) {
            $this->note('Ignored here', implode(', ', $rocket).' (the web server takes their place)');
        }

        return $config;
    }

    /**
     * The data folder and what lives in it.
     */
    private function folders(Config $config): void
    {
        $this->section('Data folder');
        $data = $config->string('data_folder');
        $relative = $data !== '' && ! str_starts_with($data, '/') && ! str_contains($data, '://');
        $label = 'DATA_FOLDER'.($relative ? ' (relative)' : '');
        if (str_starts_with($data, 's3://')) {
            $this->problem($label, 'S3', 'Kennword keeps its data on the local disk only.');
        } elseif (! is_dir($config->path('data_folder'))) {
            $this->problem($label, 'missing', 'Copy Vaultwarden\'s data folder here, or set DATA_FOLDER to where it is.');
        } elseif (! is_writable($config->path('data_folder'))) {
            $this->problem($label, 'not writable', 'PHP must be able to write to the data folder.');
        } else {
            $this->ok($label, 'found, writable');
        }
        if ($relative) {
            $this->line('    Relative paths start from Kennword\'s folder here; Vaultwarden starts them from its working directory (/ in Docker).');
        }

        foreach (self::FOLDERS as $name) {
            $path = $config->string($name);
            $label = strtoupper($name);
            if (str_starts_with($path, 's3://')) {
                $this->problem($label, 'S3', 'Kennword keeps its data on the local disk only.');
            } elseif (! is_dir($config->path($name))) {
                $this->note($label, 'none yet');
            } elseif (! is_writable($config->path($name))) {
                $this->problem($label, 'not writable', 'PHP must be able to write to it.');
            } else {
                $this->ok($label, 'found, writable');
            }
        }

        $key = $config->absolutePath($config->privateRsaKey());
        if (! is_file($key)) {
            $this->warning('RSA key', 'missing', 'A new key is made, and every client has to log in again. Copy rsa_key.pem from Vaultwarden to keep them logged in.');
        } else {
            $private = is_readable($key) ? openssl_pkey_get_private((string) file_get_contents($key)) : false;
            $details = $private === false ? false : openssl_pkey_get_details($private);
            if (! is_array($details) || ($details['type'] ?? null) !== OPENSSL_KEYTYPE_RSA) {
                $this->problem('RSA key', 'unreadable', 'The key file is no RSA private key PHP can read.');
            } else {
                $bits = $details['bits'] ?? null;
                $this->ok('RSA key', 'found, '.(is_int($bits) ? $bits : '?').' bits');
            }
        }

        if (! $config->bool('web_vault_enabled')) {
            $this->note('Web vault', 'disabled');
        } elseif (is_file($config->path('web_vault_folder').'/index.html')) {
            $this->ok('Web vault', 'found');
        } else {
            $this->warning('Web vault', 'missing', 'Install it with php artisan kennword:web-vault, or set WEB_VAULT_ENABLED=false.');
        }

        $limits = ['upload_max_filesize' => self::bytes((string) ini_get('upload_max_filesize')), 'post_max_size' => self::bytes((string) ini_get('post_max_size'))];
        $small = array_filter($limits, static fn (int $bytes, string $name): bool => $name === 'post_max_size' ? $bytes !== 0 && $bytes <= 525 * 1024 * 1024 : $bytes < 525 * 1024 * 1024, ARRAY_FILTER_USE_BOTH);
        if ($small === []) {
            $this->ok('PHP upload limits', 'large enough');
        } else {
            $this->warning('PHP upload limits', implode(', ', array_keys($small)).' too small',
                'Vaultwarden takes files up to 525 MB: set upload_max_filesize=525M and post_max_size above it, for the web server\'s PHP too.');
        }
    }

    /**
     * The connection, the booked migrations and the schema; null when the rows cannot be read.
     */
    private function database(DatabaseManager $databases, VaultwardenMigrator $migrator, Config $config): ?Connection
    {
        $this->section('Database');
        $name = $this->option('database');
        // Before connecting, which would switch on a write-ahead log of our own.
        $file = $this->sqliteFile(is_string($name) ? $name : null, $config);
        if ($file !== null && ! is_file($file)) {
            $this->problem('SQLite database', 'missing', 'Copy db.sqlite3 from Vaultwarden\'s data folder, or point DATABASE_URL at it.');

            return null;
        }
        $wal = $file === null ? false : @filesize("{$file}-wal");
        if (is_int($wal) && $wal > 0) {
            $this->note('Write-ahead log', 'not empty (keep db.sqlite3-wal and db.sqlite3-shm with db.sqlite3)');
        }
        try {
            $connection = $databases->connection(is_string($name) ? $name : null);
            $pdo = $connection->getPdo();
            $dialect = $migrator->dialect($connection);
        } catch (Throwable $exception) {
            $code = $exception instanceof PDOException && is_string($exception->getCode()) ? " (SQLSTATE {$exception->getCode()})" : '';
            $this->problem('Connection', 'failed'.$code, 'Check DATABASE_URL. For SQLite, the database file must exist.');

            return null;
        }
        $version = $pdo->getAttribute(PDO::ATTR_SERVER_VERSION);
        $this->note('Type', match ($dialect) {
            'sqlite' => 'SQLite',
            'mysql' => is_string($version) && str_contains(strtolower($version), 'mariadb') ? 'MariaDB' : 'MySQL',
            default => 'PostgreSQL',
        }.(is_string($version) ? ' '.strtok($version, '-') : ''));

        $schema = $connection->getSchemaBuilder();
        if (! $schema->hasTable(VaultwardenMigrator::TABLE)) {
            $this->problem('Booked migrations', 'none', $schema->getTables() === []
                ? 'The database is empty. Does DATABASE_URL point at Vaultwarden\'s database?'
                : 'This is no Vaultwarden database: Diesel\'s __diesel_schema_migrations is missing.');

            return null;
        }
        $booked = [];
        foreach ($connection->select('SELECT version FROM '.VaultwardenMigrator::TABLE) as $row) {
            if (is_object($row) && is_string($row->version ?? null)) {
                $booked[] = $row->version;
            }
        }
        $known = array_column($migrator->migrations($dialect), 'version');
        $pending = array_diff($known, $booked);
        $unknown = array_values(array_diff($booked, $known));
        $this->note('Booked migrations', count(array_intersect($booked, $known)).' of '.count($known));
        if ($unknown !== []) {
            sort($unknown);
            $this->problem('From a newer Vaultwarden', implode(', ', $unknown),
                'These migrations are newer than Vaultwarden '.Release::vaultwarden().', which Kennword follows. Move from that version or an older one.');
        }
        if ($pending !== []) {
            $this->warning('To apply', (string) count($pending), 'php artisan kennword:migrate applies them, as a Vaultwarden update would. '
                .'Afterwards, go back only to Vaultwarden '.Release::vaultwarden().' or newer.');
        }

        if ($pending === [] && $unknown === []) {
            $this->schema($connection, $dialect);
        } else {
            $this->note('Schema', 'compared once the migrations match');
        }

        return $connection;
    }

    /**
     * The SQLite file of a connection; null for other databases.
     */
    private function sqliteFile(?string $name, Config $config): ?string
    {
        $connection = config()->array('database.connections')[$name ?? config()->string('database.default')] ?? null;
        $driver = is_array($connection) ? ($connection['driver'] ?? null) : null;
        if ($driver === 'vaultwarden') {
            $url = $config->string('database_url');

            return DatabaseUrl::type($url, $config) === 'sqlite' ? DatabaseUrl::sqlitePath($url, $config) : null;
        }
        $file = is_array($connection) && $driver === 'sqlite' ? ($connection['database'] ?? null) : null;

        return is_string($file) && $file !== ':memory:' ? $file : null;
    }

    private function schema(Connection $connection, string $dialect): void
    {
        $expected = json_decode((string) @file_get_contents(base_path("parity/schema/{$dialect}.json")), true);
        if (! is_array($expected)) {
            $this->warning('Schema', 'not compared', "parity/schema/{$dialect}.json is missing.");

            return;
        }
        $differences = SchemaComparison::between($expected, SchemaSnapshot::of($connection));
        if ($differences->isSame()) {
            $this->ok('Schema', 'as Vaultwarden '.Release::vaultwarden().' creates it');

            return;
        }
        if ($differences->missingTables !== [] || $differences->missingColumns !== []) {
            $this->problem('Schema', 'incomplete', 'Missing: '.implode(', ', [...$differences->missingTables, ...$differences->missingColumns]).'.');
        }
        if ($differences->extraTables !== [] || $differences->extraColumns !== []) {
            $this->warning('Schema', 'extended', 'Not Vaultwarden\'s, left alone: '.implode(', ', [...$differences->extraTables, ...$differences->extraColumns]).'.');
        }
        if ($differences->changedColumns !== [] || $differences->changedKeys !== []) {
            $this->warning('Schema', 'altered', 'Other types, defaults or keys than Vaultwarden creates: '.implode(', ', [...$differences->changedColumns, ...$differences->changedKeys]).'.');
        }
    }

    /**
     * Counts of what the installation holds, and the rows we could not read.
     */
    private function rows(Connection $connection, Config $config): void
    {
        $this->section('Data');
        $schema = $connection->getSchemaBuilder();
        foreach (self::COUNTED as $table => $label) {
            if ($schema->hasTable($table)) {
                $this->note($label, (string) $connection->table($table)->count());
            }
        }

        $this->check('Ciphers of unknown types', function () use ($connection): void {
            $unknown = $connection->table('ciphers')->whereNotIn('atype', array_keys(Cipher::TYPE_KEYS))->count();
            $unknown === 0 ? $this->ok('Ciphers of unknown types', 'none') : $this->problem('Ciphers of unknown types', (string) $unknown,
                'Syncing fails for the users who see them, in Vaultwarden too. Delete them in Vaultwarden first.');
        });

        $this->check('Unreadable JSON', function () use ($connection): void {
            $object = static fn (?string $json): bool => $json !== null && self::decodes($json, static fn (mixed $value): bool => $value instanceof stdClass);
            $objects = static fn (?string $json): bool => $json === null || self::decodes($json, static fn (mixed $value): bool => is_array($value)
                && array_all($value, static fn (mixed $item): bool => $item instanceof stdClass));
            $json = static fn (?string $json): bool => $json === null || self::decodes($json, static fn (mixed $_): bool => true);
            $unreadable = array_filter([
                'ciphers.data' => $this->countRows($connection, 'ciphers', 'uuid', ['data'], static fn (stdClass $row): bool => ! $object(self::text($row->data))),
                'ciphers.fields' => $this->countRows($connection, 'ciphers', 'uuid', ['fields'], static fn (stdClass $row): bool => ! $objects(self::text($row->fields))),
                'ciphers.password_history' => $this->countRows($connection, 'ciphers', 'uuid', ['password_history'], static fn (stdClass $row): bool => ! $objects(self::text($row->password_history))),
                'sends.data' => $this->countRows($connection, 'sends', 'uuid', ['data'], static fn (stdClass $row): bool => ! $object(self::text($row->data))),
                'org_policies.data' => $this->countRows($connection, 'org_policies', 'uuid', ['data'], static fn (stdClass $row): bool => ! $json(self::text($row->data))),
                'users.equivalent_domains' => $this->countRows($connection, 'users', 'uuid', ['equivalent_domains'], static fn (stdClass $row): bool => ! $json(self::text($row->equivalent_domains))),
                'users.excluded_globals' => $this->countRows($connection, 'users', 'uuid', ['excluded_globals'], static fn (stdClass $row): bool => ! $json(self::text($row->excluded_globals))),
            ]);
            $unreadable === [] ? $this->ok('Unreadable JSON', 'none') : $this->warning('Unreadable JSON', self::counts($unreadable),
                'Clients get these entries empty or without the broken part, as from Vaultwarden.');
        });

        if ($connection->getDriverName() === 'sqlite') {
            $this->check('Timestamps', function () use ($connection): void {
                $unreadable = array_filter($this->unreadableTimestamps($connection));
                $unreadable === [] ? $this->ok('Timestamps', 'readable') : $this->problem('Timestamps', self::counts($unreadable),
                    'These rows hold timestamps in a form Vaultwarden does not write; we cannot read them.');
            });
        }

        $this->check('Files', function () use ($connection, $config): void {
            $folder = $config->path('attachments_folder');
            $attachments = $this->countRows($connection, 'attachments', 'id', ['cipher_uuid'],
                static fn (stdClass $row): bool => ! is_file("{$folder}/".self::text($row->cipher_uuid).'/'.self::text($row->id)));
            $sends = $config->path('sends_folder');
            $files = $this->countRows($connection, 'sends', 'uuid', ['atype', 'data'], static function (stdClass $row) use ($sends): bool {
                [$ok, $data] = JsonValue::decode(self::text($row->data) ?? '');
                $id = $ok && $data instanceof stdClass ? ($data->id ?? null) : null;

                return self::text($row->atype) === (string) Send::TYPE_FILE && is_string($id) && ! is_file("{$sends}/".self::text($row->uuid)."/{$id}");
            });
            $missing = array_filter(['attachments' => $attachments, 'Sends' => $files]);
            $missing === [] ? $this->ok('Files', 'all found') : $this->warning('Files', self::counts($missing).' missing',
                'Copy the attachments and sends folders from Vaultwarden\'s data folder. Downloads of the missing files fail.');
        });

        $this->check('Security keys', function () use ($connection): void {
            $this->securityKeys($connection);
        });
    }

    /**
     * Old U2F and WebAuthn data, which kennword:migrate converts like Vaultwarden does at every start.
     */
    private function securityKeys(Connection $connection): void
    {
        $webauthnUsers = [];
        $old = $broken = 0;
        foreach ($connection->table('twofactor')->select(['uuid', 'user_uuid', 'data'])->where('atype', TwoFactor::TYPE_WEBAUTHN)->orderBy('uuid')->lazy(self::CHUNK) as $row) {
            $data = self::text($row->data ?? null) ?? '';
            $current = Registrations::parse($data);
            if ($current !== null) {
                if ($current !== []) {
                    $webauthnUsers[self::text($row->user_uuid ?? null) ?? ''] = true;
                }
            } elseif (Registrations::parseV3($data) !== null) {
                $old++;
            } else {
                $broken++;
            }
        }
        $u2f = 0;
        foreach ($connection->table('twofactor')->select(['uuid', 'user_uuid', 'data'])->where('atype', TwoFactor::TYPE_U2F)->orderBy('uuid')->lazy(self::CHUNK) as $row) {
            $registrations = U2fRegistration::parseList(self::text($row->data ?? null) ?? '');
            if ($registrations === null) {
                $broken++;
            } elseif ($registrations !== [] && $registrations[0]->migrated !== true && ! isset($webauthnUsers[self::text($row->user_uuid ?? null) ?? ''])) {
                $u2f++;
            }
        }

        if ($u2f + $old > 0) {
            $this->note('Security keys to convert', implode(', ', array_filter([$u2f > 0 ? self::plural($u2f, 'U2F user') : '', $old > 0 ? self::plural($old, 'old WebAuthn user') : ''])));
            $this->line('    kennword:migrate converts them, as Vaultwarden does at every start.');
        }
        if ($broken > 0) {
            $this->problem('Security keys', self::plural($broken, 'unreadable row'), 'These keys cannot log in, here as in Vaultwarden, which does not even start with unreadable U2F data. '
                .'Have their users remove the keys in Vaultwarden and add them again.');
        } else {
            $this->ok('Security keys', 'readable');
        }
    }

    /**
     * Rows of timestamp columns that NaiveDateTime cannot parse, by table.column.
     *
     * @return array<string, int>
     */
    private function unreadableTimestamps(Connection $connection): array
    {
        $grammar = $connection->getQueryGrammar();
        $counts = [];
        foreach (SchemaSnapshot::of($connection)['tables'] as $table => $details) {
            foreach ($details['columns'] as $column) {
                $name = $column['name'] ?? null;
                if (! is_string($name) || ! in_array(strtolower(is_string($column['type'] ?? null) ? $column['type'] : ''), ['datetime', 'timestamp'], true)) {
                    continue;
                }
                // Like NaiveDateTime::parse: date, a space or T, time, and a fraction of up to nine digits.
                // The names come from the schema itself.
                $value = $grammar->wrap($name);
                $count = $connection->scalar("SELECT count(*) FROM {$grammar->wrapTable($table)} WHERE {$value} IS NOT NULL AND NOT (typeof({$value}) = 'text'"
                    ." AND {$value} GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9][ T][0-9][0-9]:[0-9][0-9]:[0-9][0-9]*'"
                    ." AND (length({$value}) = 19 OR (length({$value}) BETWEEN 21 AND 29 AND substr({$value}, 20, 1) = '.' AND substr({$value}, 21) NOT GLOB '*[^0-9]*')))");
                $counts["{$table}.{$name}"] = is_int($count) ? $count : 0;
            }
        }

        return $counts;
    }

    /**
     * How many rows of a table match, read a chunk at a time.
     *
     * @param  list<string>  $columns  Besides the key
     * @param  callable(stdClass): bool  $matches
     */
    private function countRows(Connection $connection, string $table, string $key, array $columns, callable $matches): int
    {
        if (! $connection->getSchemaBuilder()->hasTable($table)) {
            return 0;
        }
        $count = 0;
        foreach ($connection->table($table)->select([$key, ...$columns])->orderBy($key)->lazy(self::CHUNK) as $row) {
            if ($matches($row)) {
                $count++;
            }
        }

        return $count;
    }

    /**
     * Runs one check; a failure to run it counts as a problem, without its message, which may quote a row.
     */
    private function check(string $label, callable $check): void
    {
        try {
            $check();
        } catch (Throwable $exception) {
            $this->problem($label, 'not checked', 'The check failed with '.class_basename($exception).'. Is the schema complete?');
        }
    }

    /**
     * @param  callable(mixed): bool  $shape
     */
    private static function decodes(string $json, callable $shape): bool
    {
        [$ok, $value] = JsonValue::decode($json);

        return $ok && $shape($value);
    }

    private static function text(mixed $value): ?string
    {
        return is_string($value) || is_int($value) ? (string) $value : null;
    }

    /**
     * Setting names a validation message mentions; the rest of it may quote values.
     *
     * @return list<string>
     */
    private static function settingNames(string $message): array
    {
        $names = array_values(array_filter(array_map(strtoupper(...), array_keys(Settings::all())),
            static fn (string $name): bool => preg_match('/(?<![A-Z_])'.preg_quote($name, '/').'(?![A-Z_])/', $message) === 1));
        sort($names);

        return $names;
    }

    /**
     * @param  list<string>  $names
     */
    private static function upper(array $names): string
    {
        return implode(', ', array_map(strtoupper(...), $names));
    }

    /**
     * @param  array<string, int>  $counts
     */
    private static function counts(array $counts): string
    {
        return implode(', ', array_map(static fn (string $name, int $count): string => "{$name} {$count}", array_keys($counts), $counts));
    }

    private static function plural(int $count, string $noun): string
    {
        return $count === 1 ? "1 {$noun}" : "{$count} {$noun}s";
    }

    /**
     * An ini size ("525M") in bytes.
     */
    private static function bytes(string $size): int
    {
        $number = (int) $size;

        return match (strtoupper(substr(trim($size), -1))) {
            'G' => $number * 1024 ** 3,
            'M' => $number * 1024 ** 2,
            'K' => $number * 1024,
            default => $number,
        };
    }

    private function section(string $title): void
    {
        $this->newLine();
        $this->line("  <options=bold>{$title}</>");
    }

    private function ok(string $label, string $value): void
    {
        $this->components->twoColumnDetail($label, "<fg=green>{$value}</>");
    }

    private function note(string $label, string $value): void
    {
        $this->components->twoColumnDetail($label, $value);
    }

    private function warning(string $label, string $value, string $advice): void
    {
        $this->warnings++;
        $this->components->twoColumnDetail($label, "<fg=yellow>{$value}</>");
        $this->line("    <fg=yellow>Warning:</> {$advice}");
    }

    private function problem(string $label, string $value, string $advice): void
    {
        $this->problems++;
        $this->components->twoColumnDetail($label, "<fg=red;options=bold>{$value}</>");
        $this->line("    <fg=red>Problem:</> {$advice}");
    }
}
