<?php

namespace App\Database;

use App\Config\Config;
use App\Config\ConfigException;
use Pdo\Mysql;

/**
 * Turns Vaultwarden's DATABASE_URL into a Laravel connection that behaves like
 * Vaultwarden's own (src/db/mod.rs and Diesel's connection setup).
 */
final class DatabaseUrl
{
    /**
     * Query errors are logged; unlike Diesel's, Laravel's messages would
     * carry the bound values, such as tokens and two-factor secrets.
     */
    private const array MASK_BINDINGS = ['mask_bindings_in_exception_messages' => true];

    /**
     * DbConnType::from_url
     *
     * @return 'sqlite'|'mysql'|'postgresql'
     *
     * @throws ConfigException
     */
    public static function type(string $url, Config $config): string
    {
        if (strlen($url) > 6 && str_starts_with($url, 'mysql:')) {
            return 'mysql';
        }
        if (strlen($url) > 11 && (str_starts_with($url, 'postgresql:') || str_starts_with($url, 'postgres:'))) {
            return 'postgresql';
        }
        if (strlen($url) > 7 && str_starts_with($url, 'sqlite:')) {
            return 'sqlite';
        }

        // A bare path is accepted for compatibility, but only for an existing database file.
        if (file_exists($config->absolutePath($url))) {
            return 'sqlite';
        }

        throw new ConfigException(
            '`DATABASE_URL` does not match any known database scheme (mysql://, postgresql://, sqlite://) and no existing '
            ."SQLite database was found at '".self::withoutPassword($url)."'. If you intend to use SQLite, use an explicit `sqlite://` scheme in your "
            .'`DATABASE_URL`. Otherwise, check your DATABASE_URL for typos or quoting issues.'
        );
    }

    /**
     * The URL with the password of its user info masked: the message lands in
     * the log and in output that people share.
     */
    public static function withoutPassword(string $url): string
    {
        return (string) preg_replace('#^([^:/?\#]*://[^/?\#@:]*):[^/?\#]*@#', '$1:***@', $url);
    }

    /**
     * The file of a SQLite URL, relative paths resolved against the base path.
     */
    public static function sqlitePath(string $url, Config $config): string
    {
        return $config->absolutePath(str_starts_with($url, 'sqlite://') ? substr($url, strlen('sqlite://')) : $url);
    }

    /**
     * The Laravel connection configuration for DATABASE_URL.
     *
     * @return array<string, mixed>
     *
     * @throws ConfigException
     */
    public static function connection(Config $config): array
    {
        $url = $config->string('database_url');
        $customInit = $config->string('database_conn_init') !== '';

        return match (self::type($url, $config)) {
            'sqlite' => [
                'driver' => 'sqlite',
                'database' => self::sqlitePath($url, $config),
                'prefix' => '',
                ...self::MASK_BINDINGS,
                // Diesel enforces foreign keys on SQLite; only the migrations run without.
                'foreign_key_constraints' => true,
                // The default DATABASE_CONN_INIT; a custom one replaces it.
                'busy_timeout' => $customInit ? null : 5000,
                'synchronous' => $customInit ? null : 'normal',
                // Vaultwarden switches to WAL when it migrates; the mode is stored in the file.
                'journal_mode' => $config->bool('enable_db_wal') ? 'wal' : null,
            ],
            'mysql' => [
                ...self::server($url),
                'driver' => 'mysql',
                'charset' => 'utf8mb4',
                'collation' => null,
                'prefix' => '',
                ...self::MASK_BINDINGS,
                // Diesel runs every MySQL session in UTC.
                'timezone' => '+00:00',
                'options' => self::mysqlOptions($url),
            ],
            'postgresql' => [
                ...self::server($url),
                'driver' => 'pgsql',
                'charset' => 'utf8',
                'prefix' => '',
                ...self::MASK_BINDINGS,
                'search_path' => 'public',
                // Diesel runs every PostgreSQL session in UTC.
                'timezone' => 'UTC',
                ...array_intersect_key(self::query($url), array_flip(['sslmode', 'sslcert', 'sslkey', 'sslrootcert', 'application_name'])),
            ],
        };
    }

    /**
     * Host, port, database and credentials of a server URL.
     *
     * @return array{host: string|null, port: int|null, database: string, username: string|null, password: string|null, unix_socket?: string}
     */
    private static function server(string $url): array
    {
        $parts = self::parse($url);
        $query = self::query($url);

        $server = [
            'host' => $query['host'] ?? (isset($parts['host']) ? rawurldecode($parts['host']) : null),
            'port' => isset($query['port']) ? (int) $query['port'] : ($parts['port'] ?? null),
            'database' => $query['dbname'] ?? rawurldecode(ltrim($parts['path'] ?? '', '/')),
            'username' => $query['user'] ?? (isset($parts['user']) ? rawurldecode($parts['user']) : null),
            'password' => $query['password'] ?? (isset($parts['pass']) ? rawurldecode($parts['pass']) : null),
        ];
        if (isset($query['unix_socket'])) {
            $server['unix_socket'] = $query['unix_socket'];
        }

        return $server;
    }

    /**
     * TLS settings of a Diesel MySQL URL (ssl_mode, ssl_ca, ssl_cert, ssl_key).
     *
     * @return array<int, string|bool>
     */
    private static function mysqlOptions(string $url): array
    {
        $query = self::query($url);
        $options = [];

        foreach (['ssl_ca' => Mysql::ATTR_SSL_CA, 'ssl_cert' => Mysql::ATTR_SSL_CERT, 'ssl_key' => Mysql::ATTR_SSL_KEY] as $key => $attribute) {
            if (isset($query[$key])) {
                $options[$attribute] = $query[$key];
            }
        }
        if (isset($query['ssl_mode'])) {
            $options[Mysql::ATTR_SSL_VERIFY_SERVER_CERT] = in_array(strtolower($query['ssl_mode']), ['verify_ca', 'verify_identity'], true);
        }

        return $options;
    }

    /**
     * @return array{scheme?: string, host?: string, port?: int<0, 65535>, user?: string, pass?: string, path?: string, query?: string, fragment?: string}
     */
    private static function parse(string $url): array
    {
        // parse_url() needs a host, which socket URLs like mysql://user@/db?unix_socket=... leave out.
        return parse_url((string) preg_replace('#^([a-z]+://(?:[^@/]*@)?)(/)#', '$1localhost$2', $url)) ?: [];
    }

    /**
     * @return array<string, string>
     */
    private static function query(string $url): array
    {
        $query = self::parse($url)['query'] ?? null;
        if ($query === null) {
            return [];
        }

        parse_str($query, $parameters);

        $strings = [];
        foreach ($parameters as $key => $value) {
            if (is_string($value)) {
                $strings[(string) $key] = $value;
            }
        }

        return $strings;
    }
}
