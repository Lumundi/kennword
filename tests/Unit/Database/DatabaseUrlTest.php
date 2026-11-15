<?php

namespace Tests\Unit\Database;

use App\Config\Config;
use App\Config\ConfigException;
use App\Database\DatabaseUrl;
use Illuminate\Container\Container;
use Illuminate\Database\Connectors\ConnectionFactory;
use Illuminate\Database\QueryException;
use Pdo\Mysql;
use PHPUnit\Framework\TestCase;
use Tests\Attributes\Parity;

#[Parity('config:DATABASE_URL')]
class DatabaseUrlTest extends TestCase
{
    private string $base;

    protected function setUp(): void
    {
        $this->base = sys_get_temp_dir().'/vw-dburl-'.bin2hex(random_bytes(6));
        mkdir($this->base.'/data', recursive: true);
    }

    protected function tearDown(): void
    {
        exec('rm -rf '.escapeshellarg($this->base));
    }

    #[Parity('config:ENABLE_DB_WAL')]
    #[Parity('config:DATABASE_CONN_INIT')]
    public function test_sqlite_behaves_like_vaultwarden(): void
    {
        $this->assertSame([
            'driver' => 'sqlite',
            'database' => "{$this->base}/data/db.sqlite3",
            'prefix' => '',
            'mask_bindings_in_exception_messages' => true,
            'foreign_key_constraints' => true,
            'busy_timeout' => 5000,
            'synchronous' => 'normal',
            'journal_mode' => 'wal',
        ], DatabaseUrl::connection($this->config()));

        $custom = DatabaseUrl::connection($this->config(['DATABASE_URL' => 'sqlite:///var/lib/vw.db', 'DATABASE_CONN_INIT' => 'PRAGMA cache_size = 100;', 'ENABLE_DB_WAL' => 'false']));
        $this->assertSame('/var/lib/vw.db', $custom['database']);
        $this->assertNull($custom['busy_timeout']);
        $this->assertNull($custom['synchronous']);
        $this->assertNull($custom['journal_mode']);
    }

    public function test_a_bare_path_must_be_an_existing_sqlite_file(): void
    {
        touch("{$this->base}/data/existing.db");
        $this->assertSame('sqlite', DatabaseUrl::type('data/existing.db', $this->config()));

        $this->expectException(ConfigException::class);
        DatabaseUrl::type('data/missing.db', $this->config());
    }

    public function test_an_unknown_scheme_does_not_show_the_password(): void
    {
        try {
            DatabaseUrl::type('mysq://dbuser:S3cr3t:Pass@db.example.com/vw', $this->config());
            $this->fail('An unknown scheme is refused.');
        } catch (ConfigException $exception) {
            $this->assertStringContainsString("found at 'mysq://dbuser:***@db.example.com/vw'", $exception->getMessage());
            $this->assertStringNotContainsString('S3cr3t', $exception->getMessage());
        }
        $this->assertSame('data/missing.db', DatabaseUrl::withoutPassword('data/missing.db'));
        $this->assertSame('mysql://user@host/db', DatabaseUrl::withoutPassword('mysql://user@host/db'));
    }

    public function test_mysql_url(): void
    {
        $connection = DatabaseUrl::connection($this->config([
            'DATABASE_URL' => 'mysql://vault%40user:p%40ss%3Aword@db.example:3307/vault?ssl_mode=VERIFY_IDENTITY&ssl_ca=/etc/ca.pem',
        ]));

        $this->assertSame('mysql', $connection['driver']);
        $this->assertSame('db.example', $connection['host']);
        $this->assertSame(3307, $connection['port']);
        $this->assertSame('vault', $connection['database']);
        $this->assertSame('vault@user', $connection['username']);
        $this->assertSame('p@ss:word', $connection['password']);
        $this->assertSame('+00:00', $connection['timezone']);
        $this->assertSame([Mysql::ATTR_SSL_CA => '/etc/ca.pem', Mysql::ATTR_SSL_VERIFY_SERVER_CERT => true], $connection['options']);
        $this->assertTrue($connection['mask_bindings_in_exception_messages']);
    }

    public function test_mysql_socket_url(): void
    {
        $connection = DatabaseUrl::connection($this->config(['DATABASE_URL' => 'mysql://vault@/vault?unix_socket=/run/mysqld/mysqld.sock']));

        $this->assertSame('/run/mysqld/mysqld.sock', $connection['unix_socket']);
        $this->assertSame('vault', $connection['database']);
        $this->assertSame('vault', $connection['username']);
    }

    public function test_postgresql_url(): void
    {
        foreach (['postgresql', 'postgres'] as $scheme) {
            $connection = DatabaseUrl::connection($this->config(['DATABASE_URL' => "{$scheme}://vault:secret@pg.example/vaultwarden?sslmode=require"]));

            $this->assertSame('pgsql', $connection['driver']);
            $this->assertSame('pg.example', $connection['host']);
            $this->assertNull($connection['port']);
            $this->assertSame('vaultwarden', $connection['database']);
            $this->assertSame('require', $connection['sslmode']);
            $this->assertSame('UTC', $connection['timezone']);
            $this->assertTrue($connection['mask_bindings_in_exception_messages']);
        }
    }

    /**
     * Query errors are logged, so their messages must not carry the bound
     * values: tokens, two-factor secrets and password hashes.
     */
    public function test_query_errors_do_not_show_the_bound_values(): void
    {
        touch("{$this->base}/data/errors.db");
        $connection = new ConnectionFactory(new Container)->make(DatabaseUrl::connection($this->config(['DATABASE_URL' => "sqlite://{$this->base}/data/errors.db"])), 'vaultwarden');
        $connection->statement('CREATE TABLE devices (refresh_token TEXT UNIQUE)');
        $connection->insert('INSERT INTO devices VALUES (?)', ['secret-refresh-token']);

        try {
            $connection->insert('INSERT INTO devices VALUES (?)', ['secret-refresh-token']);
            $this->fail('The insert should fail.');
        } catch (QueryException $error) {
            $this->assertStringContainsString('INSERT INTO devices VALUES (?)', $error->getMessage());
            $this->assertStringNotContainsString('secret-refresh-token', $error->getMessage());
        }
    }

    /**
     * @param  array<string, string>  $env
     */
    private function config(array $env = []): Config
    {
        return Config::load(static fn (string $key): ?string => $env[$key] ?? null, $this->base, validate: false);
    }
}
