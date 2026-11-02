<?php

namespace Tests\Feature\Config;

use App\Config\Config;
use App\Templates\TemplateRenderer;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Tests\Attributes\Parity;
use Tests\TestCase;

/**
 * The application's services follow Vaultwarden's settings.
 */
class AppConfigTest extends TestCase
{
    private string $base;

    protected function setUp(): void
    {
        parent::setUp();

        $this->base = sys_get_temp_dir().'/vw-app-'.bin2hex(random_bytes(6));
        mkdir($this->base.'/data', recursive: true);
    }

    protected function tearDown(): void
    {
        exec('rm -rf '.escapeshellarg($this->base));

        parent::tearDown();
    }

    #[Parity('config:DATABASE_URL')]
    #[Parity('config:DATABASE_CONN_INIT')]
    public function test_the_vaultwarden_connection_follows_database_url(): void
    {
        touch("{$this->base}/data/vault.db");
        $this->useConfig([
            'DATABASE_URL' => "sqlite://{$this->base}/data/vault.db",
            'DATABASE_CONN_INIT' => 'PRAGMA user_version = 7; PRAGMA cache_size = 123;',
        ]);

        $connection = DB::connection('vaultwarden');

        $this->assertSame('sqlite', $connection->getDriverName());
        $this->assertSame("{$this->base}/data/vault.db", $connection->getConfig('database'));
        $this->assertEquals((object) ['user_version' => 7], $connection->selectOne('PRAGMA user_version'));
        $this->assertEquals((object) ['cache_size' => 123], $connection->selectOne('PRAGMA cache_size'));
        $this->assertEquals((object) ['foreign_keys' => 1], $connection->selectOne('PRAGMA foreign_keys'));
    }

    #[Parity('config:TEMPLATES_FOLDER')]
    #[Parity('config:RELOAD_TEMPLATES')]
    public function test_templates_come_from_the_configured_folder(): void
    {
        mkdir("{$this->base}/custom");
        file_put_contents("{$this->base}/custom/404.hbs", 'first {{urlpath}}');
        $this->useConfig(['TEMPLATES_FOLDER' => "{$this->base}/custom", 'RELOAD_TEMPLATES' => 'true']);
        $renderer = $this->app->make(TemplateRenderer::class);

        $this->assertSame('first /x', $renderer->render('404', ['urlpath' => '/x']));

        file_put_contents("{$this->base}/custom/404.hbs", 'second {{urlpath}}');
        $this->assertSame('second /x', $renderer->render('404', ['urlpath' => '/x']));
    }

    #[Parity('config:LOG_LEVEL')]
    public function test_the_log_channels_follow_log_level(): void
    {
        $this->logTo("{$this->base}/laravel.log");
        $this->useConfig(['LOG_LEVEL' => 'WARN,vaultwarden::api::icons=debug']);

        Log::info('not logged');
        Log::warning('logged');

        $log = (string) file_get_contents("{$this->base}/laravel.log");
        $this->assertStringNotContainsString('not logged', $log);
        $this->assertStringContainsString('[kennword][WARN] logged', $log);
    }

    #[Parity('config:EXTENDED_LOGGING')]
    #[Parity('config:LOG_TIMESTAMP_FORMAT')]
    #[Parity('config:LOG_FILE')]
    public function test_log_lines_and_the_log_file(): void
    {
        $this->logTo("{$this->base}/laravel.log");
        $this->useConfig(['LOG_FILE' => 'data/vaultwarden.log', 'LOG_TIMESTAMP_FORMAT' => '%d.%m.%Y %H:%M:%S%.3f (%Z)']);

        Log::warning('careful');
        Log::notice('noted');

        $line = '\[\d{2}\.\d{2}\.\d{4} \d{2}:\d{2}:\d{2}\.\d{3} \(UTC\)\]\[kennword\]';
        $expected = "/^{$line}\[WARN\] careful\n{$line}\[INFO\] noted\n$/";
        $this->assertMatchesRegularExpression($expected, (string) file_get_contents("{$this->base}/laravel.log"));
        $this->assertMatchesRegularExpression($expected, (string) file_get_contents("{$this->base}/data/vaultwarden.log"));
    }

    #[Parity('config:EXTENDED_LOGGING')]
    #[Parity('config:USE_SYSLOG')]
    public function test_plain_lines_and_the_syslog(): void
    {
        $this->logTo("{$this->base}/laravel.log");
        $this->useConfig(['EXTENDED_LOGGING' => 'false', 'USE_SYSLOG' => 'true']);

        Log::error('broken');

        $this->assertSame("broken\n", file_get_contents("{$this->base}/laravel.log"));
        $this->assertSame(['single', 'vaultwarden_syslog'], config('logging.channels.vaultwarden.channels'));
        $this->assertSame(['ident' => 'vaultwarden', 'facility' => LOG_USER], config('logging.channels.vaultwarden_syslog.handler_with'));
    }

    #[Parity('config:LOG_LEVEL')]
    public function test_log_level_off_logs_nothing(): void
    {
        $this->logTo("{$this->base}/laravel.log");
        $this->useConfig(['LOG_LEVEL' => 'off']);

        Log::emergency('not logged');

        $this->assertFileDoesNotExist("{$this->base}/laravel.log");
    }

    public function test_an_invalid_configuration_is_logged_with_the_default_levels(): void
    {
        $this->logTo("{$this->base}/laravel.log");
        $this->changeVaultwardenEnvironment(['LOG_LEVEL' => 'verbose']);

        Log::debug('logged');

        $log = (string) file_get_contents("{$this->base}/laravel.log");
        $this->assertStringContainsString('.DEBUG: logged', $log);
        $this->assertStringNotContainsString('Unable to create configured logger', $log);
    }

    private function logTo(string $path): void
    {
        config(['logging.default' => 'single', 'logging.channels.single.path' => $path]);
    }

    /**
     * @param  array<string, string>  $env
     */
    private function useConfig(array $env): void
    {
        $this->app->instance(Config::class, Config::load(static fn (string $key): ?string => $env[$key] ?? null, $this->base));
    }
}
