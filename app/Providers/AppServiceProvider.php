<?php

namespace App\Providers;

use App\Auth\AdminHeaders;
use App\Auth\Headers;
use App\Auth\Jwt;
use App\Auth\ManagerHeaders;
use App\Auth\ManagerHeadersLoose;
use App\Auth\OrgHeaders;
use App\Auth\OrgMemberHeaders;
use App\Auth\OwnerHeaders;
use App\Auth\PublicToken;
use App\Auth\RsaKeys;
use App\Auth\SendHeaders;
use App\Config\Config;
use App\Config\ConfigException;
use App\Database\DatabaseUrl;
use App\Database\SqlStatements;
use App\Database\VaultwardenMigrator;
use App\Logging\LogLevel;
use App\Logging\LogOutputs;
use App\Mail\SendmailTransport;
use App\Mail\SmtpTransport;
use App\Mail\Transport as MailTransport;
use App\Notifications\Channel as NotificationsChannel;
use App\Notifications\SocketChannel;
use App\Parity\Reference;
use App\Support\Deferred;
use App\Support\Downloader;
use App\Support\StreamDownloader;
use App\Support\WebVault;
use App\Support\WebVaultImage;
use App\Templates\TemplateRenderer;
use Illuminate\Database\Connectors\ConnectionFactory;
use Illuminate\Database\DatabaseManager;
use Illuminate\Http\Request;
use Illuminate\Support\Env;
use Illuminate\Support\ServiceProvider;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        // Read from the raw environment: Laravel's env() would turn values like "null" or "(true)" into PHP values.
        $this->app->singleton(Config::class, fn (): Config => Config::load(
            static fn (string $key): ?string => Env::getRepository()->get($key),
            base_path(),
        ));

        // Loads (or creates) the key file once per request.
        $this->app->singleton(RsaKeys::class);

        // Request guards, resolved when a controller type-hints them, like Rocket's FromRequest.
        $this->app->bind(Headers::class, fn (): Headers => Headers::fromRequest(
            $this->app->make(Request::class),
            $this->app->make(Config::class),
            $this->app->make(Jwt::class),
        ));
        foreach ([OrgHeaders::class, AdminHeaders::class, ManagerHeaders::class, ManagerHeadersLoose::class, OwnerHeaders::class, OrgMemberHeaders::class] as $guard) {
            $this->app->bind($guard, fn (): OrgHeaders => $guard::fromRequest(
                $this->app->make(Request::class),
                $this->app->make(Config::class),
                $this->app->make(Jwt::class),
            ));
        }
        $this->app->bind(PublicToken::class, fn (): PublicToken => PublicToken::fromRequest(
            $this->app->make(Request::class),
            $this->app->make(Config::class),
            $this->app->make(Jwt::class),
        ));
        $this->app->bind(SendHeaders::class, fn (): SendHeaders => SendHeaders::fromRequest(
            $this->app->make(Request::class),
            $this->app->make(Jwt::class),
        ));

        $this->app->singleton(VaultwardenMigrator::class, fn (): VaultwardenMigrator => new VaultwardenMigrator(
            database_path('vaultwarden'),
        ));

        // mail::send_with_selected_transport
        $this->app->bind(MailTransport::class, fn (): MailTransport => $this->app->make(Config::class)->bool('use_sendmail')
            ? new SendmailTransport($this->app->make(Config::class))
            : new SmtpTransport($this->app->make(Config::class)));

        $this->app->singleton(Deferred::class);

        // One connection to the notifications daemon per request, opened by the first update.
        $this->app->scoped(NotificationsChannel::class, fn (): NotificationsChannel => SocketChannel::fromConfig(
            $this->app->make(Config::class),
            $this->app->make(RsaKeys::class),
        ));

        // The web vault that kennword:web-vault installs, as parity/reference.json pins it.
        $this->app->bind(Downloader::class, StreamDownloader::class);
        $this->app->bind(WebVaultImage::class, function (): WebVaultImage {
            $reference = Reference::load(base_path());

            return new WebVaultImage($reference->webVault, $reference->webVaultDigest, $this->app->make(Downloader::class));
        });

        $this->app->singleton(TemplateRenderer::class, function (): TemplateRenderer {
            $config = $this->app->make(Config::class);

            return new TemplateRenderer(
                builtinPath: resource_path('vaultwarden/templates'),
                overridePath: $config->path('templates_folder'),
                vaultwardenVersion: config()->string('vaultwarden.version'),
                webVaultVersion: WebVault::version($config),
                reload: $config->bool('reload_templates'),
            );
        });

        // The "vaultwarden" connection is configured by DATABASE_URL, like Vaultwarden's own.
        $this->app->afterResolving('db', function (DatabaseManager $databases): void {
            $databases->extend('vaultwarden', function (array $_, string $name) {
                $config = $this->app->make(Config::class);
                $connection = $this->app->make(ConnectionFactory::class)->make(DatabaseUrl::connection($config), $name);

                foreach (SqlStatements::split($config->string('database_conn_init')) as $statement) {
                    $connection->getPdo()->exec($statement);
                }

                return $connection;
            });
        });

        // LOG_LEVEL is Vaultwarden's setting and sets the level of every channel, like init_logging.
        // With an invalid configuration, which keeps Vaultwarden from starting, the channels keep
        // the levels of config/logging.php, so that the error can still be logged.
        $this->app->afterResolving('log', function (): void {
            try {
                $level = LogLevel::parse($this->app->make(Config::class)->string('log_level'));
            } catch (ConfigException) {
                return;
            }

            LogLevel::configure($this->app->make('config'), $level);
            if ($level !== null) {
                LogOutputs::configure($this->app->make('config'), $this->app->make(Config::class), $level);
            }
        });
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        // Spawned work runs after the response; terminating callbacks themselves stay registered.
        $this->app->terminating(fn () => $this->app->make(Deferred::class)->run());
    }
}
