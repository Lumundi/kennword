<?php

namespace App\Console\Commands;

use App\Auth\RsaKeys;
use App\Config\Config;
use App\Notifications\Server;
use App\Notifications\SocketChannel;
use App\Notifications\Subscriptions;
use Illuminate\Console\Command;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Http\Request;
use RuntimeException;
use Symfony\Component\HttpFoundation\Response;

class VaultwardenNotifications extends Command
{
    /**
     * @var string
     */
    protected $signature = 'kennword:notifications
        {--listen=127.0.0.1:3012 : Address and port for the WebSocket clients, which the web server proxies /notifications/ to}';

    /**
     * @var string
     */
    protected $description = 'Serve the live notifications (/notifications/hub and /notifications/anonymous-hub) over WebSocket';

    public function handle(Config $config, RsaKeys $keys, Kernel $kernel): int
    {
        if (! $config->bool('enable_websocket')) {
            $this->components->warn('WebSocket are disabled, realtime sync functionality will not work!');

            return self::FAILURE;
        }

        $subscriptions = new Subscriptions;
        app()->instance(Subscriptions::class, $subscriptions);

        $dispatch = static function (Request $request) use ($kernel): Response {
            // Settings may change through the admin panel while the daemon runs.
            app()->forgetInstance(Config::class);
            $response = $kernel->handle($request);
            $kernel->terminate($request, $response);

            return $response;
        };
        $server = new Server($subscriptions, $dispatch, $keys->notificationsKey(), public_path('index.php'));

        $channel = SocketChannel::address($config);
        try {
            $server->listen((string) $this->option('listen'), $channel);
        } catch (RuntimeException $exception) {
            $this->components->error($exception->getMessage());

            return self::FAILURE;
        }

        $this->trap(fn (): array => [SIGINT, SIGTERM], $server->stop(...));
        $this->components->info("Serving live notifications on {$server->address()}, receiving them at {$channel}.");
        $server->run();

        return self::SUCCESS;
    }
}
