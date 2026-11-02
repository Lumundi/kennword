<?php

namespace Tests\Feature\Notifications;

use App\Auth\AuthMethod;
use App\Auth\Jwt;
use App\Auth\LoginClaims;
use App\Models\Device;
use App\Models\User;
use App\Notifications\Channel;
use App\Notifications\Notify;
use App\Notifications\Server;
use App\Notifications\Subscriptions;
use App\Notifications\WebSocketConnection;
use App\Support\Random;
use RuntimeException;
use Tests\Attributes\Parity;
use Tests\Concerns\UsesVaultwardenDatabase;
use Tests\Support\MessagePackDecoder;
use Tests\Support\WebSocketClient;
use Tests\TestCase;

/**
 * php artisan kennword:notifications, started for each test, with
 * requests of this process handing it their updates.
 */
class DaemonTest extends TestCase
{
    use UsesVaultwardenDatabase;

    /**
     * @var resource|null
     */
    private mixed $daemon = null;

    private string $url = '';

    private User $user;

    private Device $device;

    private string $token;

    protected function vaultwardenEnvironment(): array
    {
        return ['PASSWORD_ITERATIONS' => '100000'];
    }

    protected function setUp(): void
    {
        parent::setUp();
        $this->useDatabase('sqlite');
        $socket = "unix://{$this->dataFolder}/n.sock";
        config(['vaultwarden.notifications_socket' => $socket]);

        $process = proc_open([PHP_BINARY, base_path('artisan'), 'kennword:notifications', '--listen=127.0.0.1:0', '--no-ansi'],
            [1 => ['pipe', 'w'], 2 => ['file', "{$this->dataFolder}/daemon.log", 'w']], $pipes, base_path(),
            [...getenv(), 'DATA_FOLDER' => $this->dataFolder, 'NOTIFICATIONS_SOCKET' => $socket, 'LOG_LEVEL' => 'debug']);
        if ($process === false) {
            throw new RuntimeException('Cannot start the notifications daemon.');
        }
        $this->daemon = $process;
        // The start line names the port; Laravel's components print an empty line first.
        $line = '';
        while (preg_match('/on (127\.0\.0\.1:\d+)/', $line, $match) !== 1 && ($next = fgets($pipes[1])) !== false) {
            $line = $next;
        }
        if (! isset($match[1])) {
            throw new RuntimeException("The notifications daemon did not start: {$line}".file_get_contents("{$this->dataFolder}/daemon.log"));
        }
        $this->url = "http://{$match[1]}";

        $this->user = User::new('daemon@example.com');
        $this->user->save();
        $this->device = Device::new(Random::uuid(), $this->user->uuid, 'cli', 25);
        $this->device->save();
        $jwt = $this->app->make(Jwt::class);
        $this->token = LoginClaims::default($this->device, $this->user, AuthMethod::Password, 'cli', $jwt)->token($jwt);
    }

    protected function tearDown(): void
    {
        if ($this->daemon !== null) {
            proc_terminate($this->daemon);
            proc_close($this->daemon);
        }

        parent::tearDown();
    }

    #[Parity('route:GET /notifications/hub')]
    #[Parity('config:ENABLE_WEBSOCKET')]
    public function test_updates_reach_the_connections_of_the_user(): void
    {
        $hub = WebSocketClient::connect($this->url, "/notifications/hub?access_token={$this->token}");
        $this->assertSame(101, $hub->status);
        $this->assertSame(['upgrade', 'websocket', '13'], [$hub->headers['connection'] ?? null, $hub->headers['upgrade'] ?? null, $hub->headers['sec-websocket-version'] ?? null]);
        // Like tokio's interval, the first ping comes at once.
        $this->assertSame([WebSocketClient::PING, "\x02\x91\x06"], $hub->receive());
        $hub->handshake();
        $this->assertSame([WebSocketClient::BINARY, "{}\x1e"], $hub->receive());

        // The token may come in the Authorization header too; other users hear nothing.
        $byHeader = WebSocketClient::connect($this->url, '/notifications/hub', ['Authorization' => "Bearer {$this->token}"]);
        $this->assertSame(101, $byHeader->status);
        $other = User::new('other@example.com');
        $other->save();
        $jwt = $this->app->make(Jwt::class);
        $otherHub = WebSocketClient::connect($this->url, '/notifications/hub?access_token='
            .LoginClaims::default(Device::new(Random::uuid(), $other->uuid, 'cli', 25), $other, AuthMethod::Password, 'cli', $jwt)->token($jwt));
        $this->assertSame(101, $otherHub->status);

        $id = $this->postJson('/api/folders', ['name' => '2.folder'], ['Authorization' => "Bearer {$this->token}"])->assertStatus(200)->json('id');

        foreach ([$hub, $byHeader] as $connection) {
            $messages = $connection->collect(timeout: 2.0, until: 1);
            $this->assertCount(1, $messages);
            $invocation = $this->arrayOf(json_decode((string) json_encode(MessagePackDecoder::signalR($messages[0])[0]), true));
            $this->assertSame([1, [], null, 'ReceiveMessage'], array_slice($invocation, 0, 4));
            $update = $this->arrayOf($this->arrayOf($invocation[4])[0]);
            $date = $this->arrayOf($update['Payload'])['RevisionDate'];
            $this->assertIsString($date);
            $this->assertMatchesRegularExpression('/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{9}Z$/', $date);
            $this->assertSame(['ContextId' => $this->device->uuid, 'Type' => 7, 'Payload' => ['Id' => $id, 'UserId' => $this->user->uuid,
                'RevisionDate' => $date]], $update);
        }
        $this->assertSame([], $otherHub->collect(timeout: 0.3));
    }

    public function test_pings_are_answered_and_other_messages_echoed(): void
    {
        $hub = WebSocketClient::connect($this->url, "/notifications/hub?access_token={$this->token}");
        $hub->receive();

        $hub->send(WebSocketClient::PING, 'are you there');
        $this->assertSame([WebSocketClient::PONG, 'are you there'], $hub->receive());
        $hub->send(WebSocketClient::BINARY, 'echo');
        $this->assertSame([WebSocketClient::BINARY, 'echo'], $hub->receive());
        // Text that is not the handshake gets no answer.
        $hub->send(WebSocketClient::TEXT, '{"protocol":"json","version":1}'."\x1e");
        $hub->send(WebSocketClient::BINARY, 'next');
        $this->assertSame([WebSocketClient::BINARY, 'next'], $hub->receive());

        // A close ends the connection without a close frame, and so does a protocol error.
        $hub->send(WebSocketClient::CLOSE, "\x03\xe8");
        $this->assertNull($hub->receive(2.0));
        $this->assertTrue($hub->closedWithin(0.1));

        $broken = WebSocketClient::connect($this->url, "/notifications/hub?access_token={$this->token}");
        $broken->receive();
        $broken->send(WebSocketClient::BINARY, 'unmasked', masked: false);
        $this->assertTrue($broken->closedWithin(2.0));
    }

    public function test_requests_the_hub_does_not_accept(): void
    {
        // Rocket forwards what is no upgrade to the web vault, which has no such file.
        $plain = WebSocketClient::connect($this->url, '/notifications/hub', ['Connection' => null, 'Upgrade' => null]);
        $this->assertSame(404, $plain->status);
        $this->assertStringContainsString('Page not found!', $plain->body);

        $noToken = WebSocketClient::connect($this->url, '/notifications/hub');
        $this->assertSame(401, $noToken->status);
        $this->assertSame('Invalid claim', $this->arrayOf(json_decode($noToken->body, true))['message'] ?? null);
        // Upgrades keep Rocket's headers out of the way, errors too.
        $this->assertArrayNotHasKey('x-frame-options', $noToken->headers);
        $this->assertArrayNotHasKey('cache-control', $noToken->headers);

        $badToken = WebSocketClient::connect($this->url, '/notifications/hub?access_token=nope');
        $this->assertSame(401, $badToken->status);
        $this->assertSame('Invalid token', $this->arrayOf(json_decode($badToken->body, true))['message'] ?? null);

        $this->assertSame(404, WebSocketClient::connect($this->url, '/notifications/anonymous-hub')->status);
        $this->assertSame(404, WebSocketClient::connect($this->url, '/api/sync')->status);
    }

    #[Parity('route:GET /notifications/anonymous-hub')]
    public function test_the_anonymous_hub_waits_for_the_answer_to_a_login_request(): void
    {
        $requestId = Random::uuid();
        $waiting = WebSocketClient::connect($this->url, "/notifications/anonymous-hub?Token={$requestId}");
        $this->assertSame(101, $waiting->status);
        $waiting->receive();
        $again = WebSocketClient::connect($this->url, "/notifications/anonymous-hub?token={$requestId}");
        $again->receive();

        $this->app->make(Notify::class)->sendAnonymousAuthResponse($this->user->uuid, $requestId);

        foreach ([$waiting, $again] as $connection) {
            $messages = $connection->collect(timeout: 2.0, until: 1);
            $this->assertCount(1, $messages);
            $this->assertEquals([1, (object) [], null, 'AuthRequestResponseRecieved', [(object) ['Type' => 16,
                'Payload' => (object) ['Id' => $requestId, 'UserId' => $this->user->uuid], 'UserId' => $this->user->uuid]]],
                MessagePackDecoder::signalR($messages[0])[0]);
        }
    }

    public function test_an_address_holds_a_limited_number_of_anonymous_connections(): void
    {
        $connections = [];
        for ($i = 0; $i < Subscriptions::MAX_ANONYMOUS_CONNECTIONS_PER_IP; $i++) {
            $connections[] = $connection = WebSocketClient::connect($this->url, "/notifications/anonymous-hub?token={$i}");
            $this->assertSame(101, $connection->status);
        }
        $refused = WebSocketClient::connect($this->url, '/notifications/anonymous-hub?token=more');
        $this->assertSame(429, $refused->status);
        $this->assertSame('Too many connections', $this->arrayOf(json_decode($refused->body, true))['message'] ?? null);

        // A closed connection frees its slot.
        $connections[0]->close();
        usleep(200_000);
        $this->assertSame(101, WebSocketClient::connect($this->url, '/notifications/anonymous-hub?token=more')->status);
    }

    /**
     * Headers with underscores are dropped, as web servers do before PHP:
     * otherwise X_Real_IP would pass for the IP header of a trusted proxy.
     */
    public function test_headers_with_underscores_do_not_count(): void
    {
        $connections = [];
        for ($i = 0; $i < Subscriptions::MAX_ANONYMOUS_CONNECTIONS_PER_IP; $i++) {
            $connections[] = $connection = WebSocketClient::connect($this->url, "/notifications/anonymous-hub?token={$i}", ['X_Real_IP' => "203.0.113.{$i}"]);
            $this->assertSame(101, $connection->status);
        }
        $this->assertSame(429, WebSocketClient::connect($this->url, '/notifications/anonymous-hub?token=more', ['X_Real_IP' => '203.0.113.200'])->status);

        // From the trusted proxy (a local address), X-Real-IP names another client.
        $this->assertSame(101, WebSocketClient::connect($this->url, '/notifications/anonymous-hub?token=more', ['X-Real-IP' => '203.0.113.201'])->status);
    }

    public function test_frames_and_messages_past_the_limit_end_the_connection(): void
    {
        $hub = WebSocketClient::connect($this->url, "/notifications/hub?access_token={$this->token}");
        $hub->receive();

        // The longest message that is allowed is still echoed.
        $longest = str_repeat('x', WebSocketConnection::MAX_MESSAGE_SIZE);
        $hub->send(WebSocketClient::BINARY, $longest);
        $this->assertSame([WebSocketClient::BINARY, $longest], $hub->receive());

        $frame = WebSocketClient::connect($this->url, '/notifications/anonymous-hub?token=frame');
        $frame->receive();
        $frame->send(WebSocketClient::BINARY, "{$longest}x");
        $this->assertTrue($frame->closedWithin(2.0));

        $message = WebSocketClient::connect($this->url, '/notifications/anonymous-hub?token=message');
        $message->receive();
        $message->send(WebSocketClient::BINARY, str_repeat('x', intdiv(WebSocketConnection::MAX_MESSAGE_SIZE, 2)), fin: false);
        $message->send(0x0, str_repeat('x', intdiv(WebSocketConnection::MAX_MESSAGE_SIZE, 2)), fin: false);
        $message->send(0x0, 'x');
        $this->assertTrue($message->closedWithin(2.0));

        $hub->send(WebSocketClient::PING, 'still there');
        $this->assertSame([WebSocketClient::PONG, 'still there'], $hub->receive());
    }

    public function test_requests_past_the_limits_are_refused(): void
    {
        $hub = WebSocketClient::connect($this->url, "/notifications/hub?access_token={$this->token}");
        $hub->receive();

        $body = WebSocketClient::connect($this->url, '/notifications/anonymous-hub?token=body', ['Content-Length' => (string) (Server::MAX_REQUEST_BODY + 1)]);
        $this->assertSame([413, 'Payload Too Large'], [$body->status, $body->body]);
        $head = WebSocketClient::connect($this->url, '/notifications/anonymous-hub?token=head', ['X-Padding' => str_repeat('x', Server::MAX_REQUEST_HEAD)]);
        $this->assertSame([431, 'Request Header Fields Too Large'], [$head->status, $head->body]);

        $hub->send(WebSocketClient::PING, 'still there');
        $this->assertSame([WebSocketClient::PONG, 'still there'], $hub->receive());
        $this->assertSame(101, WebSocketClient::connect($this->url, '/notifications/anonymous-hub?token=next')->status);
    }

    public function test_requests_that_never_finish_make_way_for_new_ones(): void
    {
        $hub = WebSocketClient::connect($this->url, "/notifications/hub?access_token={$this->token}");
        $hub->receive();

        $address = 'tcp://'.substr($this->url, strlen('http://'));
        $unfinished = [];
        for ($i = 0; $i <= Server::MAX_PENDING_REQUESTS; $i++) {
            $socket = stream_socket_client($address, $errno, $error, 5);
            $this->assertNotFalse($socket, "Cannot connect to the daemon: {$error}");
            fwrite($socket, "GET /notifications/hub HTTP/1.1\r\nHost: localhost\r\n");
            $unfinished[] = $socket;
        }

        // The oldest was dropped for the last; a request that finishes still gets through, in place of the next.
        $this->assertTrue($this->closedWithin($unfinished[0], 2.0));
        $this->assertSame(101, WebSocketClient::connect($this->url, '/notifications/anonymous-hub?token=next')->status);
        $this->assertTrue($this->closedWithin($unfinished[1], 2.0));
        $this->assertFalse($this->closedWithin($unfinished[2], 0.2));

        $hub->send(WebSocketClient::PING, 'still there');
        $this->assertSame([WebSocketClient::PONG, 'still there'], $hub->receive());
    }

    public function test_clients_that_do_not_read_are_dropped(): void
    {
        // This one reads nothing after the upgrade.
        $slow = WebSocketClient::connect($this->url, "/notifications/hub?access_token={$this->token}");
        $requestId = Random::uuid();
        $waiting = WebSocketClient::connect($this->url, "/notifications/anonymous-hub?token={$requestId}");
        $waiting->receive();

        // More than the system buffers for a connection, and more than the daemon keeps for it.
        $channel = $this->app->make(Channel::class);
        $update = str_repeat('x', 500_000);
        for ($i = 0; $i < 64; $i++) {
            $channel->toUsers([$this->user->uuid], $update);
        }

        $this->app->make(Notify::class)->sendAnonymousAuthResponse($this->user->uuid, $requestId);
        $this->assertCount(1, $waiting->collect(timeout: 5.0, until: 1));

        $received = 0;
        while (($frame = $slow->receive(2.0)) !== null) {
            $received += strlen($frame[1]);
        }
        $this->assertTrue($slow->closedWithin(0.1));
        $this->assertLessThan(64 * strlen($update), $received);
    }

    public function test_the_daemon_does_not_start_with_websockets_disabled(): void
    {
        $this->changeVaultwardenEnvironment(['ENABLE_WEBSOCKET' => 'false']);

        $this->command('kennword:notifications', ['--listen' => '127.0.0.1:0'])
            ->expectsOutputToContain('WebSocket are disabled, realtime sync functionality will not work!')
            ->assertExitCode(1);
    }

    /**
     * Whether the daemon ended a plain connection within the time.
     *
     * @param  resource  $socket
     */
    private function closedWithin(mixed $socket, float $timeout): bool
    {
        $deadline = microtime(true) + $timeout;
        while (($left = $deadline - microtime(true)) > 0) {
            $read = [$socket];
            $write = $except = null;
            if (@stream_select($read, $write, $except, (int) $left, (int) (fmod($left, 1.0) * 1_000_000)) > 0
                && (string) @fread($socket, 65_536) === '' && feof($socket)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return array<mixed>
     */
    private function arrayOf(mixed $value): array
    {
        $this->assertIsArray($value);

        return $value;
    }
}
