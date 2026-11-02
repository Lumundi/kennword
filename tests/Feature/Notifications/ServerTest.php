<?php

namespace Tests\Feature\Notifications;

use App\Notifications\Server;
use App\Notifications\SocketChannel;
use App\Notifications\Subscriptions;
use App\Notifications\WebSocketAccept;
use Illuminate\Http\Request;
use RuntimeException;
use Symfony\Component\HttpFoundation\Response;
use Tests\TestCase;

/**
 * The notifications daemon in this process, its hub accepting every request
 * for one user, so that its limits can be tried with small sizes.
 */
class ServerTest extends TestCase
{
    private const string KEY = 'channel key';

    private Server $server;

    /**
     * @var list<resource>
     */
    private array $sockets = [];

    protected function setUp(): void
    {
        parent::setUp();
        $this->server = new Server(new Subscriptions, static fn (Request $request): Response => new WebSocketAccept('key', '127.0.0.1', userId: 'user'),
            self::KEY, public_path('index.php'), maxBuffered: 100_000);
        $this->server->listen('127.0.0.1:0', "unix://{$this->dataFolder}/n.sock");
    }

    protected function tearDown(): void
    {
        foreach ($this->sockets as $socket) {
            @fclose($socket);
        }

        parent::tearDown();
    }

    public function test_past_the_budget_the_connections_holding_the_most_are_dropped(): void
    {
        [$small, $large, $last] = [$this->hub(), $this->hub(), $this->hub()];

        // 10 kB of a frame, then 60 kB of a message, then 35 kB more: the large one goes.
        fwrite($small, substr(self::frame(str_repeat('s', 30_000)), 0, 10_008));
        fwrite($large, self::frame(str_repeat('l', 30_000), fin: false).substr(self::frame(str_repeat('l', 30_000), opcode: 0x0), 0, 30_000));
        $this->pump();
        fwrite($last, self::frame(str_repeat('t', 20_000), fin: false).substr(self::frame(str_repeat('t', 20_000), opcode: 0x0), 0, 15_000));
        $this->pump();

        $this->assertTrue($this->closed($large));
        $this->assertFalse($this->closed($last));

        // The others are served as before.
        fwrite($small, substr(self::frame(str_repeat('s', 30_000)), 10_008));
        $this->pump();
        $this->assertStringEndsWith("\x82\x7e\x75\x30".str_repeat('s', 30_000), $this->read($small));
    }

    public function test_a_query_with_more_fields_than_max_input_vars_is_served(): void
    {
        // parse_str() warns past max_input_vars, which ended the daemon for everybody.
        $socket = $this->connect("tcp://{$this->server->address()}");
        fwrite($socket, 'GET /notifications/hub?'.str_repeat('a&', ((int) ini_get('max_input_vars')) + 1)."access_token=t HTTP/1.1\r\nHost: localhost\r\n\r\n");
        $this->pump();

        $this->assertStringStartsWith('HTTP/1.1 101 ', $this->read($socket));
        $this->hub();
    }

    public function test_the_channel_takes_only_signed_lines(): void
    {
        $hub = $this->hub();
        $this->read($hub);
        [$first, $second] = [$this->connect($this->channelAddress()), $this->connect($this->channelAddress())];

        // A line that is not signed with the key ends that connection; the others still deliver.
        fwrite($first, "unsigned\n".SocketChannel::encode(['users' => ['user'], 'message' => base64_encode('lost')], self::KEY));
        fwrite($second, SocketChannel::encode(['users' => ['user'], 'message' => base64_encode('delivered')], self::KEY));
        $this->pump();

        $this->assertTrue($this->closed($first));
        $this->assertSame("\x82\x09delivered", $this->read($hub));
    }

    /**
     * Requests send a signed line as soon as they connect, so connections that
     * send nothing cannot fill the channel and keep requests out.
     */
    public function test_silent_connections_make_way_for_requests(): void
    {
        $hub = $this->hub();
        $this->read($hub);

        $silent = [];
        for ($i = 0; $i < Server::MAX_CHANNEL_CLIENTS; $i++) {
            $silent[] = $this->connect($this->channelAddress());
            $this->pump(1);
        }
        $request = $this->connect($this->channelAddress());
        fwrite($request, SocketChannel::encode(['users' => ['user'], 'message' => base64_encode('delivered')], self::KEY));
        $this->pump();

        $this->assertSame("\x82\x09delivered", $this->read($hub));
        $this->assertTrue($this->closed($silent[0]));
        $this->assertFalse($this->closed($silent[1]));

        // Once every connection has sent a valid line, a new one is refused.
        foreach (array_slice($silent, 1) as $socket) {
            fwrite($socket, SocketChannel::encode(['users' => ['user'], 'message' => base64_encode('x')], self::KEY));
        }
        $this->pump();
        $this->read($hub);
        $refused = $this->connect($this->channelAddress());
        $this->pump();
        $this->assertTrue($this->closed($refused));
        $this->assertFalse($this->closed($request));
    }

    public function test_a_connection_that_sends_no_signed_line_in_time_is_closed(): void
    {
        $server = new Server(new Subscriptions, static fn (Request $request): Response => new WebSocketAccept('key', '127.0.0.1', userId: 'user'),
            self::KEY, public_path('index.php'), channelAuthTimeout: 0.1);
        $server->listen('127.0.0.1:0', "unix://{$this->dataFolder}/quick.sock");
        [$silent, $request] = [$this->connect("unix://{$this->dataFolder}/quick.sock"), $this->connect("unix://{$this->dataFolder}/quick.sock")];
        fwrite($request, SocketChannel::encode(['users' => ['user'], 'message' => base64_encode('x')], self::KEY));

        $until = microtime(true) + 0.5;
        while (microtime(true) < $until) {
            $server->runOnce(0.01);
        }

        $this->assertTrue($this->closed($silent));
        $this->assertFalse($this->closed($request));
    }

    /**
     * Lines carry their time and a nonce: a line sent again, out of date or
     * without them is refused, so that a captured one cannot be replayed.
     */
    public function test_lines_sent_again_or_out_of_date_are_refused(): void
    {
        $hub = $this->hub();
        $this->read($hub);

        $line = SocketChannel::encode(['users' => ['user'], 'message' => base64_encode('once')], self::KEY);
        $first = $this->connect($this->channelAddress());
        fwrite($first, $line);
        $this->pump();
        $this->assertSame("\x82\x04once", $this->read($hub));

        $refused = [
            'again' => $line,
            'old' => self::sign(['users' => ['user'], 'message' => base64_encode('old'), 'time' => time() - 120, 'nonce' => bin2hex(random_bytes(16))]),
            'future' => self::sign(['users' => ['user'], 'message' => base64_encode('future'), 'time' => time() + 120, 'nonce' => bin2hex(random_bytes(16))]),
            'without' => self::sign(['users' => ['user'], 'message' => base64_encode('without')]),
        ];
        foreach ($refused as $name => $refusedLine) {
            $socket = $this->connect($this->channelAddress());
            fwrite($socket, $refusedLine);
            $this->pump();
            $this->assertTrue($this->closed($socket), "The line {$name} should be refused.");
        }
        $this->assertSame('', $this->read($hub));
    }

    public function test_the_socket_is_open_to_its_owner_and_group_only(): void
    {
        clearstatcache();

        $this->assertSame(0660, fileperms("{$this->dataFolder}/n.sock") & 0777);
    }

    public function test_over_tcp_the_channel_does_not_listen_where_anyone_can_reach_it(): void
    {
        foreach (['tcp://127.0.0.1:3013', 'tcp://[::1]:3013', 'tcp://localhost:3013', 'tcp://10.0.0.5:3013', 'tcp://192.168.1.2:3013', 'tcp://[fd00::5]:3013'] as $address) {
            Server::checkChannelHost($address);
        }

        foreach (['tcp://0.0.0.0:3013', 'tcp://[::]:3013', 'tcp://93.184.215.14:3013', 'tcp://[2001:4860:4860::8888]:3013', 'tcp://vault.example.com:3013'] as $address) {
            try {
                Server::checkChannelHost($address);
                $this->fail("{$address} should be refused.");
            } catch (RuntimeException $refused) {
                $this->assertStringContainsString('must not listen on', $refused->getMessage());
            }
        }

        // Refused before the daemon listens for clients.
        $server = new Server(new Subscriptions, static fn (Request $request): Response => new WebSocketAccept('key', '127.0.0.1', userId: 'user'),
            self::KEY, public_path('index.php'));
        $this->expectException(RuntimeException::class);
        $server->listen('127.0.0.1:0', 'tcp://0.0.0.0:0');
    }

    /**
     * A connection to the hub, upgraded and with the first ping read.
     *
     * @return resource
     */
    private function hub(): mixed
    {
        $socket = $this->connect("tcp://{$this->server->address()}");
        fwrite($socket, "GET /notifications/hub HTTP/1.1\r\nHost: localhost\r\n\r\n");
        $this->pump();
        $this->assertStringStartsWith('HTTP/1.1 101 ', $this->read($socket));

        return $socket;
    }

    /**
     * @return resource
     */
    private function connect(string $address): mixed
    {
        $socket = stream_socket_client($address, $errno, $error, 1);
        $this->assertNotFalse($socket, "Cannot connect to {$address}: {$error}");
        stream_set_blocking($socket, false);
        $this->sockets[] = $socket;

        return $socket;
    }

    /**
     * Let the server serve what came in, a connection to accept or something to read in each round.
     */
    private function pump(int $rounds = 20): void
    {
        for ($i = 0; $i < $rounds; $i++) {
            $this->server->runOnce(0.001);
        }
    }

    /**
     * @param  resource  $socket
     */
    private function read(mixed $socket): string
    {
        $data = '';
        while (($chunk = @fread($socket, 65_536)) !== false && $chunk !== '') {
            $data .= $chunk;
        }

        return $data;
    }

    /**
     * Whether the server ended the connection.
     *
     * @param  resource  $socket
     */
    private function closed(mixed $socket): bool
    {
        $this->read($socket);

        return feof($socket);
    }

    private function channelAddress(): string
    {
        return "unix://{$this->dataFolder}/n.sock";
    }

    /**
     * A line of the channel as SocketChannel signs it, with the fields given.
     *
     * @param  array<string, mixed>  $message
     */
    private static function sign(array $message): string
    {
        $payload = base64_encode((string) json_encode($message, JSON_UNESCAPED_SLASHES));

        return $payload.'.'.base64_encode(hash_hmac('sha256', $payload, self::KEY, true))."\n";
    }

    private static function frame(string $payload, int $opcode = 0x2, bool $fin = true): string
    {
        $mask = "\x12\x34\x56\x78";
        $length = strlen($payload);

        return pack('C', ($fin ? 0x80 : 0) | $opcode).($length < 126 ? pack('C', 0x80 | $length) : pack('Cn', 0x80 | 126, $length))
            .$mask.($payload ^ substr(str_repeat($mask, intdiv($length, 4) + 1), 0, $length));
    }
}
