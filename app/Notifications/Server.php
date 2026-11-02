<?php

namespace App\Notifications;

use App\Http\Request;
use App\Support\IpNetwork;
use Closure;
use RuntimeException;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

/**
 * The notifications daemon: the WebSocket side of src/api/notifications.rs
 * in one process. Requests to it go through the application like any other
 * (the hubs of NotificationsController accept them); accepted connections
 * then receive what requests hand over through the channel. A ping every 15
 * seconds keeps them open, and they are dropped when nothing came back for
 * 30 seconds.
 */
final class Server
{
    // How often a Ping is sent to the client.
    private const float PING_INTERVAL = 15.0;

    // Close the connection if nothing, not even a Pong, was received from the client for this long,
    // like the default ClientTimeoutInterval of ASP.NET Core SignalR.
    private const float CLIENT_TIMEOUT = 30.0;

    // Vaultwarden gives each connection a task of its own. Here one process holds them all, so these
    // limits keep a few clients from taking all of PHP's memory or every connection.

    // The HTTP request before the upgrade.
    private const float REQUEST_TIMEOUT = 10.0;

    public const int MAX_REQUEST_HEAD = 16_384;

    // The hubs read no body; a small one is let through and ignored.
    public const int MAX_REQUEST_BODY = 8_192;

    // Requests that are neither answered nor upgraded yet. Past this, the oldest makes way for a new
    // connection, so that requests which never finish cannot keep others out.
    public const int MAX_PENDING_REQUESTS = 64;

    // The connections of clients and of requests on the channel. stream_select() fails for all of
    // them once a descriptor reaches FD_SETSIZE, usually 1024, so both together, with room for the
    // daemon's own files, stay below it.
    public const int MAX_CONNECTIONS = 800;

    public const int MAX_CHANNEL_CLIENTS = 128;

    private const int MAX_CHANNEL_LINE = 1 << 20;

    // Requests send a signed line as soon as they connect to the channel. A connection that has not
    // sent one by then is closed, and when the channel is full, the oldest of those makes way.
    private const float CHANNEL_AUTH_TIMEOUT = 5.0;

    // How far the time of a line on the channel may be from the daemon's, in seconds. Within it, the
    // nonce of each line is kept, so that a line sent again is refused.
    private const int REPLAY_WINDOW = 60;

    // The most nonces kept; past it, the oldest go, as only a flood of signed lines gets there.
    private const int MAX_NONCES = 100_000;

    // Vaultwarden queues up to 100 messages per connection, and a request with one more waits until
    // the client read some. Requests do not wait here: a client that leaves this much unread is dropped.
    public const int MAX_OUTPUT = 256 << 10;

    // Unread input and unsent output of all connections together. Past it, those holding the most
    // are dropped.
    private const int MAX_BUFFERED = 32 << 20;

    /**
     * @var resource|null
     */
    private mixed $listener = null;

    /**
     * @var resource|null
     */
    private mixed $channel = null;

    private ?string $channelPath = null;

    /**
     * @var array<int, WebSocketConnection>
     */
    private array $clients = [];

    /**
     * @var array<int, array{resource, string, bool, float}> Of each request on the channel: the socket,
     *                                                       the unread input, whether it sent a valid
     *                                                       line, and when it connected
     */
    private array $channelClients = [];

    /**
     * @var array<string, int> The time of each line within the replay window, by its nonce
     */
    private array $nonces = [];

    /**
     * @var array<string, int> The bytes each client and channel client holds, by its key in runOnce
     */
    private array $buffered = [];

    private int $bufferedTotal = 0;

    /**
     * @var array<string, float> When each warning may be logged again
     */
    private array $warnings = [];

    private int $nextId = 1;

    private bool $stopping = false;

    /**
     * @param  Closure(Request): Response  $dispatch  Handles a request like the web server would
     * @param  int  $maxBuffered  What all connections together may hold
     * @param  float  $channelAuthTimeout  How long a connection to the channel may wait before its first signed line
     */
    public function __construct(
        private readonly Subscriptions $subscriptions,
        private readonly Closure $dispatch,
        private readonly string $channelKey,
        private readonly string $scriptFilename,
        private readonly int $maxBuffered = self::MAX_BUFFERED,
        private readonly float $channelAuthTimeout = self::CHANNEL_AUTH_TIMEOUT,
    ) {}

    /**
     * @param  string  $address  Host and port for the clients, such as 127.0.0.1:3012
     * @param  string  $channelAddress  unix:// or tcp:// address for the requests
     */
    public function listen(string $address, string $channelAddress): void
    {
        if (str_starts_with($channelAddress, 'tcp://')) {
            self::checkChannelHost($channelAddress);
        }

        $listener = @stream_socket_server("tcp://{$address}", $errno, $error);
        if ($listener === false) {
            throw new RuntimeException("Cannot listen on {$address}: {$error}");
        }
        stream_set_blocking($listener, false);
        $this->listener = $listener;

        if (str_starts_with($channelAddress, 'unix://')) {
            $path = substr($channelAddress, strlen('unix://'));
            // sun_path holds 104 bytes on macOS and the BSDs, 108 on Linux.
            if (strlen($path) >= 104) {
                throw new RuntimeException("The socket path {$path} is too long for a Unix socket; set NOTIFICATIONS_SOCKET to a shorter one.");
            }
            if (file_exists($path)) {
                $probe = @stream_socket_client($channelAddress, $errno, $error, 0.5);
                if ($probe !== false) {
                    fclose($probe);

                    throw new RuntimeException("Another notifications daemon listens at {$channelAddress}.");
                }
                @unlink($path);
            }
            $this->channelPath = $path;
        }
        $channel = @stream_socket_server($channelAddress, $errno, $error);
        if ($channel === false) {
            throw new RuntimeException("Cannot listen on {$channelAddress}: {$error}");
        }
        stream_set_blocking($channel, false);
        $this->channel = $channel;
        if ($this->channelPath !== null) {
            // For the daemon's user, which runs PHP for the web server too, and its group.
            @chmod($this->channelPath, 0660);
        }
    }

    /**
     * The channel has no transport security of its own: over TCP it listens on
     * a loopback or another address that is not global, never on all of them.
     *
     * @throws RuntimeException
     */
    public static function checkChannelHost(string $channelAddress): void
    {
        $host = trim((string) parse_url($channelAddress, PHP_URL_HOST), '[]');
        if (strcasecmp($host, 'localhost') === 0) {
            return;
        }
        $ip = filter_var($host, FILTER_VALIDATE_IP) === false ? null : IpNetwork::toCanonical($host);
        if ($ip === null || in_array($ip, ['0.0.0.0', '::'], true) || IpNetwork::isGlobal($ip)) {
            throw new RuntimeException("The notifications channel must not listen on {$channelAddress}: use a Unix socket, "
                .'a loopback address such as tcp://127.0.0.1:3013, or a private address of this host.');
        }
    }

    /**
     * The address the clients connect to, with the port chosen when it was 0.
     */
    public function address(): string
    {
        return $this->listener === null ? '' : (string) stream_socket_get_name($this->listener, false);
    }

    public function run(): void
    {
        while (! $this->stopping) {
            $this->runOnce(1.0);
        }
        $this->shutdown();
    }

    public function stop(): void
    {
        $this->stopping = true;
    }

    /**
     * One round: wait for sockets (at most until the next ping is due), serve them and send pings.
     */
    public function runOnce(float $maxWait): void
    {
        if ($this->listener === null || $this->channel === null) {
            throw new RuntimeException('The server does not listen yet.');
        }

        $read = ['listener' => $this->listener, 'channel' => $this->channel];
        $write = [];
        foreach ($this->clients as $id => $client) {
            // Like Vaultwarden's task, which waits while it sends, a client is not read while output waits for it.
            if ($client->output === '') {
                $read["client {$id}"] = $client->socket;
            } else {
                $write["client {$id}"] = $client->socket;
            }
        }
        foreach ($this->channelClients as $id => [$socket]) {
            $read["channel {$id}"] = $socket;
        }

        $wait = max(0.0, min($maxWait, $this->untilNextTimer()));
        $except = null;
        // False when a signal interrupts the wait.
        if (@stream_select($read, $write, $except, (int) $wait, (int) (fmod($wait, 1.0) * 1_000_000)) !== false) {
            foreach (array_keys($write) as $key) {
                $client = $this->clients[(int) substr((string) $key, strlen('client '))] ?? null;
                if ($client !== null) {
                    $this->flush($client);
                }
            }
            foreach (array_keys($read) as $key) {
                [$kind, $id] = array_pad(explode(' ', (string) $key, 2), 2, '0');
                match ($kind) {
                    'listener' => $this->acceptClient(),
                    'channel' => $key === 'channel' ? $this->acceptChannelClient() : $this->readChannelClient((int) $id),
                    default => $this->readClient((int) $id),
                };
            }
        }

        $this->tick();
    }

    /**
     * Send a message from the channel to the connections it names.
     *
     * @param  array<mixed>  $message
     */
    public function deliver(array $message): void
    {
        $data = base64_decode(is_string($message['message'] ?? null) ? $message['message'] : '', true);
        if ($data === false) {
            return;
        }

        $connections = [];
        if (is_array($message['users'] ?? null)) {
            foreach (array_filter($message['users'], is_string(...)) as $userId) {
                array_push($connections, ...$this->subscriptions->ofUser($userId));
            }
        }
        if (is_string($message['token'] ?? null)) {
            array_push($connections, ...$this->subscriptions->ofToken($message['token']));
        }

        foreach ($connections as $connection) {
            $connection->send(WebSocketConnection::BINARY, $data);
            $this->flush($connection);
        }
    }

    private static function now(): float
    {
        return hrtime(true) / 1e9;
    }

    private function untilNextTimer(): float
    {
        $now = self::now();
        $next = PHP_FLOAT_MAX;
        foreach ($this->clients as $client) {
            $next = min($next, $client->upgraded ? $client->nextPing : $client->openedAt + self::REQUEST_TIMEOUT);
        }
        foreach ($this->channelClients as [, , $trusted, $openedAt]) {
            if (! $trusted) {
                $next = min($next, $openedAt + $this->channelAuthTimeout);
            }
        }

        return $next - $now;
    }

    private function tick(): void
    {
        $now = self::now();
        foreach ($this->channelClients as $id => [, , $trusted, $openedAt]) {
            if (! $trusted && $now - $openedAt > $this->channelAuthTimeout) {
                $this->closeChannelClient($id);
            }
        }
        // Lines older than the window are refused by their time, so their nonces are of no more use.
        $oldest = time() - self::REPLAY_WINDOW;
        foreach ($this->nonces as $nonce => $time) {
            if ($time >= $oldest) {
                break;
            }
            unset($this->nonces[$nonce]);
        }

        foreach ($this->clients as $client) {
            if (! $client->upgraded) {
                if ($now - $client->openedAt > self::REQUEST_TIMEOUT) {
                    $this->close($client);
                }

                continue;
            }
            if ($now < $client->nextPing) {
                continue;
            }
            // The client stopped responding without closing the connection, drop it.
            if ($now - $client->lastReceived > self::CLIENT_TIMEOUT) {
                $this->close($client);

                continue;
            }
            $client->nextPing = max($client->nextPing + self::PING_INTERVAL, $now);
            $client->send(WebSocketConnection::PING, SignalR::PING);
            $this->flush($client);
        }
    }

    private function acceptClient(): void
    {
        if ($this->listener === null) {
            return;
        }
        $socket = @stream_socket_accept($this->listener, 0, $peer);
        if ($socket === false) {
            return;
        }

        // The oldest request makes way when there are too many of them, or of all connections;
        // without one to drop, the new connection is refused.
        $pending = array_filter($this->clients, static fn (WebSocketConnection $client): bool => ! $client->upgraded);
        if (count($pending) >= self::MAX_PENDING_REQUESTS || count($this->clients) >= self::MAX_CONNECTIONS) {
            $oldest = reset($pending);
            if ($oldest === false) {
                fclose($socket);
                $this->warning('The notifications daemon refuses connections: it holds as many as it can.');

                return;
            }
            $this->warning('The notifications daemon drops requests that take too long: too many are open.');
            $this->close($oldest);
        }
        stream_set_blocking($socket, false);

        [$address, $port] = self::splitAddress(is_string($peer) ? $peer : '');
        $id = $this->nextId++;
        $this->clients[$id] = new WebSocketConnection($id, $socket, $address, $port, self::now());
    }

    private function readClient(int $id): void
    {
        $client = $this->clients[$id] ?? null;
        if ($client === null) {
            return;
        }
        $data = @fread($client->socket, 65_536);
        if ($data === false || ($data === '' && feof($client->socket))) {
            $this->close($client);

            return;
        }
        // Nothing after an answered request is read.
        if ($client->closeAfterOutput) {
            return;
        }
        $client->input .= $data;

        if ($client->upgraded) {
            $this->readMessages($client);
        } else {
            $this->readRequest($client);
        }
        if (isset($this->clients[$id])) {
            $this->track("client {$id}", $client->buffered());
        }
    }

    /**
     * The HTTP request, once complete: dispatched like any other, then
     * answered and closed, or upgraded when a hub accepted it.
     */
    private function readRequest(WebSocketConnection $client): void
    {
        $end = strpos($client->input, "\r\n\r\n");
        if (($end === false ? strlen($client->input) : $end) > self::MAX_REQUEST_HEAD) {
            $this->plainResponse($client, 431, 'Request Header Fields Too Large');

            return;
        }
        if ($end === false) {
            return;
        }

        $lines = explode("\r\n", substr($client->input, 0, $end));
        $parts = explode(' ', (string) array_shift($lines));
        if (count($parts) !== 3 || ! preg_match('#^HTTP/1\.[01]$#', $parts[2]) || ! str_starts_with($parts[1], '/')) {
            $this->plainResponse($client, 400, 'Bad Request');

            return;
        }
        [$method, $target, $protocol] = $parts;

        $headers = [];
        foreach ($lines as $line) {
            $colon = strpos($line, ':');
            if ($colon === false || $colon === 0 || $line[0] === ' ' || $line[0] === "\t") {
                $this->plainResponse($client, 400, 'Bad Request');

                return;
            }
            $headers[] = [substr($line, 0, $colon), trim(substr($line, $colon + 1), " \t")];
        }

        $length = 0;
        foreach ($headers as [$name, $value]) {
            if (strcasecmp($name, 'Content-Length') === 0) {
                $length = ctype_digit($value) ? (int) $value : -1;
            }
        }
        if ($length < 0 || $length > self::MAX_REQUEST_BODY) {
            $this->plainResponse($client, $length < 0 ? 400 : 413, $length < 0 ? 'Bad Request' : 'Payload Too Large');

            return;
        }
        if (strlen($client->input) < $end + 4 + $length) {
            return;
        }
        $body = substr($client->input, $end + 4, $length);
        $client->input = substr($client->input, $end + 4 + $length);

        // Only what lies below the hubs' mount point goes through the application.
        if (preg_match('#^[^?]*/notifications/#', $target) !== 1) {
            $this->plainResponse($client, 404, 'Not Found');

            return;
        }

        try {
            $request = $this->request($client, $method, $target, $protocol, $headers, $body);
            $response = ($this->dispatch)($request);
        } catch (Throwable $exception) {
            report($exception);
            $this->plainResponse($client, 500, 'Internal Server Error');

            return;
        }

        if ($response instanceof WebSocketAccept && $response->getStatusCode() === 101) {
            $this->upgrade($client, $response);

            return;
        }
        if ($response instanceof WebSocketAccept && $response->anonymousToken !== null) {
            $this->subscriptions->release($response->ip);
        }

        ob_start();
        try {
            $response->sendContent();
        } finally {
            $content = (string) ob_get_clean();
        }
        $client->output .= self::responseHead($response, strlen($content)).($method === 'HEAD' ? '' : $content);
        $client->closeAfterOutput = true;
        $this->flush($client);
    }

    private function upgrade(WebSocketConnection $client, WebSocketAccept $response): void
    {
        $client->output .= self::responseHead($response, null);
        $client->upgraded = true;
        $client->ip = $response->ip;
        $client->userId = $response->userId;
        $client->anonymousToken = $response->anonymousToken;
        $this->subscriptions->subscribe($client);

        // Like tokio's interval, the first ping goes out at once.
        $now = self::now();
        $client->lastReceived = $now;
        $client->nextPing = $now + self::PING_INTERVAL;
        $client->send(WebSocketConnection::PING, SignalR::PING);
        $this->flush($client);

        if ($client->input !== '') {
            $this->readMessages($client);
        }
    }

    private function readMessages(WebSocketConnection $client): void
    {
        try {
            $messages = $client->readMessages();
        } catch (RuntimeException $exception) {
            logger()->debug("WebSocket error from {$client->ip}: {$exception->getMessage()}");
            $this->close($client);

            return;
        }

        foreach ($messages as [$opcode, $payload]) {
            // Any message, including a Pong, means the client is still there.
            $client->lastReceived = self::now();

            switch ($opcode) {
                case WebSocketConnection::PING:
                    $client->send(WebSocketConnection::PONG, $payload);
                    break;
                case WebSocketConnection::PONG:
                    break;
                case WebSocketConnection::TEXT:
                    // The initial message with the protocol and version is answered.
                    if (SignalR::isInitialMessage($payload)) {
                        $client->send(WebSocketConnection::BINARY, SignalR::INITIAL_RESPONSE);
                    }
                    break;
                case WebSocketConnection::CLOSE:
                    // Nothing is sent back, the connection just ends.
                    $this->close($client);

                    return;
                default:
                    // Anything else is echoed.
                    $client->send($opcode, $payload);
            }
        }
        $this->flush($client);
    }

    private function flush(WebSocketConnection $client): void
    {
        if (! isset($this->clients[$client->id])) {
            return;
        }
        if ($client->output !== '') {
            $written = @fwrite($client->socket, $client->output);
            if ($written === false) {
                $this->close($client);

                return;
            }
            $client->output = (string) substr($client->output, $written);
        }

        if ($client->output === '' && $client->closeAfterOutput) {
            $this->close($client);
        } elseif (strlen($client->output) > self::MAX_OUTPUT) {
            logger()->error("Error sending WS update to {$client->ip}: the client does not read");
            $this->close($client);
        } else {
            $this->track("client {$client->id}", $client->buffered());
        }
    }

    /**
     * Note what a client or channel client holds now. When all of them
     * together hold more than the budget, those holding the most are dropped.
     */
    private function track(string $key, int $bytes): void
    {
        $this->bufferedTotal += $bytes - ($this->buffered[$key] ?? 0);
        if ($bytes > 0) {
            $this->buffered[$key] = $bytes;
        } else {
            unset($this->buffered[$key]);
        }
        if ($this->bufferedTotal <= $this->maxBuffered) {
            return;
        }

        $largest = $this->buffered;
        arsort($largest);
        foreach (array_keys($largest) as $other) {
            if ($this->bufferedTotal <= $this->maxBuffered) {
                break;
            }
            [$kind, $id] = explode(' ', $other, 2);
            if ($kind === 'channel') {
                logger()->warning('The notifications daemon dropped a request on its channel: it is out of buffer space');
                $this->closeChannelClient((int) $id);
            } elseif (($client = $this->clients[(int) $id] ?? null) !== null) {
                logger()->warning('Closing WS connection from '.($client->ip !== '' ? $client->ip : $client->peerAddress)
                    .': the notifications daemon is out of buffer space');
                $this->close($client);
            }
        }
    }

    /**
     * Log a warning that clients can cause, at most once a minute.
     */
    private function warning(string $message): void
    {
        $now = self::now();
        if ($now >= ($this->warnings[$message] ?? 0.0)) {
            $this->warnings[$message] = $now + 60.0;
            logger()->warning($message);
        }
    }

    private function close(WebSocketConnection $client): void
    {
        if (! isset($this->clients[$client->id])) {
            return;
        }
        unset($this->clients[$client->id]);
        $this->track("client {$client->id}", 0);
        if ($client->upgraded) {
            logger()->info("Closing WS connection from {$client->ip}");
            $this->subscriptions->unsubscribe($client);
        }
        @fclose($client->socket);
    }

    private function plainResponse(WebSocketConnection $client, int $status, string $reason): void
    {
        $client->output .= "HTTP/1.1 {$status} {$reason}\r\nContent-Type: text/plain; charset=utf-8\r\n"
            .'Content-Length: '.strlen($reason)."\r\nConnection: close\r\n\r\n{$reason}";
        $client->closeAfterOutput = true;
        $this->flush($client);
    }

    /**
     * @param  list<array{string, string}>  $headers
     */
    private function request(WebSocketConnection $client, string $method, string $target, string $protocol, array $headers, string $body): Request
    {
        [$localAddress, $localPort] = self::splitAddress($this->address());
        $question = strpos($target, '?');
        $queryString = $question === false ? '' : substr($target, $question + 1);
        $server = [
            'REQUEST_METHOD' => $method,
            'REQUEST_URI' => $target,
            'QUERY_STRING' => $queryString,
            'SERVER_PROTOCOL' => $protocol,
            'REMOTE_ADDR' => $client->peerAddress,
            'REMOTE_PORT' => $client->peerPort,
            'SERVER_ADDR' => $localAddress,
            'SERVER_NAME' => $localAddress,
            'SERVER_PORT' => $localPort,
            // Where the web server would run the application.
            'SCRIPT_FILENAME' => $this->scriptFilename,
            'SCRIPT_NAME' => '/index.php',
            'PHP_SELF' => '/index.php',
            'DOCUMENT_ROOT' => dirname($this->scriptFilename),
            'REQUEST_TIME' => time(),
            'REQUEST_TIME_FLOAT' => microtime(true),
        ];
        $cookies = [];
        foreach ($headers as [$name, $value]) {
            // Like nginx and Apache in front of PHP: X_Real_IP would read as X-Real-IP.
            if (str_contains($name, '_')) {
                continue;
            }
            $key = strtoupper(str_replace('-', '_', $name));
            $key = in_array($key, ['CONTENT_TYPE', 'CONTENT_LENGTH'], true) ? $key : "HTTP_{$key}";
            $server[$key] = isset($server[$key]) ? "{$server[$key]}, {$value}" : $value;
            if (strcasecmp($name, 'Cookie') === 0) {
                foreach (explode(';', $value) as $cookie) {
                    [$cookieName, $cookieValue] = array_pad(explode('=', $cookie, 2), 2, '');
                    $cookies[trim($cookieName)] = urldecode(trim($cookieValue));
                }
            }
        }

        return new Request(self::queryFields($queryString), [], [], $cookies, [], $server, $body);
    }

    /**
     * The query's fields, the last of a name winning as with parse_str(), but without its cut-off at
     * max_input_vars: Rocket takes any number of fields.
     *
     * @return array<array-key, string>
     */
    private static function queryFields(string $queryString): array
    {
        $fields = [];
        foreach (explode('&', $queryString) as $pair) {
            if ($pair === '') {
                continue;
            }
            [$name, $value] = array_pad(explode('=', $pair, 2), 2, '');
            $fields[urldecode($name)] = urldecode($value);
        }

        return $fields;
    }

    /**
     * @param  int|null  $length  The length of the body, null for an upgrade
     */
    private static function responseHead(Response $response, ?int $length): string
    {
        $status = $response->getStatusCode();
        $head = sprintf('HTTP/1.1 %d %s', $status, Response::$statusTexts[$status] ?? '')."\r\n";
        // Names in lower case, as hyper writes them.
        foreach ($response->headers->all() as $name => $values) {
            if ($name === 'set-cookie' || ($length !== null && in_array($name, ['connection', 'content-length', 'transfer-encoding'], true))) {
                continue;
            }
            foreach ($values as $value) {
                $head .= "{$name}: {$value}\r\n";
            }
        }
        foreach ($response->headers->getCookies() as $cookie) {
            $head .= "set-cookie: {$cookie}\r\n";
        }
        if ($length !== null) {
            $head .= "content-length: {$length}\r\nconnection: close\r\n";
        }

        return "{$head}\r\n";
    }

    /**
     * @return array{string, int}
     */
    private static function splitAddress(string $address): array
    {
        $colon = strrpos($address, ':');
        if ($colon === false) {
            return [$address, 0];
        }

        return [trim(substr($address, 0, $colon), '[]'), (int) substr($address, $colon + 1)];
    }

    private function shutdown(): void
    {
        foreach ($this->clients as $client) {
            $this->close($client);
        }
        foreach ($this->channelClients as [$socket]) {
            @fclose($socket);
        }
        $this->channelClients = [];
        foreach ([$this->listener, $this->channel] as $socket) {
            if (is_resource($socket)) {
                fclose($socket);
            }
        }
        $this->listener = $this->channel = null;
        if ($this->channelPath !== null) {
            @unlink($this->channelPath);
        }
    }

    private function acceptChannelClient(): void
    {
        if ($this->channel === null) {
            return;
        }
        $socket = @stream_socket_accept($this->channel, 0);
        if ($socket === false) {
            return;
        }
        if (count($this->channelClients) >= self::MAX_CHANNEL_CLIENTS) {
            // The oldest connection that has not sent a valid line yet makes way: requests send one at once.
            $silent = array_key_first(array_filter($this->channelClients, static fn (array $client): bool => ! $client[2]));
            if ($silent === null) {
                fclose($socket);
                $this->warning('The notifications daemon refuses requests on its channel: too many are connected.');

                return;
            }
            $this->closeChannelClient($silent);
        }
        stream_set_blocking($socket, false);
        $this->channelClients[$this->nextId++] = [$socket, '', false, self::now()];
    }

    private function closeChannelClient(int $id): void
    {
        if (isset($this->channelClients[$id])) {
            @fclose($this->channelClients[$id][0]);
            unset($this->channelClients[$id]);
            $this->track("channel {$id}", 0);
        }
    }

    private function readChannelClient(int $id): void
    {
        if (! isset($this->channelClients[$id])) {
            return;
        }
        [$socket, $buffer, $trusted, $openedAt] = $this->channelClients[$id];
        $data = @fread($socket, 65_536);
        $closed = $data === false || ($data === '' && feof($socket));
        $buffer .= (string) $data;

        while (($newline = strpos($buffer, "\n")) !== false) {
            $message = SocketChannel::decode(substr($buffer, 0, $newline), $this->channelKey);
            $buffer = substr($buffer, $newline + 1);
            if ($message === null || ! $this->isNew($message)) {
                // Requests sign every line once, so nothing more is read from whoever sent this one.
                $this->warning($message === null
                    ? 'The notifications daemon received a message that is not signed with its key.'
                    : 'The notifications daemon received a message that is out of date or was sent before.');
                $closed = true;

                break;
            }
            $trusted = true;
            $this->deliver($message);
        }

        if ($closed || strlen($buffer) > self::MAX_CHANNEL_LINE) {
            $this->closeChannelClient($id);
        } elseif (isset($this->channelClients[$id])) {
            $this->channelClients[$id] = [$socket, $buffer, $trusted, $openedAt];
            $this->track("channel {$id}", strlen($buffer));
        }
    }

    /**
     * Whether a signed line is sent for the first time: its time within the
     * replay window and its nonce not seen in it.
     *
     * @param  array<mixed>  $message
     */
    private function isNew(array $message): bool
    {
        $time = $message['time'] ?? null;
        $nonce = $message['nonce'] ?? null;
        if (! is_int($time) || abs(time() - $time) > self::REPLAY_WINDOW
            || ! is_string($nonce) || preg_match('/^[0-9a-f]{32}$/D', $nonce) !== 1 || isset($this->nonces[$nonce])) {
            return false;
        }

        $this->nonces[$nonce] = $time;
        if (count($this->nonces) > self::MAX_NONCES) {
            unset($this->nonces[array_key_first($this->nonces)]);
        }

        return true;
    }
}
