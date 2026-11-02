<?php

namespace App\Notifications;

use App\Auth\RsaKeys;
use App\Config\Config;

/**
 * The channel to the notifications daemon: a Unix socket in the data folder
 * by default, or the address in NOTIFICATIONS_SOCKET (such as
 * tcp://127.0.0.1:3013). One line per message, signed with a key derived
 * from the RSA key both sides read. Without a daemon listening, the
 * messages are dropped, like Vaultwarden's when nobody is connected.
 */
final class SocketChannel implements Channel
{
    /**
     * @var resource|false|null False once connecting failed in this request
     */
    private mixed $socket = null;

    public function __construct(
        private readonly string $address,
        private readonly string $key,
    ) {}

    public static function fromConfig(Config $config, RsaKeys $keys): self
    {
        return new self(self::address($config), $keys->notificationsKey());
    }

    public static function address(Config $config): string
    {
        $address = config('vaultwarden.notifications_socket');

        return is_string($address) && $address !== '' ? $address : 'unix://'.$config->path('data_folder').'/notifications.sock';
    }

    public function toUsers(array $userIds, string $message): void
    {
        $this->send(['users' => $userIds, 'message' => base64_encode($message)]);
    }

    public function toAnonymous(string $token, string $message): void
    {
        $this->send(['token' => $token, 'message' => base64_encode($message)]);
    }

    /**
     * A line of the channel: the message as base64-encoded JSON, a dot and
     * its HMAC-SHA256 in base64. The message carries the time and a nonce,
     * so that the daemon can refuse a line that is sent again.
     *
     * @param  array<string, mixed>  $message
     */
    public static function encode(array $message, string $key): string
    {
        $message = [...$message, 'time' => time(), 'nonce' => bin2hex(random_bytes(16))];
        $payload = base64_encode((string) json_encode($message, JSON_UNESCAPED_SLASHES));

        return $payload.'.'.base64_encode(hash_hmac('sha256', $payload, $key, true))."\n";
    }

    /**
     * The message of a line, null when it is malformed or not signed with the key.
     *
     * @return array<mixed>|null
     */
    public static function decode(string $line, string $key): ?array
    {
        [$payload, $signature] = array_pad(explode('.', trim($line), 2), 2, '');
        if (! hash_equals(base64_encode(hash_hmac('sha256', $payload, $key, true)), $signature)) {
            return null;
        }
        $message = json_decode((string) base64_decode($payload, true), true);

        return is_array($message) && ! array_is_list($message) ? $message : null;
    }

    public function __destruct()
    {
        if (is_resource($this->socket)) {
            fclose($this->socket);
        }
    }

    /**
     * @param  array<string, mixed>  $message
     */
    private function send(array $message): void
    {
        if ($this->socket === null) {
            $socket = @stream_socket_client($this->address, $errno, $error, 1.0);
            if ($socket === false) {
                logger()->debug("The notifications daemon is not listening at {$this->address}: {$error}");
            } else {
                stream_set_timeout($socket, 1);
            }
            $this->socket = $socket;
        }
        if ($this->socket === false) {
            return;
        }

        $line = self::encode($message, $this->key);
        if (@fwrite($this->socket, $line) !== strlen($line)) {
            logger()->error("Error sending WS update to the notifications daemon at {$this->address}");
            fclose($this->socket);
            $this->socket = false;
        }
    }
}
