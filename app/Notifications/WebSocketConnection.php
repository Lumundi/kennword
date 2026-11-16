<?php

namespace App\Notifications;

use RuntimeException;

/**
 * A client of the notifications daemon: an HTTP request until a hub accepts
 * it, then a WebSocket in the server role, framed like tungstenite.
 */
final class WebSocketConnection
{
    public const int TEXT = 0x1;

    public const int BINARY = 0x2;

    public const int CLOSE = 0x8;

    public const int PING = 0x9;

    public const int PONG = 0xA;

    // tungstenite allows frames of 16 MiB and messages of 64 MiB, in a task per connection. One PHP
    // process holds every connection, so incoming messages are limited like the default
    // MaximumReceiveMessageSize of ASP.NET Core SignalR, which the official server uses. The clients
    // only send the handshake, pings and pongs of a few bytes.
    public const int MAX_FRAME_SIZE = 32 << 10;

    public const int MAX_MESSAGE_SIZE = 32 << 10;

    public string $input = '';

    public string $output = '';

    public bool $upgraded = false;

    // Close as soon as the output is written, after a plain HTTP response.
    public bool $closeAfterOutput = false;

    public ?string $userId = null;

    public ?string $anonymousToken = null;

    // The last second (UNIX time) in which the access token of the connection is valid.
    public ?int $validUntil = null;

    // The client's address as the hub saw it (ClientIp).
    public string $ip = '';

    public float $lastReceived;

    public float $nextPing;

    // The opcode and data of a fragmented message being received.
    private ?int $fragmentedType = null;

    private string $fragments = '';

    /**
     * @param  resource  $socket
     */
    public function __construct(
        public readonly int $id,
        public readonly mixed $socket,
        public readonly string $peerAddress,
        public readonly int $peerPort,
        public readonly float $openedAt,
    ) {
        $this->lastReceived = $openedAt;
        $this->nextPing = $openedAt;
    }

    /**
     * The complete messages in the input, as opcode and payload; control
     * frames are messages of their own. Fragments are kept until the last
     * one arrives.
     *
     * @return list<array{int, string}>
     *
     * @throws RuntimeException On a protocol error, which ends the connection
     */
    public function readMessages(): array
    {
        $messages = [];
        while (($frame = $this->nextFrame()) !== null) {
            [$fin, $opcode, $payload] = $frame;

            if ($opcode >= 0x8) {
                if (! $fin) {
                    throw new RuntimeException('Fragmented control frame');
                }
                if (strlen($payload) > 125) {
                    throw new RuntimeException('Control frame too big');
                }
                if (! in_array($opcode, [self::CLOSE, self::PING, self::PONG], true)) {
                    throw new RuntimeException("Unknown control frame type {$opcode}");
                }
                if ($opcode === self::CLOSE && (strlen($payload) === 1 || ! mb_check_encoding(substr($payload, 2), 'UTF-8'))) {
                    throw new RuntimeException('Invalid close sequence');
                }
                $messages[] = [$opcode, $payload];

                continue;
            }

            if ($opcode === 0x0) {
                if ($this->fragmentedType === null) {
                    throw new RuntimeException('Continue frame but nothing to continue');
                }
                $this->fragments .= $payload;
            } elseif ($this->fragmentedType !== null) {
                throw new RuntimeException('While waiting for more fragments received another data frame');
            } elseif ($opcode === self::TEXT || $opcode === self::BINARY) {
                $this->fragmentedType = $opcode;
                $this->fragments = $payload;
            } else {
                throw new RuntimeException("Unknown data frame type {$opcode}");
            }
            if (strlen($this->fragments) > self::MAX_MESSAGE_SIZE) {
                throw new RuntimeException('Message too long');
            }

            if ($fin) {
                if ($this->fragmentedType === self::TEXT && ! mb_check_encoding($this->fragments, 'UTF-8')) {
                    throw new RuntimeException('UTF-8 encoding error');
                }
                $messages[] = [$this->fragmentedType, $this->fragments];
                $this->fragmentedType = null;
                $this->fragments = '';
            }
        }

        return $messages;
    }

    /**
     * The bytes the connection holds: unread input, the fragments of a message and unsent output.
     */
    public function buffered(): int
    {
        return strlen($this->input) + strlen($this->fragments) + strlen($this->output);
    }

    /**
     * Queue a frame of one piece, unmasked as the server sends them.
     */
    public function send(int $opcode, string $payload): void
    {
        $length = strlen($payload);
        $header = pack('C', 0x80 | $opcode).match (true) {
            $length < 126 => pack('C', $length),
            $length < 65536 => "\x7e".pack('n', $length),
            default => "\x7f".pack('J', $length),
        };
        $this->output .= $header.$payload;
    }

    /**
     * @return array{bool, int, string}|null Whether it is the final frame, its opcode and unmasked payload
     */
    private function nextFrame(): ?array
    {
        $available = strlen($this->input);
        if ($available < 2) {
            return null;
        }
        $first = ord($this->input[0]);
        $second = ord($this->input[1]);

        $offset = 2;
        $length = $second & 0x7F;
        if ($length === 126) {
            if ($available < 4) {
                return null;
            }
            $length = unpack('n', $this->input, 2)[1] ?? 0;
            $offset = 4;
        } elseif ($length === 127) {
            if ($available < 10) {
                return null;
            }
            $length = unpack('J', $this->input, 2)[1] ?? 0;
            $offset = 10;
        }
        if (! is_int($length) || $length < 0 || $length > self::MAX_FRAME_SIZE) {
            throw new RuntimeException('Frame too long');
        }

        $masked = ($second & 0x80) !== 0;
        $mask = '';
        if ($masked) {
            if ($available < $offset + 4) {
                return null;
            }
            $mask = substr($this->input, $offset, 4);
            $offset += 4;
        }
        if ($available < $offset + $length) {
            return null;
        }
        $payload = substr($this->input, $offset, $length);
        $this->input = substr($this->input, $offset + $length);

        if (($first & 0x70) !== 0) {
            throw new RuntimeException('Reserved bits are non-zero');
        }
        if (! $masked) {
            throw new RuntimeException('Received an unmasked frame from client');
        }
        if ($length > 0) {
            $payload ^= substr(str_repeat($mask, intdiv($length, 4) + 1), 0, $length);
        }

        return [($first & 0x80) !== 0, $first & 0x0F, $payload];
    }
}
